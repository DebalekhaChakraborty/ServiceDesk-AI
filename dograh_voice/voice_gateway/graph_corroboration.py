"""Read-only Microsoft Graph corroboration of a Duo-verified identity.

After Duo allows, the trusted identity comes from the local map row bound to
`duo_user_id`. That row could be stale — an employee may have left, been moved
to another tenant, or been renamed since it was written. This module asks the
directory one question before the identity is used:

    does object <oid> still exist, in the expected tenant?

Strictly a READ. There is no write path in this file and no Graph write scope
is requested. A UPN reported by Graph that differs from the local row is
recorded as *drift* and surfaced; it never silently retargets the active call,
because "the directory says this oid is now bob@" must not turn a recovery call
for one person into a recovery call for another. Reconciling the alias is an
administrative action, taken between calls.

EVERY outcome other than a live, uncontradicted read fails closed:

    contradiction (object missing / wrong tenant)  -> fail closed, terminal
    unavailable   (no credentials / Graph down)    -> fail closed, retry later

Corroboration is a REQUIRED second opinion, not a diagnostic. A Duo `allow`
proves only that somebody holds the enrolled phone; it says nothing about
whether the local row still describes a real, current employee in the expected
tenant. Treating an outage as a pass would mean an attacker who can make Graph
unreachable — or who simply calls during an incident — gets a recovery persona
on Duo alone, from a map row nobody re-checked. So availability and correctness
are BOTH required, and the two are still distinguished, but only to choose
between "this is over" and "try again later".

`available` therefore records whether a live answer was obtained, and `ok`
records whether identity may be established from it. Nothing sets `ok` true
without a live, affirmative directory read.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import requests

logger = logging.getLogger("voice_gateway")

RUNTIME = Path(__file__).resolve().parents[1] / "runtime"
GRAPH_BASE_URL = os.getenv("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0")
TIMEOUT_SECONDS = 20.0


@dataclass(frozen=True)
class CorroborationResult:
    available: bool                 # was a live answer obtained at all?
    ok: bool                        # may identity be established from it?
    reason: str = ""                # coarse, log-safe
    object_exists: Optional[bool] = None
    tenant_ok: Optional[bool] = None
    directory_upn: Optional[str] = None
    account_enabled: Optional[bool] = None
    upn_drift: bool = False

    def establishes_identity(self) -> bool:
        """The single gate a recovery persona must pass.

        Both halves are required and neither is redundant: `ok` alone would be
        fail-open if some future code path forgot to set it on an outage, and
        `available` alone says nothing about what the directory answered. A
        caller that asks this question cannot accidentally proceed on an
        unavailable result.
        """
        return self.available and self.ok

    def summary(self) -> dict[str, Any]:
        """Compact record for the session and for logs. No token, no secret."""
        return {
            "available": self.available,
            "ok": self.ok,
            "reason": self.reason,
            "object_exists": self.object_exists,
            "tenant_ok": self.tenant_ok,
            "account_enabled": self.account_enabled,
            "upn_drift": self.upn_drift,
        }


class GraphCorroborator:
    """Interface. Implementations must never mutate anything."""

    def corroborate(self, tenant_id: str, object_id: str,
                    expected_upn: str) -> CorroborationResult:
        raise NotImplementedError


class NullGraphCorroborator(GraphCorroborator):
    """Used when no read credentials are configured.

    It cannot corroborate anything, so it never permits an identity. Recovery
    is refused at startup when this is the configured corroborator, rather than
    left to fail one caller at a time.
    """

    def corroborate(self, tenant_id: str, object_id: str,
                    expected_upn: str) -> CorroborationResult:
        return CorroborationResult(available=False, ok=False, reason="not_configured")


class LiveGraphCorroborator(GraphCorroborator):
    """Client-credentials Graph reader.

    Uses its OWN application registration by default rather than borrowing
    sd_chat's: that app holds directory write permissions this check does not
    need, and a dedicated read-only app keeps the gateway's blast radius equal
    to what it actually does. Pointing it at an existing app is an explicit
    operator decision, not a default.
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 session: Optional[Any] = None) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._session = session or requests.Session()

    def __repr__(self) -> str:  # never render the secret
        return f"LiveGraphCorroborator(tenant={self._tenant_id!r})"

    __str__ = __repr__

    def _token(self) -> str:
        response = self._session.post(
            f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=TIMEOUT_SECONDS,
        )
        if response.status_code != 200:
            raise RuntimeError(f"token_http_{response.status_code}")
        token = response.json().get("access_token")
        if not token:
            raise RuntimeError("token_missing")
        return str(token)

    def corroborate(self, tenant_id: str, object_id: str,
                    expected_upn: str) -> CorroborationResult:
        # A tenant mismatch is settled locally; there is no reason to ask a
        # directory about an object that belongs to a different one.
        if tenant_id and self._tenant_id and tenant_id.lower() != self._tenant_id.lower():
            return CorroborationResult(
                available=True, ok=False, reason="tenant_mismatch",
                tenant_ok=False, object_exists=None,
            )
        try:
            token = self._token()
            response = self._session.get(
                f"{GRAPH_BASE_URL}/users/{object_id}",
                params={"$select": "id,userPrincipalName,accountEnabled,displayName"},
                headers={"Authorization": f"Bearer {token}"},
                timeout=TIMEOUT_SECONDS,
            )
        except Exception as exc:
            # Network error, DNS failure, timeout, or a token endpoint that did
            # not answer. No opinion was obtained, so no identity may be built.
            logger.warning("graph corroboration unavailable reason=%s", type(exc).__name__)
            return CorroborationResult(available=False, ok=False, reason="graph_unavailable")

        if response.status_code == 404:
            # A contradiction, not an outage: the map points at an object the
            # directory does not have.
            return CorroborationResult(
                available=True, ok=False, reason="object_not_found",
                object_exists=False, tenant_ok=True,
            )
        if response.status_code != 200:
            # 401/403/429/5xx: the directory did not answer the question. Not a
            # contradiction, but not corroboration either.
            logger.warning("graph corroboration http=%s", response.status_code)
            return CorroborationResult(available=False, ok=False, reason="graph_error")

        body = response.json()
        directory_upn = str(body.get("userPrincipalName") or "").lower()
        drift = bool(directory_upn and directory_upn != (expected_upn or "").lower())
        if drift:
            # Recorded, surfaced, and NOT acted on. Correcting the alias is an
            # administrative step between calls.
            logger.warning("graph corroboration upn_drift oid=%s", object_id[:8])
        return CorroborationResult(
            available=True, ok=True, reason="ok",
            object_exists=True, tenant_ok=True,
            directory_upn=directory_upn or None,
            account_enabled=body.get("accountEnabled"),
            upn_drift=drift,
        )


def _read_runtime_value(env_name: str, file_name: str) -> str:
    """Environment first, then an owner-only runtime file. Never argv.

    The same order the Duo loader uses. Every value the corroborator needs is
    resolvable this way, so starting the gateway requires no exported
    environment and no wrapper script: a launch that depends on a shell's
    variables silently degrades to no corroboration, which - now that
    corroboration is mandatory - silently disables recovery.
    """
    value = os.getenv(env_name, "").strip()
    if value:
        return value
    path = RUNTIME / file_name
    if not path.exists():
        return ""
    if path.stat().st_mode & 0o077:
        # Refusing is right, but doing it silently turns a chmod slip into an
        # unexplained "recovery DISABLED" at startup.
        logger.warning("ignoring %s: mode %o is not owner-only (must be 0600)",
                       path.name, path.stat().st_mode & 0o777)
        return ""
    return path.read_text().strip()


def load_corroborator() -> GraphCorroborator:
    """Build a live corroborator when configured; otherwise the null one."""
    tenant = _read_runtime_value("RECOVERY_GRAPH_TENANT_ID", ".recovery_graph_tenant_id")
    client = _read_runtime_value("RECOVERY_GRAPH_CLIENT_ID", ".recovery_graph_client_id")
    secret = _read_runtime_value("RECOVERY_GRAPH_CLIENT_SECRET",
                                 ".recovery_graph_client_secret")
    if not (tenant and client and secret):
        missing = [n for n, v in (("tenant_id", tenant), ("client_id", client),
                                  ("client_secret", secret)) if not v]
        logger.warning("graph corroboration unconfigured: missing %s",
                       ", ".join(missing))
        return NullGraphCorroborator()
    return LiveGraphCorroborator(tenant, client, secret)
