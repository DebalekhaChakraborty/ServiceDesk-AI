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

Availability and contradiction are treated very differently:

    contradiction (object missing / wrong tenant)  -> fail closed
    unavailable   (no credentials / Graph down)    -> proceed, marked explicitly

Failing closed on unavailability would make an unrelated outage indistinguishable
from an attack while adding nothing: this phase is read-only self-diagnosis, and
sd_chat performs its own live Graph read immediately afterwards.
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
    available: bool                 # was a live check possible at all?
    ok: bool                        # no contradiction found
    reason: str = ""                # coarse, log-safe
    object_exists: Optional[bool] = None
    tenant_ok: Optional[bool] = None
    directory_upn: Optional[str] = None
    account_enabled: Optional[bool] = None
    upn_drift: bool = False

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
    """Used when no read credentials are configured."""

    def corroborate(self, tenant_id: str, object_id: str,
                    expected_upn: str) -> CorroborationResult:
        return CorroborationResult(available=False, ok=True, reason="not_configured")


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
            logger.warning("graph corroboration unavailable reason=%s", type(exc).__name__)
            return CorroborationResult(available=False, ok=True, reason="graph_unavailable")

        if response.status_code == 404:
            # A contradiction, not an outage: the map points at an object the
            # directory does not have.
            return CorroborationResult(
                available=True, ok=False, reason="object_not_found",
                object_exists=False, tenant_ok=True,
            )
        if response.status_code != 200:
            logger.warning("graph corroboration http=%s", response.status_code)
            return CorroborationResult(available=False, ok=True, reason="graph_error")

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


def _read_secret(env_name: str, file_name: str) -> str:
    value = os.getenv(env_name, "").strip()
    if value:
        return value
    path = RUNTIME / file_name
    if path.exists() and not (path.stat().st_mode & 0o077):
        return path.read_text().strip()
    return ""


def load_corroborator() -> GraphCorroborator:
    """Build a live corroborator when configured; otherwise the null one."""
    tenant = os.getenv("RECOVERY_GRAPH_TENANT_ID", "").strip()
    client = os.getenv("RECOVERY_GRAPH_CLIENT_ID", "").strip()
    secret = _read_secret("RECOVERY_GRAPH_CLIENT_SECRET", ".recovery_graph_client_secret")
    if not (tenant and client and secret):
        return NullGraphCorroborator()
    return LiveGraphCorroborator(tenant, client, secret)
