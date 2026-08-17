"""Cisco Duo Auth API client — the ACTIVE recovery MFA provider.

Only the Auth API is used. The Admin API is deliberately absent: it is not
available on Duo Free, and it carries directory-wide write authority that this
flow has no business holding.

Why the signing is implemented here rather than via `duo_client`
----------------------------------------------------------------
`duo_client` is not installed, and the only Python environment available to the
gateway is `venvs/debalekha`, which is shared with the RUNNING ServiceDesk
process. Installing into it to satisfy this module would put a live production
agent at risk of a transitive dependency change, and creating a second
interpreter for the gateway is a larger change than the ~40 lines of signing
below. The protocol is small, fully specified, and exercised by tests against
Duo's published example vectors.

Everything that touches the secret key is confined to `_signature`. The key is
never logged, never rendered, never placed in argv, and `__repr__` is
overridden so an accidental f-string cannot leak it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from email.utils import formatdate
from pathlib import Path
from typing import Any, Mapping, Optional
from urllib.parse import quote

import requests

from .mfa_provider import (
    AuthResult,
    Device,
    EnrollmentStatus,
    EnrollmentTicket,
    MfaProviderError,
    PreauthResult,
    ProviderCheck,
    PushHandle,
    RecoveryMfaProvider,
)

logger = logging.getLogger("voice_gateway")

RUNTIME = Path(__file__).resolve().parents[1] / "runtime"

# Duo API hostnames only. A hostname supplied by a caller or chosen by a model
# would turn this client into an arbitrary-HTTP primitive that signs requests
# with our integration key, so the shape is pinned here.
DUO_HOST_RE = re.compile(r"^api-[a-z0-9]{6,16}\.duo(security|federal)\.com$")

# HMAC-SHA512 is Duo's current signing default; the server distinguishes the
# algorithm by signature length. SHA1 remains selectable for an older
# integration, but never silently.
_DIGESTS = {"sha512": hashlib.sha512, "sha1": hashlib.sha1}

DEFAULT_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class DuoConfig:
    ikey: str
    skey: str
    host: str
    digest: str = "sha512"
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if not self.ikey or not self.skey:
            raise MfaProviderError("DUO_CONFIG_INCOMPLETE", "ikey/skey missing")
        if not DUO_HOST_RE.fullmatch(self.host or ""):
            raise MfaProviderError(
                "DUO_HOST_REJECTED",
                "DUO_HOST must be an api-XXXXXXXX.duosecurity.com hostname",
            )
        if self.digest not in _DIGESTS:
            raise MfaProviderError("DUO_DIGEST_UNSUPPORTED", self.digest)

    def redacted(self) -> dict[str, str]:
        """Safe for a configuration dump. The secret key never appears."""
        return {
            "duo_host": self.host,
            "duo_ikey": f"{self.ikey[:4]}…{self.ikey[-2:]}" if len(self.ikey) > 8 else "set",
            "duo_skey": "<redacted>",
            "duo_signature": self.digest,
        }

    # Belt and braces: neither repr nor str can ever render the secret.
    def __repr__(self) -> str:
        return f"DuoConfig({self.redacted()})"

    __str__ = __repr__


def _read_runtime_secret(env_name: str, file_name: str) -> str:
    """Environment first, then a 0600 runtime file. Never argv."""
    value = os.getenv(env_name, "").strip()
    if value:
        return value
    path = RUNTIME / file_name
    if path.exists():
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise MfaProviderError(
                "DUO_SECRET_PERMISSIONS",
                f"{path} is mode {mode:o}; it must be 0600",
            )
        return path.read_text().strip()
    return ""


def load_duo_config() -> Optional[DuoConfig]:
    """Assemble Duo configuration, or None when Duo is not configured at all."""
    ikey = _read_runtime_secret("DUO_IKEY", ".duo_ikey")
    skey = _read_runtime_secret("DUO_SKEY", ".duo_skey")
    host = _read_runtime_secret("DUO_HOST", ".duo_host").lower()
    if not (ikey or skey or host):
        return None
    return DuoConfig(
        ikey=ikey,
        skey=skey,
        host=host,
        digest=os.getenv("DUO_SIGNATURE_ALGORITHM", "sha512").strip().lower(),
        timeout_seconds=float(os.getenv("DUO_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)),
    )


def _encode(value: str) -> str:
    """Duo's parameter encoding: RFC 3986 with "~" left unreserved."""
    return quote(str(value), safe="~")


def canonicalize(method: str, host: str, path: str,
                 params: Mapping[str, str], date: str) -> str:
    """The exact string Duo signs.

        date \n METHOD \n host \n path \n sorted&encoded=params

    Sorting is on the encoded key so both ends agree byte-for-byte regardless
    of insertion order.
    """
    pairs = "&".join(
        f"{_encode(key)}={_encode(params[key])}" for key in sorted(params)
    )
    return "\n".join([date, method.upper(), host.lower(), path, pairs])


class DuoRecoveryProvider(RecoveryMfaProvider):
    """Auth API operations, and nothing else.

    There is intentionally no generic `request()` here. Each method below maps
    to one documented endpoint with a fixed parameter set, so neither Dograh nor
    a model can reach an endpoint this flow was not designed around.
    """

    name = "duo"

    def __init__(self, config: DuoConfig, session: Optional[Any] = None) -> None:
        self._config = config
        self._session = session or requests.Session()

    @property
    def host(self) -> str:
        return self._config.host

    def redacted_config(self) -> dict[str, str]:
        return self._config.redacted()

    def __repr__(self) -> str:
        return f"DuoRecoveryProvider(host={self._config.host!r})"

    __str__ = __repr__

    # -- signing -----------------------------------------------------------
    def _signature(self, canonical: str) -> str:
        digest = _DIGESTS[self._config.digest]
        return hmac.new(
            self._config.skey.encode("utf-8"), canonical.encode("utf-8"), digest
        ).hexdigest()

    def _authorization(self, canonical: str) -> str:
        token = f"{self._config.ikey}:{self._signature(canonical)}".encode("utf-8")
        return "Basic " + base64.b64encode(token).decode("ascii")

    # -- transport ---------------------------------------------------------
    def _request(self, method: str, path: str,
                 params: Optional[Mapping[str, str]] = None) -> dict[str, Any]:
        """One signed Auth API call. HTTPS only, to the configured host only."""
        params = {k: str(v) for k, v in (params or {}).items() if v is not None}
        date = formatdate(timeval=time.time(), localtime=False, usegmt=False)
        canonical = canonicalize(method, self._config.host, path, params, date)

        headers = {
            "Date": date,
            "Authorization": self._authorization(canonical),
            "User-Agent": "servicedesk-voice-recovery/1.0",
        }
        url = f"https://{self._config.host}{path}"

        try:
            if method.upper() == "GET":
                response = self._session.get(
                    url, params=params, headers=headers,
                    timeout=self._config.timeout_seconds,
                )
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                response = self._session.post(
                    url, data=params, headers=headers,
                    timeout=self._config.timeout_seconds,
                )
        except requests.RequestException as exc:
            raise MfaProviderError("DUO_UNREACHABLE", type(exc).__name__) from exc

        try:
            payload = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise MfaProviderError("DUO_BAD_RESPONSE", f"HTTP {response.status_code}") from exc

        if payload.get("stat") != "OK":
            # message_detail can echo the submitted parameters, which for a
            # passcode call would be the passcode itself. Only the numeric code
            # is carried forward.
            raise MfaProviderError("DUO_API_ERROR", str(payload.get("code", "")))
        result = payload.get("response")
        return result if isinstance(result, dict) else {"value": result}

    # -- operations --------------------------------------------------------
    def check(self) -> ProviderCheck:
        """GET /auth/v2/check. Recovery stays disabled unless this succeeds."""
        try:
            self._request("GET", "/auth/v2/check")
            return ProviderCheck(ok=True)
        except MfaProviderError as exc:
            logger.warning("duo check failed code=%s", exc.code)
            return ProviderCheck(ok=False, reason=exc.code)

    def enroll(self, valid_secs: int = 3600,
               username: Optional[str] = None) -> EnrollmentTicket:
        """POST /auth/v2/enroll.

        `username` is left unset by default. Duo generates an anonymous user
        and returns its `user_id`, which is the stable binding we actually
        want; supplying a UPN as the Duo username would recreate exactly the
        rename fragility the identity map exists to avoid.
        """
        params: dict[str, str] = {"valid_secs": str(int(valid_secs))}
        if username:
            params["username"] = username
        data = self._request("POST", "/auth/v2/enroll", params)
        return EnrollmentTicket(
            user_id=str(data.get("user_id", "")),
            activation_code=str(data.get("activation_code", "")),
            activation_barcode_url=data.get("activation_barcode"),
            expires_at=data.get("expiration"),
            username=data.get("username"),
        )

    def enroll_status(self, user_id: str, activation_code: str) -> EnrollmentStatus:
        """POST /auth/v2/enroll_status -> "success" | "waiting" | "invalid"."""
        data = self._request(
            "POST", "/auth/v2/enroll_status",
            {"user_id": user_id, "activation_code": activation_code},
        )
        return EnrollmentStatus(state=str(data.get("value", data)).strip().lower())

    def preauth(self, user_id: str) -> PreauthResult:
        """POST /auth/v2/preauth — the authoritative device inventory."""
        data = self._request("POST", "/auth/v2/preauth", {"user_id": user_id})
        devices = tuple(
            Device(
                device_id=str(d.get("device", "")),
                display_name=str(d.get("display_name", "")),
                device_type=str(d.get("type", "")),
                capabilities=frozenset(d.get("capabilities") or ()),
            )
            for d in (data.get("devices") or [])
            if isinstance(d, dict)
        )
        return PreauthResult(result=str(data.get("result", "")).lower(), devices=devices)

    def start_push(self, user_id: str, device_id: str) -> PushHandle:
        """POST /auth/v2/auth with factor=push, async=1."""
        data = self._request(
            "POST", "/auth/v2/auth",
            {"user_id": user_id, "factor": "push", "device": device_id, "async": "1"},
        )
        txid = str(data.get("txid", ""))
        if not txid:
            raise MfaProviderError("DUO_NO_TXID")
        return PushHandle(txid=txid)

    def poll_push(self, txid: str) -> AuthResult:
        """GET /auth/v2/auth_status. One poll; the caller bounds the loop."""
        data = self._request("GET", "/auth/v2/auth_status", {"txid": txid})
        return AuthResult(
            result=str(data.get("result", "")).lower(),
            status=str(data.get("status", "")).lower(),
        )

    def verify_passcode(self, user_id: str, passcode: str) -> AuthResult:
        """POST /auth/v2/auth with factor=passcode.

        The passcode reaches exactly two places: this parameter dict and the
        signed request body. It is never logged, and DUO_API_ERROR deliberately
        drops `message_detail`, which would otherwise echo it back.
        """
        data = self._request(
            "POST", "/auth/v2/auth",
            {"user_id": user_id, "factor": "passcode", "passcode": passcode},
        )
        return AuthResult(
            result=str(data.get("result", "")).lower(),
            status=str(data.get("status", "")).lower(),
        )

    # -- enrollment QR -----------------------------------------------------
    def fetch_activation_qr(self, barcode_url: str) -> tuple[str, bytes]:
        """Fetch Duo's activation QR so the portal can inline it.

        Fetched server-side and returned as bytes rather than linked from the
        page: the browser then never contacts Duo directly, the portal's
        `img-src 'self' data:` policy is untouched, and no third-party host is
        added to the CSP.

        The URL is checked against the CONFIGURED Duo host before any request,
        so a substituted `activation_barcode` cannot turn this into an SSRF
        primitive.
        """
        from urllib.parse import urlparse

        parsed = urlparse(barcode_url or "")
        if parsed.scheme != "https" or parsed.hostname != self._config.host:
            raise MfaProviderError("DUO_BARCODE_HOST_REJECTED")
        try:
            response = self._session.get(barcode_url, timeout=self._config.timeout_seconds)
        except requests.RequestException as exc:
            raise MfaProviderError("DUO_UNREACHABLE", type(exc).__name__) from exc
        if response.status_code != 200:
            raise MfaProviderError("DUO_BARCODE_UNAVAILABLE", str(response.status_code))
        content_type = response.headers.get("Content-Type", "image/png").split(";")[0].strip()
        if not content_type.startswith("image/"):
            raise MfaProviderError("DUO_BARCODE_NOT_IMAGE")
        return content_type, response.content
