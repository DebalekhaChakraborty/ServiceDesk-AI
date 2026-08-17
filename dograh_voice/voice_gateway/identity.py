"""Short-lived signed identity assertions for authenticated voice calls.

The browser is never trusted. A UPN reaches ServiceDesk only if it arrives
inside a token that was signed server-side by the Entra-authenticated portal,
using a secret that exists on the portal and the gateway and nowhere else.

Format is a compact JWS (JWT-shaped) so it stays inspectable and portable:

    base64url(header) "." base64url(payload) "." base64url(HMAC-SHA256)

HMAC-SHA256 is used rather than an asymmetric scheme because both ends run
under the same operator for this PoC. The trade-off is explicit: the verifier
can also mint. If the gateway is ever exposed more widely than the portal,
move to RS256/EdDSA so the gateway holds only a public key.

Deliberately implemented with hmac/hashlib rather than a JWT library: it adds
no dependency, and every check below is one this design actually needs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

AUDIENCE = "servicedesk-voice-gateway"
TOKEN_VERSION = 1
ALGORITHM = "HS256"

# Clock skew tolerated between the portal and the gateway. Small on purpose:
# both run on the same host today, and a wide window only helps replay.
CLOCK_SKEW_SECONDS = 30

# Upper bound on a token's own lifetime. A token that claims a longer life than
# this is rejected outright, so a portal bug cannot mint a long-lived bearer
# credential.
MAX_TTL_SECONDS = 15 * 60

SECRET_ENV = "VOICE_IDENTITY_SIGNING_SECRET"
SECRET_FILE = Path(__file__).resolve().parents[1] / "runtime" / ".voice_identity_secret"


class IdentityTokenError(Exception):
    """Verification failed.

    `reason` is for local logs only. Callers must return a generic message to
    the client: telling an attacker which check failed is free help.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def load_signing_secret() -> str:
    """Resolve the dedicated voice signing secret. Never logged, never returned."""
    secret = os.getenv(SECRET_ENV, "").strip()
    if not secret and SECRET_FILE.exists():
        secret = SECRET_FILE.read_text().strip()
    if not secret:
        raise IdentityTokenError(
            f"no voice identity signing secret: set {SECRET_ENV} or create {SECRET_FILE}"
        )
    if len(secret) < 32:
        raise IdentityTokenError("voice identity signing secret is too short (<32 chars)")
    return secret


def new_call_id() -> str:
    """A fresh, unguessable call id. One per voice call, never reused."""
    return f"voice_{secrets.token_urlsafe(24)}"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _canonical(obj: dict[str, Any]) -> bytes:
    """Deterministic JSON matching the portal's sorted JSON.stringify output."""
    return json.dumps(
        obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")


def _sign(signing_input: bytes, secret: str) -> str:
    return _b64e(hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest())


def mint(
    upn: str,
    call_id: str,
    secret: str,
    ttl_seconds: int = 300,
    display_name: str | None = None,
    object_id: str | None = None,
    now: float | None = None,
) -> str:
    """Create a signed assertion. SERVER-SIDE ONLY — never runs in a browser."""
    if not upn or not upn.strip():
        raise IdentityTokenError("upn is required")
    if not call_id or not call_id.strip():
        raise IdentityTokenError("call_id is required")
    if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
        raise IdentityTokenError(f"ttl must be 1..{MAX_TTL_SECONDS} seconds")

    issued = int(now if now is not None else time.time())
    payload: dict[str, Any] = {
        "ver": TOKEN_VERSION,
        "call_id": call_id,
        "upn": upn,
        "iat": issued,
        "exp": issued + ttl_seconds,
        "aud": AUDIENCE,
    }
    # Optional claims. identity_context_tool maps these to display_name and
    # aad_object_id; both are signed, so neither is browser-assertable.
    if display_name:
        payload["name"] = display_name
    if object_id:
        payload["oid"] = object_id

    header = {"alg": ALGORITHM, "typ": "JWT"}
    # ensure_ascii=False is REQUIRED for cross-language parity: the portal signs
    # with JSON.stringify, which emits raw UTF-8, while Python would otherwise
    # emit \uXXXX escapes. A display name containing any non-ASCII character
    # would then produce different signing input on each side and every token
    # would fail verification.
    signing_input = (
        _b64e(_canonical(header)) + "." + _b64e(_canonical(payload))
    ).encode("ascii")
    return signing_input.decode("ascii") + "." + _sign(signing_input, secret)


PURPOSE_RECOVERY = "account_recovery"


def mint_recovery_bootstrap(
    call_id: str, secret: str, claimed_upn: str | None = None,
    ttl_seconds: int = 300, now: float | None = None,
) -> str:
    """Bootstrap for an UNAUTHENTICATED recovery call.

    Critically this carries NO verified identity. `claimed_upn` is a lookup
    hint the caller typed; it is signed only so it cannot be swapped mid-call,
    never so it can be believed. Trust is established later, by TOTP, from the
    enrollment record.
    """
    if not call_id or not call_id.strip():
        raise IdentityTokenError("call_id is required")
    if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
        raise IdentityTokenError(f"ttl must be 1..{MAX_TTL_SECONDS} seconds")

    issued = int(now if now is not None else time.time())
    payload: dict[str, Any] = {
        "ver": TOKEN_VERSION,
        "call_id": call_id,
        "purpose": PURPOSE_RECOVERY,
        "iat": issued,
        "exp": issued + ttl_seconds,
        "aud": AUDIENCE,
    }
    if claimed_upn:
        # Named to be unmistakable at every use site.
        payload["claimed_upn_hint"] = claimed_upn

    header = {"alg": ALGORITHM, "typ": "JWT"}
    signing_input = (
        _b64e(_canonical(header)) + "." + _b64e(_canonical(payload))
    ).encode("ascii")
    return signing_input.decode("ascii") + "." + _sign(signing_input, secret)


def verify_recovery_bootstrap(
    token: str, secret: str, expected_call_id: str, now: float | None = None
) -> dict[str, Any]:
    """Verify a recovery bootstrap. Never returns a trusted UPN."""
    payload = _verify_common(token, secret, expected_call_id, now)
    if payload.get("purpose") != PURPOSE_RECOVERY:
        raise IdentityTokenError("not a recovery token")
    if "upn" in payload:
        # A recovery bootstrap must never carry a verified identity claim.
        raise IdentityTokenError("recovery token must not assert an identity")
    return payload


def verify(token: str, secret: str, expected_call_id: str, now: float | None = None) -> dict[str, Any]:
    """Verify signature, expiry, audience and call binding. Returns the payload.

    Raises IdentityTokenError for every failure. The order matters: the
    signature is checked BEFORE any claim is read, so no untrusted field is
    acted on until the token is proven authentic.
    """
    return _finish_identity_verification(
        _verify_common(token, secret, expected_call_id, now)
    )


def _verify_common(token: str, secret: str, expected_call_id: str,
                   now: float | None = None) -> dict[str, Any]:
    """Signature, algorithm, audience, lifetime and call binding.

    Shared by both token kinds so neither can drift into weaker checking.
    """
    if not isinstance(token, str) or not token:
        raise IdentityTokenError("token missing")
    if len(token) > 4096:
        raise IdentityTokenError("token too large")

    parts = token.split(".")
    if len(parts) != 3:
        raise IdentityTokenError("malformed token")
    header_b64, payload_b64, signature = parts

    expected_sig = _sign(f"{header_b64}.{payload_b64}".encode("ascii"), secret)
    if not hmac.compare_digest(signature, expected_sig):
        raise IdentityTokenError("bad signature")

    try:
        header = json.loads(_b64d(header_b64))
        payload = json.loads(_b64d(payload_b64))
    except Exception as exc:
        raise IdentityTokenError("undecodable token") from exc
    if not isinstance(payload, dict) or not isinstance(header, dict):
        raise IdentityTokenError("malformed payload")

    # Pin the algorithm so a forged header cannot select "none" or downgrade.
    if header.get("alg") != ALGORITHM:
        raise IdentityTokenError("unexpected algorithm")
    if payload.get("ver") != TOKEN_VERSION:
        raise IdentityTokenError("unsupported token version")
    if payload.get("aud") != AUDIENCE:
        raise IdentityTokenError("wrong audience")

    current = now if now is not None else time.time()
    iat, exp = payload.get("iat"), payload.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int):
        raise IdentityTokenError("missing iat/exp")
    if exp <= iat or (exp - iat) > MAX_TTL_SECONDS:
        raise IdentityTokenError("implausible lifetime")
    if current > exp + CLOCK_SKEW_SECONDS:
        raise IdentityTokenError("expired")
    if current + CLOCK_SKEW_SECONDS < iat:
        raise IdentityTokenError("issued in the future")

    # Binding the token to one call is what stops a token captured from call A
    # being replayed to join call B inside its lifetime.
    if not expected_call_id or payload.get("call_id") != expected_call_id:
        raise IdentityTokenError("call_id mismatch")

    return payload


def _finish_identity_verification(payload: dict[str, Any]) -> dict[str, Any]:
    upn = payload.get("upn")
    if not isinstance(upn, str) or not upn.strip():
        raise IdentityTokenError("missing upn")
    if payload.get("purpose") == PURPOSE_RECOVERY:
        # A recovery bootstrap can never be used as a full identity assertion.
        raise IdentityTokenError("recovery token cannot assert identity")
    return payload


def persona_from_claims(payload: dict[str, Any]) -> dict[str, Any]:
    """Build the persona that sd_chat's identity_context_tool already consumes.

    Field names are chosen to match _extract_persona_from_state /
    ensure_identity_context_in_state exactly — this reuses the existing trusted
    identity contract rather than inventing a second one.
    """
    persona: dict[str, Any] = {
        "userPrincipalName": payload["upn"],
        "mail": payload["upn"],
        "displayName": payload.get("name") or payload["upn"],
        "identity_source": "entra_portal_voice",
    }
    if payload.get("oid"):
        persona["id"] = payload["oid"]
    return persona


def redact_token(token: str) -> str:
    """Log-safe handle for a token. The token itself is never logged."""
    if not isinstance(token, str) or not token:
        return "<none>"
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
