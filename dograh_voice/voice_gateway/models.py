"""Wire contract for the voice gateway."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class VoiceTurnRequest(BaseModel):
    """One caller utterance from Dograh.

    `voice_session_id` is optional at the schema level ONLY so that PoC single
    session mode can accept a body of `{"text": ...}`. Outside that mode the
    endpoint rejects a request without it — the id is never defaulted silently.
    """

    voice_session_id: Optional[str] = Field(default=None, min_length=1, max_length=200)
    text: str = Field(min_length=1)

    # Authenticated mode. Both arrive as Dograh PRESET parameters rendered from
    # initial_context, never as LLM-filled parameters, so the model cannot
    # choose or alter either value.
    call_id: Optional[str] = Field(default=None, min_length=1, max_length=200)
    voice_identity_token: Optional[str] = Field(default=None, max_length=4096)

    # NEVER TRUSTED. Accepted so the schema stays stable and so a browser
    # attempting to assert an identity gets a normal 200 with the assertion
    # discarded, rather than an error that reveals the field is inspected.
    # The real UPN is recovered only by verifying voice_identity_token.
    verified_upn: Optional[str] = None
    channel: Optional[str] = "voice"


class RecoveryEnrollBeginRequest(BaseModel):
    """Called by the PORTAL only, from a freshly authenticated Entra session."""
    upn: str = Field(min_length=3, max_length=320)
    display_name: str = Field(default="", max_length=200)
    object_id: Optional[str] = Field(default=None, max_length=100)


class RecoveryEnrollBeginResponse(BaseModel):
    # The seed appears here ONCE, at enrollment, and never again.
    secret: str
    otpauth_uri: str
    digits: int
    period_seconds: int


class RecoveryEnrollConfirmRequest(BaseModel):
    upn: str = Field(min_length=3, max_length=320)
    code: str = Field(min_length=1, max_length=64)


class RecoveryStartRequest(BaseModel):
    """Public recovery bootstrap.

    `claimed_upn` is retained ONLY for the retired TOTP provider, where the
    address was typed on the page. Under Duo the caller identifies themselves by
    voice instead, so the field is optional and the public page sends nothing at
    all — which removes the last place this endpoint could have leaked whether
    an account exists.
    """
    call_id: str = Field(min_length=1, max_length=200)
    claimed_upn: Optional[str] = Field(default=None, max_length=320)
    recovery_token: str = Field(max_length=4096)


class DuoEnrollBeginRequest(BaseModel):
    """Called by the PORTAL only, from a freshly authenticated Entra session.

    All three identity fields come from the sealed session and are matched
    against the existing map row. A form-supplied identity is never trusted, so
    nobody can enroll a Duo credential against a colleague's record.
    """
    tenant_id: str = Field(min_length=1, max_length=100)
    object_id: str = Field(min_length=1, max_length=100)
    upn: str = Field(min_length=3, max_length=320)


class DuoEnrollBeginResponse(BaseModel):
    status: Literal["pending"] = "pending"
    # Duo's activation code, plus its QR fetched server-side and inlined so the
    # browser never contacts Duo and the portal CSP is untouched.
    activation_code: str
    qr_data_uri: Optional[str] = None
    expires_at: Optional[int] = None


class DuoEnrollStatusResponse(BaseModel):
    # "success" is the ONLY state that activates recovery for this employee.
    status: Literal["active", "waiting", "invalid"]


class VoiceTurnResponse(BaseModel):
    voice_session_id: str
    text: str
    status: Literal["ok"] = "ok"


class VoiceTurnError(BaseModel):
    status: Literal["error"] = "error"
    code: str
    text: str


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    # Downstream reachability, without leaking any detail about why.
    servicedesk: Optional[Literal["reachable", "unreachable"]] = None
    # Surfaced so the unsafe-for-multi-caller PoC mode is never silently active.
    poc_single_session: bool = False
