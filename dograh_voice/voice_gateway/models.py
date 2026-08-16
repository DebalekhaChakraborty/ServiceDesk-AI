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

    # Reserved for a later phase. Accepted so the schema is stable, but the
    # gateway MUST NOT act on them: Phase 3 performs no caller verification, so
    # a value here is an unverified assertion from the voice channel and is
    # deliberately ignored rather than forwarded to ServiceDesk.
    verified_upn: Optional[str] = None
    channel: Optional[str] = "voice"


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
