"""Deterministic voice_session_id -> ServiceDesk (ADK) session id mapping.

There is deliberately no conversation state here. ServiceDesk's ADK session
service remains the single source of truth for the conversation; this module
only computes a stable id and remembers which ids have already been created so
we can skip a redundant existence check.
"""

from __future__ import annotations

import hashlib
import re

_SAFE = re.compile(r"[^A-Za-z0-9._-]")
_PREFIX = "voice-"
_READABLE_MAX = 48


def adk_session_id(voice_session_id: str) -> str:
    """Map a Dograh call id to a ServiceDesk session id, deterministically.

    Same voice_session_id always yields the same ServiceDesk session, which is
    what keeps a multi-turn call on one conversation. A short digest of the
    *original* value is appended so two different call ids can never collide
    after unsafe characters are normalised away.
    """
    if not voice_session_id or not voice_session_id.strip():
        raise ValueError("voice_session_id must be non-empty")

    digest = hashlib.sha256(voice_session_id.encode("utf-8")).hexdigest()[:8]
    readable = _SAFE.sub("-", voice_session_id.strip())[:_READABLE_MAX].strip("-")
    return f"{_PREFIX}{readable}-{digest}" if readable else f"{_PREFIX}{digest}"


def redact_session_id(voice_session_id: str) -> str:
    """Log-safe handle: a short digest, never the raw call id."""
    return hashlib.sha256(voice_session_id.encode("utf-8")).hexdigest()[:12]


class SessionRegistry:
    """Remembers which ServiceDesk sessions this process has already created.

    Purely an optimisation. A miss costs one extra existence check; it is never
    treated as authoritative, so a ServiceDesk restart cannot desynchronise it
    into a wrong answer.
    """

    def __init__(self) -> None:
        self._known: set[str] = set()

    def is_known(self, adk_id: str) -> bool:
        return adk_id in self._known

    def mark_known(self, adk_id: str) -> None:
        self._known.add(adk_id)

    def forget(self, adk_id: str) -> None:
        self._known.discard(adk_id)

    def __len__(self) -> int:
        return len(self._known)
