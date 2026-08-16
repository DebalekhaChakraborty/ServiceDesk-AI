"""Self-hosted TOTP recovery — RETAINED AS REFERENCE, NOT THE ACTIVE PROVIDER.

Superseded by duo_recovery.DuoRecoveryManager. Cisco Duo now performs recovery
authentication, so this module is reachable only when RECOVERY_PROVIDER is set
explicitly to "totp"; nothing constructs it by default. It is kept rather than
deleted until Duo end-to-end acceptance is signed off, so there is a known-good
path to fall back to.

`TurnOutcome` below is still live: the Duo state machine reuses it so the
gateway has exactly one shape of recovery turn result to handle.

Deterministic pre-ServiceDesk recovery state machine, keyed by call_id.

Owned by Python. The LLM transcribes speech and speaks replies; it never
decides whether a code was valid, never sees the seed, and never sees the
utterance that carried the code — while the machine is WAITING_FOR_OTP the
caller's words are consumed here and are NOT forwarded to sd_chat.

    RECOVERY_STARTED -> WAITING_FOR_OTP -> OTP_VERIFIED -> SERVICEDESK_ACTIVE
                                    \\-> FAILED_LOCKED

Only SERVICEDESK_ACTIVE forwards utterances onward, and it is reachable only
through a verified TOTP.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .recovery_store import RecoveryStore, redact_account
from .totp import SpokenCodeError, parse_spoken_code

logger = logging.getLogger("voice_gateway")

# A recovery call that stalls should not stay open indefinitely.
SESSION_TTL_SECONDS = 900


class RecoveryState(str, Enum):
    RECOVERY_STARTED = "RECOVERY_STARTED"
    WAITING_FOR_OTP = "WAITING_FOR_OTP"
    OTP_VERIFIED = "OTP_VERIFIED"
    SERVICEDESK_ACTIVE = "SERVICEDESK_ACTIVE"
    FAILED_LOCKED = "FAILED_LOCKED"


PROMPT_FOR_OTP = (
    "Please open your authenticator app and speak the six-digit code."
)
RETRY_PROMPT = (
    "I did not catch six digits. Please say the six-digit code again, "
    "one digit at a time."
)
# One message for every failure cause: wrong code, replayed code, and an
# account that was never enrolled must be indistinguishable to the caller.
GENERIC_FAILURE = (
    "That code could not be verified. Please open your authenticator app and "
    "speak the current six-digit code."
)
LOCKED_MESSAGE = (
    "Too many attempts. For your security this recovery session is closed. "
    "Please contact the Service Desk by another channel."
)
VERIFIED_MESSAGE = (
    "Thank you. Your identity has been verified for account recovery. "
    "How can I help?"
)


@dataclass
class RecoverySession:
    call_id: str
    claimed_upn: str                    # UNTRUSTED until OTP verification
    state: RecoveryState = RecoveryState.RECOVERY_STARTED
    created_at: float = field(default_factory=time.time)
    attempts: int = 0
    verified_identity: Optional[dict] = None   # from the enrollment record only

    def expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) - self.created_at > SESSION_TTL_SECONDS


@dataclass
class TurnOutcome:
    """What the gateway should do with this utterance."""
    speak: Optional[str] = None      # reply to speak; consumed here
    forward: bool = False            # send the utterance to sd_chat instead
    state: Optional[RecoveryState] = None
    identity: Optional[dict] = None
    # Text to send to sd_chat INSTEAD of the caller's current utterance. Set
    # only when a request captured before authentication is being released, so
    # the caller is not asked to repeat the problem they already described.
    # None means "forward what they just said", which is the normal case.
    forward_text: Optional[str] = None

    def outbound_text(self, spoken: str) -> str:
        """The text that actually goes to sd_chat for this turn."""
        return self.forward_text if self.forward_text is not None else spoken


class RecoveryManager:
    """All recovery sessions for this process, keyed by call_id."""

    def __init__(self, store: Optional[RecoveryStore] = None) -> None:
        self._store = store or RecoveryStore()
        self._sessions: dict[str, RecoverySession] = {}
        self._lock = threading.Lock()

    @property
    def store(self) -> RecoveryStore:
        return self._store

    @staticmethod
    def persona_for(identity: dict) -> dict:
        """Uniform with DuoRecoveryManager, so the gateway needs no branching."""
        return recovery_persona(identity)

    def start(self, call_id: str, claimed_upn: str) -> RecoverySession:
        """Begin a recovery call. The claimed UPN is only a lookup hint.

        Note what does NOT happen here: no check of whether the account is
        enrolled, and no different behaviour if it is not. Probing this
        endpoint must not reveal who has a recovery credential.
        """
        with self._lock:
            session = RecoverySession(
                call_id=call_id,
                claimed_upn=claimed_upn,
                state=RecoveryState.WAITING_FOR_OTP,
            )
            self._sessions[call_id] = session
            logger.info(
                "recovery start call=%s account=%s state=%s",
                call_id[:8], redact_account(claimed_upn), session.state.value,
            )
            return session

    def get(self, call_id: str) -> Optional[RecoverySession]:
        return self._sessions.get(call_id)

    def handle_turn(self, call_id: str, utterance: str,
                    now: Optional[float] = None) -> TurnOutcome:
        """Advance the machine for one utterance.

        Returns forward=True only in SERVICEDESK_ACTIVE. Every other state
        consumes the utterance here, which is what keeps a spoken OTP out of
        sd_chat entirely.
        """
        with self._lock:
            session = self._sessions.get(call_id)
            if session is None:
                return TurnOutcome(speak=GENERIC_FAILURE)

            moment = now if now is not None else time.time()

            if session.expired(moment) and session.state is not RecoveryState.SERVICEDESK_ACTIVE:
                session.state = RecoveryState.FAILED_LOCKED
                return TurnOutcome(speak=LOCKED_MESSAGE, state=session.state)

            if session.state is RecoveryState.FAILED_LOCKED:
                return TurnOutcome(speak=LOCKED_MESSAGE, state=session.state)

            if session.state is RecoveryState.SERVICEDESK_ACTIVE:
                return TurnOutcome(forward=True, state=session.state,
                                   identity=session.verified_identity)

            if session.state is RecoveryState.OTP_VERIFIED:
                # The turn AFTER verification is the first real ServiceDesk one.
                session.state = RecoveryState.SERVICEDESK_ACTIVE
                return TurnOutcome(forward=True, state=session.state,
                                   identity=session.verified_identity)

            # --- WAITING_FOR_OTP: the utterance is a code, not a question ---
            try:
                code = parse_spoken_code(utterance)
            except SpokenCodeError as exc:
                # Parsing never counts as an authentication failure: a
                # transcription miss is not an attack, and counting it would
                # let noise lock a legitimate caller out.
                logger.info(
                    "recovery parse call=%s account=%s category=%s",
                    call_id[:8], redact_account(session.claimed_upn), exc.category,
                )
                return TurnOutcome(speak=RETRY_PROMPT, state=session.state)

            session.attempts += 1
            started = time.monotonic()
            ok, category = self._store.verify(session.claimed_upn, code, moment)
            duration_ms = int((time.monotonic() - started) * 1000)

            # The code itself - raw or normalised - is never in this record.
            logger.info(
                "recovery verify call=%s account=%s attempt=%d result=%s "
                "category=%s duration_ms=%d",
                call_id[:8], redact_account(session.claimed_upn),
                session.attempts, "ok" if ok else "fail", category, duration_ms,
            )

            if ok:
                identity = self._store.identity_for(session.claimed_upn)
                if identity is None:            # cannot happen; fail closed
                    session.state = RecoveryState.FAILED_LOCKED
                    return TurnOutcome(speak=LOCKED_MESSAGE, state=session.state)
                session.verified_identity = {
                    **identity,
                    "auth_method": "recovery_totp",
                    "identity_source": "recovery_totp",
                    "recovery_scope": "self_account_recovery",
                    "purpose": "account_recovery",
                }
                session.state = RecoveryState.OTP_VERIFIED
                return TurnOutcome(speak=VERIFIED_MESSAGE, state=session.state,
                                   identity=session.verified_identity)

            if category == "locked":
                session.state = RecoveryState.FAILED_LOCKED
                return TurnOutcome(speak=LOCKED_MESSAGE, state=session.state)

            # Escalating delay so repeated guessing gets progressively slower.
            delay = self._store.backoff_seconds(session.claimed_upn)
            if delay:
                time.sleep(delay)

            if self._store.status_for(session.claimed_upn) and \
                    self._is_locked_now(session.claimed_upn, moment):
                session.state = RecoveryState.FAILED_LOCKED
                return TurnOutcome(speak=LOCKED_MESSAGE, state=session.state)

            return TurnOutcome(speak=GENERIC_FAILURE, state=session.state)

    def _is_locked_now(self, upn: str, moment: float) -> bool:
        record = self._store._get(upn)            # noqa: SLF001 - same package
        return bool(record and record.locked_until and moment < record.locked_until)


def recovery_persona(identity: dict) -> dict:
    """Persona for a TOTP-recovered caller, in the existing sd_chat contract.

    Same field names identity_context_tool already reads, plus provenance
    markers so downstream policy can see this identity came from a recovery
    factor rather than a full Entra sign-in.
    """
    persona = {
        "userPrincipalName": identity["upn"],
        "mail": identity["upn"],
        "displayName": identity.get("display_name") or identity["upn"],
        "identity_source": "recovery_totp",
        "recovery_scope": "self_account_recovery",
        "auth_method": "recovery_totp",
    }
    if identity.get("object_id"):
        persona["id"] = identity["object_id"]
    return persona
