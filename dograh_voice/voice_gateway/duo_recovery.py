"""Duo-backed voice recovery: the deterministic pre-ServiceDesk state machine.

Owned entirely by Python. Dograh transcribes speech and speaks replies; it never
decides who the caller is, never sees a Duo transaction id, never sees a
passcode, and never chooses a factor. Until the machine reaches
SERVICEDESK_ACTIVE, the caller's words are consumed here and are NOT forwarded
to sd_chat — which is what keeps a spoken passcode out of the agent entirely.

    AWAITING_IDENTIFIER
        -> AWAITING_FACTOR_CHOICE      (exactly one map record, Duo preauth ok)
        -> AWAITING_PASSCODE           (no push-capable device)
    AWAITING_FACTOR_CHOICE
        -> PUSH_PENDING | AWAITING_PASSCODE
    PUSH_PENDING / AWAITING_PASSCODE
        -> VERIFIED -> SERVICEDESK_ACTIVE
        -> FAILED_LOCKED

The identifier a caller speaks selects a candidate row and does nothing else.
Authentication is Duo's `result=allow`, and the identity that leaves this module
is read back from the row bound to `duo_user_id` — never from what was spoken.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .graph_corroboration import GraphCorroborator, NullGraphCorroborator
from .identifiers import (
    IdentifierError,
    extract_identifier,
    parse_factor_choice,
)
from .identity_map import AmbiguousIdentifier, EmployeeIdentityMap, EmployeeRecord
from .mfa_provider import (
    MfaProviderError,
    PREAUTH_AUTH,
    RESULT_ALLOW,
    RESULT_DENY,
    RecoveryMfaProvider,
)
from .recovery import TurnOutcome
from .totp import SpokenCodeError, parse_spoken_code

logger = logging.getLogger("voice_gateway")

# A stalled recovery call must not stay open indefinitely.
SESSION_TTL_SECONDS = 900

# Identifier attempts are counted per CALL: a failed lookup has no account to
# charge, so the budget lives on the call instead.
MAX_IDENTIFIER_ATTEMPTS = 5
# Authentication attempts are ALSO counted per account, in the identity map, so
# hanging up and redialling does not reset anything.
MAX_FACTOR_ATTEMPTS = 5

# Push polling. Bounded twice over: a per-turn budget so a tool call returns
# promptly, and an absolute deadline so the transaction cannot be waited on
# forever across turns.
PUSH_TOTAL_TIMEOUT_SECONDS = 90.0
PUSH_TURN_BUDGET_SECONDS = 20.0
PUSH_POLL_INTERVAL_SECONDS = 2.0
MAX_POLLS_PER_TURN = 12


class DuoRecoveryState(str, Enum):
    RECOVERY_STARTED = "RECOVERY_STARTED"
    AWAITING_IDENTIFIER = "AWAITING_IDENTIFIER"
    AWAITING_FACTOR_CHOICE = "AWAITING_FACTOR_CHOICE"
    PUSH_PENDING = "PUSH_PENDING"
    AWAITING_PASSCODE = "AWAITING_PASSCODE"
    VERIFIED = "VERIFIED"
    SERVICEDESK_ACTIVE = "SERVICEDESK_ACTIVE"
    FAILED_LOCKED = "FAILED_LOCKED"


IDENTIFIER_PROMPT = (
    "To get started, please tell me your employee ID. "
    "You can also give your work email address or your registered mobile number."
)
IDENTIFIER_RETRY = (
    "I did not catch an employee ID. Please say your employee ID, "
    "one digit at a time."
)
# ONE message for every lookup and preauth failure. Unknown identifier,
# ambiguous identifier, recovery disabled, no Duo binding, Duo denial and Duo
# "not enrolled" are indistinguishable to the caller by design: any difference
# here turns the phone line into a directory enumeration tool.
GENERIC_LOOKUP_FAILURE = (
    "I could not verify those details. Please say your employee ID, "
    "one digit at a time."
)
FACTOR_PROMPT = (
    "How would you like to verify your identity? I can send a Duo Push "
    "notification, or you can speak the six-digit passcode from Duo Mobile."
)
FACTOR_PROMPT_PASSCODE_ONLY = (
    "To verify your identity, please open Duo Mobile and speak the "
    "six-digit passcode."
)
FACTOR_RETRY = (
    "Sorry, I did not catch that. Say \"push\" to receive a Duo Push "
    "notification, or \"passcode\" to speak a code from Duo Mobile."
)
PUSH_SENT_MESSAGE = (
    "I've sent a verification request to your Duo Mobile app. "
    "Please approve it."
)
PUSH_WAITING_MESSAGE = (
    "I'm still waiting for the request to be approved in Duo Mobile. "
    "Let me know once you've approved it."
)
PUSH_TIMEOUT_MESSAGE = (
    "I did not receive an approval in time. "
    "Would you like me to send another push, or would you prefer to speak a passcode?"
)
PASSCODE_PROMPT = (
    "Please open Duo Mobile and speak the six-digit passcode."
)
PASSCODE_RETRY = (
    "I did not catch six digits. Please say the six-digit passcode again, "
    "one digit at a time."
)
GENERIC_AUTH_FAILURE = (
    "That verification did not succeed. Please open Duo Mobile and "
    "speak the current six-digit passcode."
)
LOCKED_MESSAGE = (
    "Too many attempts. For your security this recovery session is closed. "
    "Please contact the Service Desk by another channel."
)
VERIFIED_MESSAGE = (
    "Thank you. Your identity has been verified for account recovery. "
    "How can I help?"
)
PROVIDER_UNAVAILABLE = (
    "Account recovery is not available right now. "
    "Please contact the Service Desk by another channel."
)


@dataclass
class DuoRecoverySession:
    call_id: str
    state: DuoRecoveryState = DuoRecoveryState.AWAITING_IDENTIFIER
    created_at: float = field(default_factory=time.time)

    # Candidate selected by a spoken identifier. NOT an authenticated identity.
    employee_id: Optional[str] = None
    duo_user_id: Optional[str] = None
    push_device_id: Optional[str] = None
    passcode_capable: bool = False

    # Server-side only. The transaction id is never rendered, never returned to
    # Dograh, and never reaches the LLM.
    txid: Optional[str] = None
    push_deadline: Optional[float] = None

    identifier_attempts: int = 0
    factor_attempts: int = 0
    auth_method: Optional[str] = None
    verified_identity: Optional[dict] = None

    def expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) - self.created_at > SESSION_TTL_SECONDS

    def public_state(self) -> dict[str, Any]:
        """Everything about this session that may be shown outside the gateway.

        The txid is deliberately absent.
        """
        return {"call_id": self.call_id, "state": self.state.value}


class DuoRecoveryManager:
    """All Duo recovery calls for this process, keyed by call_id."""

    def __init__(
        self,
        identity_map: EmployeeIdentityMap,
        provider: RecoveryMfaProvider,
        corroborator: Optional[GraphCorroborator] = None,
        sleep=time.sleep,
    ) -> None:
        self._map = identity_map
        self._provider = provider
        self._corroborator = corroborator or NullGraphCorroborator()
        self._sessions: dict[str, DuoRecoverySession] = {}
        self._lock = threading.Lock()
        self._sleep = sleep

    @property
    def provider(self) -> RecoveryMfaProvider:
        return self._provider

    @property
    def identity_map(self) -> EmployeeIdentityMap:
        return self._map

    # -- lifecycle ---------------------------------------------------------
    def start(self, call_id: str) -> DuoRecoverySession:
        """Begin a recovery call.

        Nothing is looked up here and no identifier is accepted from the web
        page, so this endpoint reveals nothing at all about who is enrolled.
        """
        with self._lock:
            session = DuoRecoverySession(call_id=call_id)
            self._sessions[call_id] = session
            logger.info("duo recovery start call=%s state=%s",
                        call_id[:8], session.state.value)
            return session

    def get(self, call_id: str) -> Optional[DuoRecoverySession]:
        return self._sessions.get(call_id)

    @staticmethod
    def persona_for(identity: dict) -> dict:
        return duo_persona(identity)

    # -- turn handling -----------------------------------------------------
    def handle_turn(self, call_id: str, utterance: str,
                    now: Optional[float] = None) -> TurnOutcome:
        with self._lock:
            session = self._sessions.get(call_id)
            if session is None:
                return TurnOutcome(speak=GENERIC_LOOKUP_FAILURE)

            moment = now if now is not None else time.time()

            if session.state is DuoRecoveryState.SERVICEDESK_ACTIVE:
                return TurnOutcome(forward=True, state=None,
                                   identity=session.verified_identity)
            if session.state is DuoRecoveryState.VERIFIED:
                # The turn AFTER verification is the first real ServiceDesk one.
                session.state = DuoRecoveryState.SERVICEDESK_ACTIVE
                return TurnOutcome(forward=True, identity=session.verified_identity)

            if session.state is DuoRecoveryState.FAILED_LOCKED:
                return TurnOutcome(speak=LOCKED_MESSAGE)
            if session.expired(moment):
                session.state = DuoRecoveryState.FAILED_LOCKED
                return TurnOutcome(speak=LOCKED_MESSAGE)

            try:
                if session.state is DuoRecoveryState.AWAITING_IDENTIFIER:
                    return self._handle_identifier(session, utterance, moment)
                if session.state is DuoRecoveryState.AWAITING_FACTOR_CHOICE:
                    return self._handle_factor_choice(session, utterance, moment)
                if session.state is DuoRecoveryState.PUSH_PENDING:
                    return self._handle_push_poll(session, moment)
                if session.state is DuoRecoveryState.AWAITING_PASSCODE:
                    return self._handle_passcode(session, utterance, moment)
            except MfaProviderError as exc:
                # A provider outage must not look like a failed identity check.
                logger.warning("duo recovery call=%s provider_error=%s",
                               call_id[:8], exc.code)
                return TurnOutcome(speak=PROVIDER_UNAVAILABLE)

            return TurnOutcome(speak=GENERIC_LOOKUP_FAILURE)

    # -- step 1: identifier ------------------------------------------------
    def _handle_identifier(self, session: DuoRecoverySession, utterance: str,
                           moment: float) -> TurnOutcome:
        try:
            identifier = extract_identifier(
                utterance, self._map.default_calling_code
            )
        except IdentifierError as exc:
            # Nothing usable was said - a name, silence, or noise. This is not
            # an authentication attempt and costs no budget, but a caller who
            # never gives an identifier still hits the session TTL.
            logger.info("duo recovery call=%s identifier_miss=%s",
                        session.call_id[:8], exc.category)
            return TurnOutcome(speak=IDENTIFIER_RETRY, state=None)

        session.identifier_attempts += 1
        if session.identifier_attempts > MAX_IDENTIFIER_ATTEMPTS:
            session.state = DuoRecoveryState.FAILED_LOCKED
            return TurnOutcome(speak=LOCKED_MESSAGE)

        try:
            record = self._map.lookup(identifier)
        except AmbiguousIdentifier:
            # Two people match. Never resolved by guessing, and never disclosed.
            logger.warning("duo recovery call=%s lookup=ambiguous kind=%s",
                           session.call_id[:8], identifier.kind.value)
            return TurnOutcome(speak=GENERIC_LOOKUP_FAILURE)

        if record is None or not record.recovery_ready():
            logger.info("duo recovery call=%s lookup=%s kind=%s",
                        session.call_id[:8],
                        "miss" if record is None else "not_recovery_ready",
                        identifier.kind.value)
            return TurnOutcome(speak=GENERIC_LOOKUP_FAILURE)

        if self._map.is_locked(record.employee_id, moment):
            logger.warning("duo recovery call=%s account=%s locked",
                           session.call_id[:8], record.redacted())
            session.state = DuoRecoveryState.FAILED_LOCKED
            return TurnOutcome(speak=LOCKED_MESSAGE)

        # Live device inventory, from Duo, for the BOUND Duo user only.
        preauth = self._provider.preauth(record.duo_user_id)
        if preauth.result != PREAUTH_AUTH:
            # "allow" here is a Duo policy bypass. Accepting it would let a
            # bypass rule authenticate an account-recovery call with no factor
            # at all, so it is refused along with deny and enroll.
            logger.info("duo recovery call=%s preauth=%s account=%s",
                        session.call_id[:8], preauth.result, record.redacted())
            return TurnOutcome(speak=GENERIC_LOOKUP_FAILURE)

        session.employee_id = record.employee_id
        session.duo_user_id = record.duo_user_id
        push_device = preauth.push_device()
        session.push_device_id = push_device.device_id if push_device else None
        session.passcode_capable = preauth.has_passcode_device()

        logger.info("duo recovery call=%s account=%s preauth=auth push=%s otp=%s",
                    session.call_id[:8], record.redacted(),
                    bool(session.push_device_id), session.passcode_capable)

        if session.push_device_id:
            session.state = DuoRecoveryState.AWAITING_FACTOR_CHOICE
            return TurnOutcome(speak=FACTOR_PROMPT)

        # No push-capable device: offer the passcode rather than a dead choice.
        session.state = DuoRecoveryState.AWAITING_PASSCODE
        return TurnOutcome(speak=FACTOR_PROMPT_PASSCODE_ONLY)

    # -- step 2: factor choice --------------------------------------------
    def _handle_factor_choice(self, session: DuoRecoverySession, utterance: str,
                              moment: float) -> TurnOutcome:
        choice = parse_factor_choice(utterance)
        if choice is None:
            return TurnOutcome(speak=FACTOR_RETRY)

        if choice == "passcode":
            session.state = DuoRecoveryState.AWAITING_PASSCODE
            return TurnOutcome(speak=PASSCODE_PROMPT)

        if not session.push_device_id:
            session.state = DuoRecoveryState.AWAITING_PASSCODE
            return TurnOutcome(speak=FACTOR_PROMPT_PASSCODE_ONLY)

        handle = self._provider.start_push(session.duo_user_id, session.push_device_id)
        session.txid = handle.txid          # never leaves this process
        session.push_deadline = moment + PUSH_TOTAL_TIMEOUT_SECONDS
        session.state = DuoRecoveryState.PUSH_PENDING
        session.auth_method = "duo_push"
        logger.info("duo recovery call=%s push sent", session.call_id[:8])

        # Poll immediately: an employee with the phone in hand often approves
        # before the sentence finishes.
        outcome = self._poll_push(session, moment, first_turn=True)
        return outcome

    # -- step 3a: push -----------------------------------------------------
    def _handle_push_poll(self, session: DuoRecoverySession,
                          moment: float) -> TurnOutcome:
        return self._poll_push(session, moment, first_turn=False)

    def _poll_push(self, session: DuoRecoverySession, moment: float,
                   first_turn: bool) -> TurnOutcome:
        """Bounded polling of one push transaction.

        Two bounds, both hard: MAX_POLLS_PER_TURN keeps a single tool call
        short, and push_deadline stops the transaction being waited on forever
        across turns. There is no unbounded loop anywhere in this path.
        """
        if not session.txid:
            session.state = DuoRecoveryState.AWAITING_FACTOR_CHOICE
            return TurnOutcome(speak=FACTOR_RETRY)

        turn_deadline = time.monotonic() + PUSH_TURN_BUDGET_SECONDS
        polls = 0

        while polls < MAX_POLLS_PER_TURN and time.monotonic() < turn_deadline:
            polls += 1
            status = self._provider.poll_push(session.txid)

            if status.result == RESULT_ALLOW:
                logger.info("duo recovery call=%s push=allow", session.call_id[:8])
                return self._verified(session, "duo_push", moment)

            if status.result == RESULT_DENY:
                # An explicit rejection by the device owner. Treated as final:
                # the person holding the enrolled phone said no.
                logger.warning("duo recovery call=%s push=deny", session.call_id[:8])
                session.txid = None
                self._charge_failure(session, moment)
                session.state = DuoRecoveryState.FAILED_LOCKED
                return TurnOutcome(speak=LOCKED_MESSAGE)

            if (session.push_deadline or 0) <= time.time():
                break
            self._sleep(PUSH_POLL_INTERVAL_SECONDS)

        if (session.push_deadline or 0) <= time.time():
            logger.info("duo recovery call=%s push=timeout", session.call_id[:8])
            session.txid = None
            session.push_deadline = None
            self._charge_failure(session, moment)
            if session.state is DuoRecoveryState.FAILED_LOCKED:
                return TurnOutcome(speak=LOCKED_MESSAGE)
            session.state = DuoRecoveryState.AWAITING_FACTOR_CHOICE
            return TurnOutcome(speak=PUSH_TIMEOUT_MESSAGE)

        session.state = DuoRecoveryState.PUSH_PENDING
        return TurnOutcome(speak=PUSH_SENT_MESSAGE if first_turn else PUSH_WAITING_MESSAGE)

    # -- step 3b: spoken passcode -----------------------------------------
    def _handle_passcode(self, session: DuoRecoverySession, utterance: str,
                         moment: float) -> TurnOutcome:
        try:
            passcode = parse_spoken_code(utterance)
        except SpokenCodeError as exc:
            # A transcription miss is not an authentication failure, and
            # counting it would let background noise lock a real caller out.
            logger.info("duo recovery call=%s passcode_parse=%s",
                        session.call_id[:8], exc.category)
            return TurnOutcome(speak=PASSCODE_RETRY)

        # Neither the raw utterance nor the parsed passcode is logged, here or
        # in the provider.
        result = self._provider.verify_passcode(session.duo_user_id, passcode)
        del passcode

        if result.result == RESULT_ALLOW:
            logger.info("duo recovery call=%s passcode=allow", session.call_id[:8])
            return self._verified(session, "duo_passcode", moment)

        logger.info("duo recovery call=%s passcode=deny", session.call_id[:8])
        self._charge_failure(session, moment)
        if session.state is DuoRecoveryState.FAILED_LOCKED:
            return TurnOutcome(speak=LOCKED_MESSAGE)
        return TurnOutcome(speak=GENERIC_AUTH_FAILURE)

    def _charge_failure(self, session: DuoRecoverySession, moment: float) -> None:
        session.factor_attempts += 1
        locked = False
        if session.employee_id:
            # Persisted against the ACCOUNT, so a new call inherits the count.
            locked = self._map.record_failure(session.employee_id, moment)
        if locked or session.factor_attempts >= MAX_FACTOR_ATTEMPTS:
            session.state = DuoRecoveryState.FAILED_LOCKED

    # -- verified ----------------------------------------------------------
    def _verified(self, session: DuoRecoverySession, method: str,
                  moment: float) -> TurnOutcome:
        """Build the trusted identity. Only reachable from Duo result=allow.

        The identity is read back from the record bound to `duo_user_id`, NOT
        from `session.employee_id` and certainly not from anything the caller
        spoke. If the binding no longer resolves, the call fails closed.
        """
        record = self._map.by_duo_user_id(session.duo_user_id or "")
        if record is None or not record.recovery_ready():
            logger.error("duo recovery call=%s verified but binding missing",
                         session.call_id[:8])
            session.state = DuoRecoveryState.FAILED_LOCKED
            return TurnOutcome(speak=LOCKED_MESSAGE)

        corroboration = self._corroborator.corroborate(
            record.entra_tenant_id, record.entra_object_id, record.upn
        )
        if corroboration.available and not corroboration.ok:
            # The directory contradicts the map: wrong tenant, or the object is
            # gone. Fail closed - this is not an outage.
            logger.warning("duo recovery call=%s corroboration_failed reason=%s",
                           session.call_id[:8], corroboration.reason)
            session.state = DuoRecoveryState.FAILED_LOCKED
            return TurnOutcome(speak=LOCKED_MESSAGE)

        session.txid = None
        session.auth_method = method
        self._map.clear_failures(record.employee_id)

        session.verified_identity = {
            "employee_id": record.employee_id,
            "entra_tenant_id": record.entra_tenant_id,
            "entra_object_id": record.entra_object_id,
            "upn": record.upn,
            "display_name": record.display_name or record.upn,
            "duo_user_id": record.duo_user_id,
            "auth_method": method,
            "identity_source": "duo_recovery",
            "recovery_scope": "self_account_recovery",
            "purpose": "account_recovery",
            "graph_corroboration": corroboration.summary(),
        }
        session.state = DuoRecoveryState.VERIFIED
        logger.info(
            "duo recovery call=%s VERIFIED account=%s method=%s corroborated=%s",
            session.call_id[:8], record.redacted(), method,
            corroboration.available and corroboration.ok,
        )
        return TurnOutcome(speak=VERIFIED_MESSAGE, identity=session.verified_identity)


def duo_persona(identity: dict) -> dict:
    """Persona for a Duo-recovered caller, in the existing sd_chat contract.

    Field names match what identity_context_tool already consumes, so this
    reuses the trusted identity contract rather than inventing a second one.
    The provenance markers let downstream policy see that this identity came
    from a recovery factor rather than a full Entra sign-in, and that its scope
    is the caller's own account only.

    `userPrincipalName` stays the LOCAL alias even when Graph reports a
    different one: the object id is canonical and is carried in `id`, and
    silently retargeting an active call to a directory-supplied UPN is exactly
    what the drift check exists to prevent.
    """
    persona = {
        "userPrincipalName": identity["upn"],
        "mail": identity["upn"],
        "displayName": identity.get("display_name") or identity["upn"],
        "identity_source": "duo_recovery",
        "recovery_scope": "self_account_recovery",
        "auth_method": identity.get("auth_method", "duo_recovery"),
    }
    if identity.get("entra_object_id"):
        persona["id"] = identity["entra_object_id"]
    if identity.get("employee_id"):
        persona["employee_id"] = identity["employee_id"]
    corroboration = identity.get("graph_corroboration") or {}
    if corroboration.get("upn_drift"):
        # Surfaced, never acted on.
        persona["upn_drift_detected"] = True
    return persona
