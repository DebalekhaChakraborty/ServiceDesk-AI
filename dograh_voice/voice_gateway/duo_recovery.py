"""ServiceDesk Voice AI: the deterministic pre-ServiceDesk state machine.

This is the external, unauthenticated voice line. It is NOT an account-recovery
bot — a caller may reach it for a locked account, a forgotten password, VPN, a
printer, software, an incident, a request, or anything else the Service Desk
handles. They are outside the Entra-protected portal because they often cannot
sign in, and that says nothing at all about what they want. Duo is the identity
check that stands between them and sd_chat; it is not the purpose of the call.

Owned entirely by Python. Dograh transcribes speech and speaks replies; it never
decides who the caller is, never sees a Duo transaction id, never sees a
passcode, and never chooses a factor. Until the machine reaches
SERVICEDESK_ACTIVE, the caller's words are consumed here and are NOT forwarded
to sd_chat — which is what keeps a spoken passcode out of the agent entirely,
and what keeps an unauthenticated stranger out of it.

    AWAITING_REQUEST               (every external call starts here)
        -> AWAITING_REQUEST            (greeting, or identifier volunteered early)
        -> AWAITING_IDENTIFIER         (a ServiceDesk request was stated)
    AWAITING_IDENTIFIER
        -> AWAITING_FACTOR_CHOICE      (exactly one map record, Duo preauth ok)
        -> AWAITING_PASSCODE           (no push-capable device)
    AWAITING_FACTOR_CHOICE
        -> PUSH_PENDING | AWAITING_PASSCODE
    PUSH_PENDING / AWAITING_PASSCODE
        -> VERIFIED -> SERVICEDESK_ACTIVE
        -> SERVICEDESK_ACTIVE          (direct, carrying the pending request)
        -> FAILED_LOCKED
        -> FAILED_UNAVAILABLE

The identifier a caller speaks selects a candidate row and does nothing else.
Authentication is Duo's `result=allow`, and the identity that leaves this module
is read back from the row bound to `duo_user_id` — never from what was spoken.

A Duo `allow` is necessary but NOT sufficient. VERIFIED additionally requires a
live, uncontradicted Graph read of the mapped object id; without one the call
ends in FAILED_UNAVAILABLE and no identity is built. See `_verified`.

The caller's original request is held in `pending_request` for the whole of that
journey and released to sd_chat exactly once, at the moment an identity is
built. It is a problem statement and nothing more: it never influences the
lookup, never influences authentication, and cannot itself cause a forward.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Optional

from .conversation import classify_opening
from .graph_corroboration import (
    CorroborationResult,
    GraphCorroborator,
    NullGraphCorroborator,
)
from .identifiers import (
    IdentifierError,
    SpokenIdentifier,
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

# An opening utterance longer than this is not stored as the pending request.
# The gateway's own max_text_chars gate runs AFTER this module, so without a
# bound here an unbounded transcript could sit in process memory for the whole
# session TTL. A caller who genuinely says this much is asked to be brief.
MAX_REQUEST_CHARS = 1000


class DuoRecoveryState(str, Enum):
    RECOVERY_STARTED = "RECOVERY_STARTED"
    # Where every external call now begins: the caller says what they need
    # before anyone asks who they are.
    AWAITING_REQUEST = "AWAITING_REQUEST"
    AWAITING_IDENTIFIER = "AWAITING_IDENTIFIER"
    AWAITING_FACTOR_CHOICE = "AWAITING_FACTOR_CHOICE"
    PUSH_PENDING = "PUSH_PENDING"
    AWAITING_PASSCODE = "AWAITING_PASSCODE"
    VERIFIED = "VERIFIED"
    SERVICEDESK_ACTIVE = "SERVICEDESK_ACTIVE"
    FAILED_LOCKED = "FAILED_LOCKED"
    # Terminal, but NOT an authentication failure: our own dependency could not
    # answer. Kept distinct from FAILED_LOCKED so the caller is told to try
    # again rather than that they are locked out, and so an outage never
    # charges an account a failure it did not commit.
    FAILED_UNAVAILABLE = "FAILED_UNAVAILABLE"


# The first thing an external caller hears. It identifies the line as the
# Service Desk, asks nothing about identity, and assumes nothing about intent.
WELCOME_PROMPT = "Welcome to ServiceDesk. How can I help you today?"
# A greeting is answered, not authenticated. Saying "hello" must never send a
# Duo Push.
SMALL_TALK_REPLY = "Yes, I'm here. How can I help you today?"
# Nothing usable was said at all.
WELCOME_RETRY = "Sorry, I didn't catch that. How can I help you today?"
# Said when a caller opens with their employee ID because an older script
# taught them to. The identifier is kept; the question is what they need.
REQUEST_PROMPT_AFTER_IDENTIFIER = (
    "Thank you. Before I look anything up — how can I help you today?"
)
# Neutral acknowledgement. It deliberately claims NO diagnosis: sd_chat has not
# seen the request yet, so the line must not imply it has found or understood
# anything.
VERIFY_FIRST_ACK = (
    "I can help with that. Since you're calling without signing in, "
    "I need to verify your identity first."
)
IDENTIFIER_PROMPT = (
    "Please tell me your employee ID. "
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
# Push-capable device that does NOT advertise mobile_otp. The passcode is not
# mentioned at all: naming a factor the device cannot perform invites the
# caller to read a code nothing can generate.
FACTOR_PROMPT_PUSH_ONLY = (
    "To verify your identity, I can send a Duo Push notification to your "
    "device. Say \"push\" when you are ready."
)
FACTOR_RETRY = (
    "Sorry, I did not catch that. Say \"push\" to receive a Duo Push "
    "notification, or \"passcode\" to speak a code from Duo Mobile."
)
FACTOR_RETRY_PUSH_ONLY = (
    "Sorry, I did not catch that. Say \"push\" to receive a Duo Push "
    "notification in Duo Mobile."
)
# Spoken when a caller asks for a passcode on a device that cannot produce one.
# A misunderstanding, not a failed authentication - it costs no attempt budget.
PASSCODE_NOT_AVAILABLE = (
    "Your device is not set up to generate passcodes. I can send a Duo Push "
    "notification instead. Say \"push\" when you are ready."
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
PUSH_TIMEOUT_MESSAGE_PUSH_ONLY = (
    "I did not receive an approval in time. "
    "Would you like me to send another push?"
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
    "Thank you. I've verified your identity. How can I help you today?"
)
# Said when the caller already told us what they need. It promises to look, not
# to have looked: the sd_chat reply is appended to this sentence by the gateway,
# so nothing here may pre-empt what that reply turns out to say.
VERIFIED_CONTINUING = (
    "Thank you, your identity is verified. Let me pick up where we left off."
)
PROVIDER_UNAVAILABLE = (
    "I can't verify your identity right now. "
    "Please contact the Service Desk by another channel."
)
# Spoken when corroboration could not be obtained. Deliberately says nothing
# about which dependency failed, and deliberately does not say "locked": the
# caller did nothing wrong and a later call may well succeed.
CORROBORATION_UNAVAILABLE = (
    "I can't complete verification right now. Please try your call again in a "
    "few minutes, or contact the Service Desk by another channel."
)


@dataclass
class DuoRecoverySession:
    call_id: str
    state: DuoRecoveryState = DuoRecoveryState.AWAITING_REQUEST
    created_at: float = field(default_factory=time.time)

    # What the caller said they need, VERBATIM. Server-side only: it is never
    # placed in the signed bootstrap, never returned to Dograh, never a preset
    # parameter, and never supplied by browser initialization. It is a problem
    # statement and carries no authority whatsoever — it cannot select an
    # account, cannot bypass a factor, and cannot on its own cause a forward.
    pending_request: Optional[str] = None
    # Released to sd_chat exactly once, at the moment an identity is built.
    pending_request_forwarded: bool = False

    # An identifier the caller volunteered before being asked. Untrusted, and
    # nothing more than a lookup key held so they need not repeat it.
    candidate_identifier: Optional[SpokenIdentifier] = None

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

    # What a terminal FAILED_UNAVAILABLE session keeps saying. Held so the
    # sentence a caller hears on the turn AFTER the failure matches the one
    # that ended the call, rather than switching to a different explanation.
    terminal_message: Optional[str] = None

    def expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) - self.created_at > SESSION_TTL_SECONDS

    def public_state(self) -> dict[str, Any]:
        """Everything about this session that may be shown outside the gateway.

        The txid is deliberately absent, and so is the pending request: the
        caller's own words are theirs, not telemetry.
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
        """Begin an external ServiceDesk call.

        Nothing is looked up here and no identifier is accepted from the web
        page, so this endpoint reveals nothing at all about who is enrolled.
        The call opens in AWAITING_REQUEST, not AWAITING_IDENTIFIER: the line
        asks what the caller needs before it asks who they are.
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
            if session.state is DuoRecoveryState.FAILED_UNAVAILABLE:
                return TurnOutcome(
                    speak=session.terminal_message or CORROBORATION_UNAVAILABLE
                )
            if session.expired(moment):
                session.state = DuoRecoveryState.FAILED_LOCKED
                return TurnOutcome(speak=LOCKED_MESSAGE)

            try:
                if session.state is DuoRecoveryState.AWAITING_REQUEST:
                    return self._handle_request(session, utterance, moment)
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

    # -- step 0: what does the caller need? --------------------------------
    def _handle_request(self, session: DuoRecoverySession, utterance: str,
                        moment: float) -> TurnOutcome:
        """Capture the caller's ServiceDesk request. Forwards NOTHING.

        This is the turn that makes the line ServiceDesk-first rather than
        recovery-first, and it is also the turn most likely to be mistaken for
        a security shortcut. It is not one: the request is stored locally, the
        state advances only as far as "now prove who you are", and no byte of
        what was said here reaches sd_chat until Duo and Graph have both
        passed. The caller has, at this point, established nothing.
        """
        if len(utterance or "") > MAX_REQUEST_CHARS:
            logger.info("duo recovery call=%s opening=too_long", session.call_id[:8])
            return TurnOutcome(speak=WELCOME_RETRY)

        opening = classify_opening(utterance, self._map.default_calling_code)
        # The caller's words are never logged; only what they were shaped like.
        logger.info("duo recovery call=%s opening %s",
                    session.call_id[:8], opening.redacted())

        if opening.request is None:
            if opening.identifier is not None:
                # Backward compatible with the older identifier-first script.
                # Retained as an untrusted lookup candidate ONLY, so the caller
                # is not made to say it twice. It selects nobody until a
                # request arrives and the lookup actually runs.
                session.candidate_identifier = opening.identifier
                return TurnOutcome(speak=REQUEST_PROMPT_AFTER_IDENTIFIER)
            # A greeting, or noise. Neither starts authentication, and neither
            # is stored: "hello" must never send a Duo Push. The caller is
            # asked again, bounded only by the session TTL — nothing here
            # costs an attempt, contacts Duo, or reaches sd_chat, so there is
            # no budget for a re-prompt to protect.
            return TurnOutcome(speak=SMALL_TALK_REPLY if opening.small_talk
                               else WELCOME_RETRY)

        session.pending_request = opening.request

        # An identifier spoken in the SAME breath is used; otherwise one kept
        # from an earlier identifier-first opening is. Either way it is only a
        # lookup key, and it is consumed here so it can never be reused.
        identifier = opening.identifier or session.candidate_identifier
        session.candidate_identifier = None
        session.state = DuoRecoveryState.AWAITING_IDENTIFIER

        if identifier is None:
            return TurnOutcome(speak=f"{VERIFY_FIRST_ACK} {IDENTIFIER_PROMPT}")

        # The retained identifier goes through the SAME resolution path as a
        # spoken one, attempt budget included, so preserving it grants nothing.
        outcome = self._resolve_identifier(session, identifier, moment)
        if outcome.speak:
            return replace(outcome, speak=f"{VERIFY_FIRST_ACK} {outcome.speak}")
        return outcome

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

        return self._resolve_identifier(session, identifier, moment)

    def _resolve_identifier(self, session: DuoRecoverySession,
                            identifier: SpokenIdentifier,
                            moment: float) -> TurnOutcome:
        """Turn one normalised identifier into a candidate row, or nothing."""
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

        return self._offer_factors(session, record)

    def _offer_factors(self, session: DuoRecoverySession,
                       record: EmployeeRecord) -> TurnOutcome:
        """Offer exactly the factors THIS device advertises, and nothing else.

        Capability comes from the live preauth response and never from the local
        map, which stores a mobile number as a lookup alias and knows nothing
        about what the device can do.

        Offering an unusable factor is not a cosmetic problem. A caller who
        accepts it is sent to read a code no device can generate, and every
        attempt charges the ACCOUNT a failure - so an option we should never
        have mentioned walks a legitimate caller into a lockout.
        """
        has_push = bool(session.push_device_id)
        has_otp = session.passcode_capable

        if has_push and has_otp:
            session.state = DuoRecoveryState.AWAITING_FACTOR_CHOICE
            return TurnOutcome(speak=FACTOR_PROMPT)

        if has_push:
            session.state = DuoRecoveryState.AWAITING_FACTOR_CHOICE
            return TurnOutcome(speak=FACTOR_PROMPT_PUSH_ONLY)

        if has_otp:
            session.state = DuoRecoveryState.AWAITING_PASSCODE
            return TurnOutcome(speak=FACTOR_PROMPT_PASSCODE_ONLY)

        # Enrolled, but nothing on the account can actually authenticate. The
        # caller has attempted nothing, so no failure is charged. The wording is
        # the one used for a Duo outage on purpose: "enrolled with no usable
        # device" must not be distinguishable from "Duo is unreachable".
        logger.error("duo recovery call=%s FAIL_CLOSED no_usable_factor account=%s",
                     session.call_id[:8], record.redacted())
        session.state = DuoRecoveryState.FAILED_UNAVAILABLE
        session.terminal_message = PROVIDER_UNAVAILABLE
        return TurnOutcome(speak=PROVIDER_UNAVAILABLE)

    # -- step 2: factor choice --------------------------------------------
    def _handle_factor_choice(self, session: DuoRecoverySession, utterance: str,
                              moment: float) -> TurnOutcome:
        choice = parse_factor_choice(utterance)
        if choice is None:
            return TurnOutcome(speak=FACTOR_RETRY if session.passcode_capable
                               else FACTOR_RETRY_PUSH_ONLY)

        if choice == "passcode":
            if not session.passcode_capable:
                # Asking for a factor the device cannot perform is a
                # misunderstanding, not a failed authentication: the state does
                # not move and no attempt budget is spent.
                logger.info("duo recovery call=%s passcode_requested_unavailable",
                            session.call_id[:8])
                return TurnOutcome(speak=PASSCODE_NOT_AVAILABLE)
            session.state = DuoRecoveryState.AWAITING_PASSCODE
            return TurnOutcome(speak=PASSCODE_PROMPT)

        if not session.push_device_id:
            if session.passcode_capable:
                session.state = DuoRecoveryState.AWAITING_PASSCODE
                return TurnOutcome(speak=FACTOR_PROMPT_PASSCODE_ONLY)
            session.state = DuoRecoveryState.FAILED_UNAVAILABLE
            session.terminal_message = PROVIDER_UNAVAILABLE
            return TurnOutcome(speak=PROVIDER_UNAVAILABLE)

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
            return TurnOutcome(speak=PUSH_TIMEOUT_MESSAGE if session.passcode_capable
                               else PUSH_TIMEOUT_MESSAGE_PUSH_ONLY)

        session.state = DuoRecoveryState.PUSH_PENDING
        return TurnOutcome(speak=PUSH_SENT_MESSAGE if first_turn else PUSH_WAITING_MESSAGE)

    # -- step 3b: spoken passcode -----------------------------------------
    def _handle_passcode(self, session: DuoRecoverySession, utterance: str,
                         moment: float) -> TurnOutcome:
        if not session.passcode_capable:
            # Unreachable through _offer_factors and _handle_factor_choice, and
            # asserted here anyway: this is the single line standing between a
            # push-only caller and an account failure charged for a code their
            # device cannot produce. It must never depend on callers upstream
            # having got the capability check right.
            logger.warning("duo recovery call=%s passcode_state_without_capability",
                           session.call_id[:8])
            session.state = DuoRecoveryState.AWAITING_FACTOR_CHOICE
            return TurnOutcome(speak=PASSCODE_NOT_AVAILABLE)

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
        """Build the trusted identity. Duo `allow` is necessary, not sufficient.

        Two independent gates must both pass:

        1. the `duo_user_id` binding still resolves to a recovery-ready row -
           the identity is read back from THAT row, not from
           `session.employee_id` and certainly not from anything the caller
           spoke;
        2. Microsoft Graph confirms, live, that the mapped object id still
           exists in the expected tenant.

        Gate 2 fails closed on BOTH contradiction and unavailability. A Duo
        allow on its own establishes no identity_context: it proves possession
        of the enrolled phone, and nothing about whether the local row is still
        true. The two failures are distinguished only in what the caller hears
        and in whether the session is treated as an authentication failure.
        """
        record = self._map.by_duo_user_id(session.duo_user_id or "")
        if record is None or not record.recovery_ready():
            logger.error("duo recovery call=%s verified but binding missing",
                         session.call_id[:8])
            session.txid = None
            session.state = DuoRecoveryState.FAILED_LOCKED
            return TurnOutcome(speak=LOCKED_MESSAGE)

        try:
            corroboration = self._corroborator.corroborate(
                record.entra_tenant_id, record.entra_object_id, record.upn
            )
        except Exception as exc:
            # A corroborator that raises is an unavailable corroborator. It must
            # never become an implicit pass by escaping to a caller that only
            # knows how to report a provider outage.
            logger.warning("duo recovery call=%s corroboration_raised=%s",
                           session.call_id[:8], type(exc).__name__)
            corroboration = CorroborationResult(
                available=False, ok=False, reason="corroborator_error"
            )

        if not corroboration.establishes_identity():
            session.txid = None
            if not corroboration.available:
                # Our own dependency is down, or was never configured. The
                # caller is not at fault, so no account failure is charged and
                # nothing is said about being locked out - but no identity is
                # built either.
                logger.error(
                    "duo recovery call=%s FAIL_CLOSED corroboration_unavailable "
                    "reason=%s account=%s",
                    session.call_id[:8], corroboration.reason, record.redacted(),
                )
                session.state = DuoRecoveryState.FAILED_UNAVAILABLE
                session.terminal_message = CORROBORATION_UNAVAILABLE
                return TurnOutcome(speak=CORROBORATION_UNAVAILABLE)

            # The directory contradicts the map: wrong tenant, or the object is
            # gone. Terminal, and not something a retry can fix.
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

        # The caller already told us what they need, so they are not asked to
        # say it again. This is the ONLY place the pending request is released,
        # it is reachable only past both gates above, and the flag makes it a
        # one-shot: every later turn forwards what the caller actually says.
        if session.pending_request and not session.pending_request_forwarded:
            session.pending_request_forwarded = True
            session.state = DuoRecoveryState.SERVICEDESK_ACTIVE
            logger.info("duo recovery call=%s pending_request forwarded=true",
                        session.call_id[:8])
            return TurnOutcome(
                speak=VERIFIED_CONTINUING,
                forward=True,
                forward_text=session.pending_request,
                identity=session.verified_identity,
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
