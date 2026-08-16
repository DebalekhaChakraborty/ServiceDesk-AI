"""ServiceDesk-first external voice: what the caller says, and when it moves.

The external line is **ServiceDesk Voice AI**, not an account-recovery bot. A
caller reaches it for a locked account, a forgotten password, VPN, a printer,
software, an incident, or anything else the Service Desk handles; being outside
the Entra-protected portal tells us only that they could not sign in, which is
not a statement of intent. So they say what they need FIRST, and Duo is the
identity check that follows.

That reordering creates exactly one new thing to get wrong. The caller's request
is, unlike a spoken passcode, genuinely meant for sd_chat — just not yet. It is
held server-side across the whole authentication journey and released once, at
the moment an identity is built. Every test below is about the "not yet": which
turns capture it, which turns must never move it, and the single turn that may.

Three properties are load-bearing:

    a greeting is not a request        - "hello" must not send a Duo Push;
    an identifier is not a request     - "my employee ID is 1999" states no
                                         problem, and is not one;
    a request is not an identity       - it selects nobody, proves nothing, and
                                         reaches sd_chat only past Duo AND Graph.
"""

from __future__ import annotations

import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from voice_gateway.app import create_app
from voice_gateway.conversation import classify_opening
from voice_gateway.duo_recovery import (
    CORROBORATION_UNAVAILABLE,
    DuoRecoveryManager,
    DuoRecoveryState,
    FACTOR_PROMPT_PUSH_ONLY,
    GENERIC_LOOKUP_FAILURE,
    LOCKED_MESSAGE,
    MAX_REQUEST_CHARS,
    PROVIDER_UNAVAILABLE,
    REQUEST_PROMPT_AFTER_IDENTIFIER,
    SMALL_TALK_REPLY,
    VERIFIED_CONTINUING,
    VERIFIED_MESSAGE,
    VERIFY_FIRST_ACK,
    WELCOME_PROMPT,
    WELCOME_RETRY,
)
from voice_gateway.graph_corroboration import CorroborationResult, GraphCorroborator
from voice_gateway.identifiers import IdentifierKind
from voice_gateway.identity import mint, mint_recovery_bootstrap
from voice_gateway.identity_map import MAX_FAILURES
from voice_gateway.mfa_provider import CAP_MOBILE_OTP, CAP_PUSH, Device
from voice_gateway.servicedesk_client import ServiceDeskClient
from voice_gateway.session import auth_session_id

from test_authenticated_identity import RecordingServiceDesk, SECRET, auth_settings
from test_duo_recovery import (
    ALICE_ID,
    ALICE_OID,
    ALICE_UPN,
    BOB_OID,
    BOB_UPN,
    CorroboratingStub,
    UnavailableCorroborator,
    enrolled,          # noqa: F401 - pytest fixture
    identity_map,      # noqa: F401 - pytest fixture
    provider,          # noqa: F401 - pytest fixture
)

VPN_REQUEST = "My VPN keeps disconnecting."
PUSH_ONLY = (Device(device_id="DEV-P", display_name="Android", device_type="phone",
                    capabilities=frozenset({CAP_PUSH})),)
BOTH_FACTORS = (Device(device_id="DEV-B", display_name="iPhone", device_type="phone",
                       capabilities=frozenset({CAP_PUSH, CAP_MOBILE_OTP})),)


@pytest.fixture(autouse=True)
def _signing_secret(monkeypatch):
    monkeypatch.setenv("VOICE_IDENTITY_SIGNING_SECRET", SECRET)


@pytest.fixture
def manager(enrolled, provider):                              # noqa: F811
    return DuoRecoveryManager(enrolled, provider, CorroboratingStub(),
                              sleep=lambda _: None)


def duo_manager(identity_map, provider, corroborator):        # noqa: F811
    return DuoRecoveryManager(identity_map, provider, corroborator,
                              sleep=lambda _: None)


class Contradicting(GraphCorroborator):
    """The directory says the mapped object is not there."""

    def corroborate(self, tenant_id, object_id, expected_upn):
        return CorroborationResult(available=True, ok=False,
                                   reason="object_not_found", object_exists=False)


# ---------------------------------------------------------------------------
# gateway plumbing
# ---------------------------------------------------------------------------

def gateway(manager, reply="Your VPN profile was reset."):
    """A TestClient over a mocked ServiceDesk, with `manager` as the voice path."""
    fake = RecordingServiceDesk(reply=reply)
    settings = auth_settings()
    sd = ServiceDeskClient(
        base_url=settings.servicedesk_base_url,
        app_name=settings.app_name, user_id=settings.user_id,
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
    )
    client = TestClient(create_app(settings=settings, client=sd, recovery=manager))
    return client, fake


def sent_texts(fake) -> list[str]:
    """Every user utterance the gateway actually forwarded to sd_chat."""
    return [p["newMessage"]["parts"][0]["text"] for p in fake.run_payloads]


def say(client, call_id, token, text):
    return client.post("/voice/turn", json={
        "call_id": call_id, "voice_identity_token": token, "text": text,
    })


def call_through_gateway(manager, utterances, call_id="call-e2e", reply="Reply."):
    """Drive a whole external call over HTTP and hand back what was recorded."""
    client, fake = gateway(manager, reply=reply)
    manager.start(call_id)
    token = mint_recovery_bootstrap(call_id, SECRET)
    spoken = []
    with client:
        for utterance in utterances:
            response = say(client, call_id, token, utterance)
            assert response.status_code == 200, (utterance, response.text)
            spoken.append(response.json()["text"])
    return fake, spoken


# ===========================================================================
# 17. REQUEST CAPTURE
#
# The opening turn. Nothing here authenticates anybody, and nothing here may
# start authentication on its own.
# ===========================================================================

def test_17_a_first_request_is_captured_and_not_forwarded(manager, provider):  # noqa: F811
    """A: a stated problem is stored verbatim and moves the call to identity."""
    call_id = "call-17a"
    manager.start(call_id)
    assert manager.get(call_id).state is DuoRecoveryState.AWAITING_REQUEST

    outcome = manager.handle_turn(call_id, VPN_REQUEST)
    session = manager.get(call_id)

    assert session.pending_request == VPN_REQUEST      # exact caller text
    assert session.pending_request_forwarded is False
    assert outcome.forward is False                    # forwarded_to_sd_chat
    assert outcome.forward_text is None
    assert outcome.identity is None
    assert session.state is DuoRecoveryState.AWAITING_IDENTIFIER

    # The reply acknowledges without claiming to have diagnosed anything.
    assert outcome.speak.startswith(VERIFY_FIRST_ACK)
    # Nothing has been asked of Duo: a request selects no account.
    assert provider.called("preauth") == []
    assert session.employee_id is None and session.duo_user_id is None


@pytest.mark.parametrize("request_text", [
    "My VPN keeps disconnecting.",
    "I can't print to the finance printer.",
    "My account is locked and I can't sign in.",
    "Outlook crashes when I open it.",
    "I need to raise an incident for a failed deployment.",
])
def test_17_a2_any_servicedesk_need_is_a_request(manager, request_text):
    """The line is not a password-reset feature: every need opens the same way."""
    call_id = f"call-17a2-{abs(hash(request_text))}"
    manager.start(call_id)
    manager.handle_turn(call_id, request_text)

    session = manager.get(call_id)
    assert session.pending_request == request_text
    assert session.state is DuoRecoveryState.AWAITING_IDENTIFIER


@pytest.mark.parametrize("greeting", [
    "hello", "Hi", "hey", "Good morning", "can you hear me",
    "Hello? Is anyone there?", "yes", "thanks",
])
def test_17_b_small_talk_starts_nothing(manager, provider, greeting):  # noqa: F811
    """B: "hello" is answered, not authenticated."""
    call_id = f"call-17b-{abs(hash(greeting))}"
    manager.start(call_id)
    outcome = manager.handle_turn(call_id, greeting)
    session = manager.get(call_id)

    assert outcome.speak == SMALL_TALK_REPLY
    assert outcome.forward is False
    assert session.pending_request is None             # not stored as a request
    assert session.candidate_identifier is None        # no candidate identity
    assert session.state is DuoRecoveryState.AWAITING_REQUEST
    # No Duo contact of any kind, and no attempt budget spent.
    assert provider.called("preauth") == []
    assert provider.called("start_push") == []
    assert session.identifier_attempts == 0
    assert session.factor_attempts == 0


def test_17_b2_repeated_greetings_never_escalate(manager, provider):  # noqa: F811
    """A chatty caller does not talk their way into a push."""
    call_id = "call-17b2"
    manager.start(call_id)
    for _ in range(6):
        assert manager.handle_turn(call_id, "hello?").speak == SMALL_TALK_REPLY

    assert manager.get(call_id).state is DuoRecoveryState.AWAITING_REQUEST
    assert provider.called("start_push") == []
    assert provider.called("preauth") == []


def test_17_b3_unintelligible_speech_asks_again(manager):
    """Noise is not a request either, and is not treated as one."""
    call_id = "call-17b3"
    manager.start(call_id)
    outcome = manager.handle_turn(call_id, "um, uh...")

    assert outcome.speak == WELCOME_RETRY
    assert manager.get(call_id).pending_request is None
    assert manager.get(call_id).state is DuoRecoveryState.AWAITING_REQUEST


@pytest.mark.parametrize("opening", [
    "My employee ID is 1798283.",
    "employee id one seven nine eight two eight three",
    f"my work email is {ALICE_UPN}",
])
def test_17_c_an_identifier_is_not_the_business_request(manager, provider, opening):  # noqa: F811
    """C: an ID states no problem, so it does not become the pending request."""
    call_id = f"call-17c-{abs(hash(opening))}"
    manager.start(call_id)
    outcome = manager.handle_turn(call_id, opening)
    session = manager.get(call_id)

    assert session.pending_request is None             # NOT the request
    assert outcome.speak == REQUEST_PROMPT_AFTER_IDENTIFIER
    assert session.state is DuoRecoveryState.AWAITING_REQUEST
    # Retained as a lookup candidate only. It has selected nobody: no map read,
    # no Duo call, no employee bound to this session.
    assert session.candidate_identifier is not None
    assert session.employee_id is None
    assert provider.called("preauth") == []


def test_17_c2_a_retained_identifier_is_not_asked_for_twice(manager, provider):  # noqa: F811
    """The caller led with their ID; they should not have to repeat it."""
    call_id = "call-17c2"
    manager.start(call_id)
    manager.handle_turn(call_id, f"My employee ID is {ALICE_ID}.")

    outcome = manager.handle_turn(call_id, VPN_REQUEST)
    session = manager.get(call_id)

    # The request is captured AND the retained identifier resolved in one turn.
    assert session.pending_request == VPN_REQUEST
    assert outcome.speak.startswith(VERIFY_FIRST_ACK)
    assert provider.called("preauth") == [("preauth", "duo-user-alice")]
    assert session.duo_user_id == "duo-user-alice"
    # ...and it is consumed, so it cannot be replayed on a later turn.
    assert session.candidate_identifier is None


def test_17_c3_a_retained_identifier_still_costs_an_attempt(manager):
    """Preserving it is a convenience, not a way around the attempt budget."""
    call_id = "call-17c3"
    manager.start(call_id)
    manager.handle_turn(call_id, "my employee ID is 4040404")     # unknown
    assert manager.get(call_id).identifier_attempts == 0          # not looked up yet

    manager.handle_turn(call_id, VPN_REQUEST)
    assert manager.get(call_id).identifier_attempts == 1


def test_17_c4_a_retained_identifier_that_matches_nobody_says_the_generic_line(manager):
    """The lookup still fails closed, and still says one indistinguishable thing."""
    call_id = "call-17c4"
    manager.start(call_id)
    manager.handle_turn(call_id, "my employee ID is 4040404")
    outcome = manager.handle_turn(call_id, VPN_REQUEST)

    assert GENERIC_LOOKUP_FAILURE in outcome.speak
    assert manager.get(call_id).state is DuoRecoveryState.AWAITING_IDENTIFIER
    assert manager.get(call_id).pending_request == VPN_REQUEST    # still held


def test_17_d_a_request_and_an_identifier_in_one_breath(manager, provider):  # noqa: F811
    """Both are taken: the words are the request, the digits are the candidate."""
    call_id = "call-17d"
    manager.start(call_id)
    spoken = f"My VPN keeps disconnecting and my employee ID is {ALICE_ID}."
    outcome = manager.handle_turn(call_id, spoken)
    session = manager.get(call_id)

    assert session.pending_request == spoken
    assert provider.called("preauth") == [("preauth", "duo-user-alice")]
    assert outcome.forward is False
    assert session.state is DuoRecoveryState.AWAITING_FACTOR_CHOICE


def test_17_e_an_absurdly_long_opening_is_not_stored(manager):
    """The gateway's length gate runs later, so this one runs here."""
    call_id = "call-17e"
    manager.start(call_id)
    outcome = manager.handle_turn(call_id, "my vpn " + "x" * MAX_REQUEST_CHARS)

    assert outcome.speak == WELCOME_RETRY
    assert manager.get(call_id).pending_request is None
    assert manager.get(call_id).state is DuoRecoveryState.AWAITING_REQUEST


def test_17_f_the_opening_prompt_is_a_servicedesk_greeting():
    """It names the Service Desk, and asks nothing about identity or intent."""
    lowered = WELCOME_PROMPT.lower()
    assert "servicedesk" in lowered or "service desk" in lowered
    for banned in ("employee id", "employee number", "recovery", "recover",
                   "password", "email address", "mobile", "duo"):
        assert banned not in lowered, WELCOME_PROMPT


def test_17_g_recovery_start_hands_back_the_servicedesk_greeting(manager):
    """The bootstrap endpoint no longer opens with "tell me your employee ID"."""
    client, _ = gateway(manager)
    with client:
        response = client.post("/recovery/start", json={
            "call_id": "call-17g",
            "recovery_token": mint_recovery_bootstrap("call-17g", SECRET),
        })
    assert response.status_code == 200
    assert response.json()["prompt"] == WELCOME_PROMPT


def test_17_h_pre_verification_replies_claim_no_diagnosis(manager):
    """The line must not pretend to know anything sd_chat has not been asked."""
    call_id = "call-17h"
    manager.start(call_id)
    spoken = [manager.handle_turn(call_id, VPN_REQUEST).speak,
              manager.handle_turn(call_id, f"employee id {ALICE_ID}").speak]

    blob = " ".join(s for s in spoken if s).lower()
    for claim in ("i have found", "i found", "i know why", "i'll reset",
                  "i will reset", "your account is locked", "the problem is"):
        assert claim not in blob, blob


# ===========================================================================
# 18. AUTH BOUNDARY
#
# The whole point of holding the request. Every test drives a call that states
# a real problem, fails identity in a different way, and asserts that sd_chat
# was never contacted at all.
# ===========================================================================

def test_18_a_request_does_not_reach_servicedesk_before_duo_allow(manager, provider):  # noqa: F811
    """The request is stated, an account is selected, a push is in flight."""
    provider.devices = PUSH_ONLY
    provider.push_results = ["waiting"]

    fake, _ = call_through_gateway(manager, [
        VPN_REQUEST, f"my employee ID is {ALICE_ID}", "push", "not yet",
    ], call_id="call-18a")

    assert fake.run_payloads == []
    assert fake.created_state == {}
    assert VPN_REQUEST not in json.dumps(fake.run_payloads)


def test_18_b_request_does_not_reach_servicedesk_before_corroboration(enrolled, provider):  # noqa: F811
    """Duo allowed. Graph could not answer. Still nothing forwarded."""
    manager = duo_manager(enrolled, provider, UnavailableCorroborator())
    provider.push_results = ["allow"]

    fake, spoken = call_through_gateway(manager, [
        VPN_REQUEST, f"my employee ID is {ALICE_ID}", "push",
    ], call_id="call-18b")

    # Duo really did authenticate; this is not a Duo failure being caught.
    assert provider.called("start_push") != []
    assert fake.run_payloads == []
    assert fake.created_state == {}
    assert spoken[-1] == CORROBORATION_UNAVAILABLE
    assert manager.get("call-18b").pending_request == VPN_REQUEST
    assert manager.get("call-18b").pending_request_forwarded is False


def test_18_c_duo_deny_forwards_nothing(manager, provider):  # noqa: F811
    """The person holding the enrolled phone said no."""
    provider.devices = PUSH_ONLY
    provider.push_results = ["deny"]

    fake, spoken = call_through_gateway(manager, [
        VPN_REQUEST, f"my employee ID is {ALICE_ID}", "push",
    ], call_id="call-18c")

    assert fake.run_payloads == []
    assert spoken[-1] == LOCKED_MESSAGE
    assert manager.get("call-18c").pending_request_forwarded is False
    # ...and a later turn does not smuggle it through either.
    fake2, _ = call_through_gateway(manager, ["are you still there"],
                                    call_id="call-18c-again")
    assert fake2.run_payloads == []


def test_18_d_duo_expiry_forwards_nothing(manager, provider):  # noqa: F811
    """A push that is never approved times out; nothing moves."""
    import time as _time

    provider.devices = PUSH_ONLY
    provider.push_results = ["waiting"]
    call_id = "call-18d"
    client, fake = gateway(manager)
    manager.start(call_id)
    token = mint_recovery_bootstrap(call_id, SECRET)

    with client:
        say(client, call_id, token, VPN_REQUEST)
        say(client, call_id, token, f"my employee ID is {ALICE_ID}")
        say(client, call_id, token, "push")
        # Force the absolute deadline into the past, as a real 90s wait would.
        manager.get(call_id).push_deadline = _time.time() - 1
        say(client, call_id, token, "still waiting")

    assert fake.run_payloads == []
    assert manager.get(call_id).verified_identity is None
    assert manager.get(call_id).pending_request_forwarded is False


def test_18_e_a_bad_identifier_forwards_nothing(manager):
    """No account was ever selected, so there is nothing to authenticate."""
    fake, _ = call_through_gateway(manager, [
        VPN_REQUEST, "my employee ID is 4040404", "my name is Alice", "hello?",
    ], call_id="call-18e")

    assert fake.run_payloads == []
    assert fake.created_state == {}


def test_18_f_graph_contradiction_forwards_nothing(enrolled, provider):  # noqa: F811
    """The map points at an object the directory does not have."""
    manager = duo_manager(enrolled, provider, Contradicting())

    fake, spoken = call_through_gateway(manager, [
        VPN_REQUEST, f"my employee ID is {ALICE_ID}", "passcode",
        "four eight two one six nine",
    ], call_id="call-18f")

    assert fake.run_payloads == []
    assert spoken[-1] == LOCKED_MESSAGE
    assert manager.get("call-18f").verified_identity is None


def test_18_g_an_unsupported_factor_forwards_nothing(manager, provider):  # noqa: F811
    """Enrolled, but no device can actually authenticate."""
    provider.devices = ()

    fake, spoken = call_through_gateway(manager, [
        VPN_REQUEST, f"my employee ID is {ALICE_ID}", "push", "passcode",
    ], call_id="call-18g")

    assert fake.run_payloads == []
    assert spoken[1] == PROVIDER_UNAVAILABLE
    assert manager.get("call-18g").state is DuoRecoveryState.FAILED_UNAVAILABLE


def test_18_h_an_expired_session_forwards_nothing(manager, provider):  # noqa: F811
    """A stalled call is closed, and closing it releases nothing."""
    from voice_gateway.duo_recovery import SESSION_TTL_SECONDS

    call_id = "call-18h"
    manager.start(call_id)
    manager.handle_turn(call_id, VPN_REQUEST)
    started = manager.get(call_id).created_at

    outcome = manager.handle_turn(call_id, f"employee id {ALICE_ID}",
                                  now=started + SESSION_TTL_SECONDS + 1)
    assert outcome.forward is False
    assert outcome.speak == LOCKED_MESSAGE
    assert manager.get(call_id).pending_request_forwarded is False


def test_18_i_stating_a_request_spends_no_attempt_budget(manager, provider):  # noqa: F811
    """Existing failure counters keep their meaning: a request is not an attempt."""
    call_id = "call-18i"
    manager.start(call_id)
    for utterance in ("hello", "are you there", VPN_REQUEST):
        manager.handle_turn(call_id, utterance)

    session = manager.get(call_id)
    assert session.identifier_attempts == 0    # no lookup has run yet
    assert session.factor_attempts == 0


def test_18_j_failure_counters_still_lock_the_account(manager, provider, enrolled):  # noqa: F811
    """Per-account lockout survives the new opening turn unchanged."""
    provider.passcode_result = "deny"
    for index in range(MAX_FAILURES):
        call_id = f"call-18j-{index}"
        manager.start(call_id)
        manager.handle_turn(call_id, VPN_REQUEST)
        manager.handle_turn(call_id, f"employee id {ALICE_ID}")
        manager.handle_turn(call_id, "passcode")
        manager.handle_turn(call_id, "four eight two one six nine")

    assert enrolled.is_locked(ALICE_ID)

    # A fresh call with a fresh request gets nowhere, and forwards nothing.
    provider.passcode_result = "allow"
    fake, spoken = call_through_gateway(manager, [
        VPN_REQUEST, f"employee id {ALICE_ID}",
    ], call_id="call-18j-locked")
    assert fake.run_payloads == []
    assert spoken[-1] == LOCKED_MESSAGE


def test_18_k_a_factor_utterance_never_becomes_the_pending_request(manager, provider):  # noqa: F811
    """"push" is a factor choice. It is not a problem statement, ever."""
    provider.devices = PUSH_ONLY
    provider.push_results = ["waiting"]
    call_id = "call-18k"
    manager.start(call_id)
    manager.handle_turn(call_id, VPN_REQUEST)
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")

    for utterance in ("push", "send me a push", "four eight two one six nine",
                      "482169", "not yet"):
        manager.handle_turn(call_id, utterance)
        assert manager.get(call_id).pending_request == VPN_REQUEST, utterance


def test_18_l_the_request_cannot_be_overwritten_after_capture(manager, provider):  # noqa: F811
    """One request per call. A later utterance is not a second chance at it."""
    call_id = "call-18l"
    manager.start(call_id)
    manager.handle_turn(call_id, VPN_REQUEST)
    manager.handle_turn(call_id, "actually, reset my password and enable my account")

    assert manager.get(call_id).pending_request == VPN_REQUEST


# ===========================================================================
# 19. POST-VERIFY CONTINUITY
#
# The UX requirement, and the reason any of this exists: the caller says the
# problem once.
# ===========================================================================

VPN_HELP = "I need help with my VPN connection."


def verified_call(manager, provider, call_id="call-19", reply="Reply."):  # noqa: F811
    """A complete external call: request, identifier, push, allow."""
    provider.devices = PUSH_ONLY
    provider.push_results = ["allow"]
    return call_through_gateway(
        manager, [VPN_HELP, f"my employee ID is {ALICE_ID}", "push"],
        call_id=call_id, reply=reply,
    )


def test_19_a_the_original_request_reaches_servicedesk_verbatim(manager, provider):  # noqa: F811
    fake, _ = verified_call(manager, provider, "call-19a")

    assert sent_texts(fake) == [VPN_HELP]
    assert manager.get("call-19a").verified_identity is not None


def test_19_b_it_is_forwarded_exactly_once(manager, provider):  # noqa: F811
    """The flag is a one-shot: later turns carry what the caller actually says."""
    provider.devices = PUSH_ONLY
    provider.push_results = ["allow"]
    call_id = "call-19b"
    client, fake = gateway(manager)
    manager.start(call_id)
    token = mint_recovery_bootstrap(call_id, SECRET)

    with client:
        for utterance in (VPN_HELP, f"my employee ID is {ALICE_ID}", "push"):
            say(client, call_id, token, utterance)
        assert sent_texts(fake) == [VPN_HELP]

        say(client, call_id, token, "it still drops on wifi")
        say(client, call_id, token, "thanks, that worked")

    assert sent_texts(fake) == [VPN_HELP, "it still drops on wifi",
                                "thanks, that worked"]
    assert sent_texts(fake).count(VPN_HELP) == 1
    assert manager.get(call_id).pending_request_forwarded is True


def test_19_c_a_verified_identity_accompanies_the_session(manager, provider):  # noqa: F811
    """The persona is seeded BEFORE the carried request is answered."""
    fake, _ = verified_call(manager, provider, "call-19c")

    persona = fake.created_state[auth_session_id("call-19c")]["persona"]
    assert persona["userPrincipalName"] == ALICE_UPN
    assert persona["id"] == ALICE_OID
    assert persona["identity_source"] == "duo_recovery"
    assert persona["recovery_scope"] == "self_account_recovery"
    assert persona["auth_method"] == "duo_push"
    # Nobody else's identity is anywhere near it.
    assert BOB_UPN not in json.dumps(fake.created_state)
    assert BOB_OID not in json.dumps(fake.created_state)


def test_19_d_the_servicedesk_answer_is_returned_to_dograh(manager, provider):  # noqa: F811
    """One spoken turn: verification confirmed, then the real answer."""
    fake, spoken = verified_call(manager, provider, "call-19d",
                                 reply="I've reset your VPN profile.")

    assert spoken[-1] == f"{VERIFIED_CONTINUING} I've reset your VPN profile."
    # The caller is NOT asked to repeat themselves.
    assert "how can i help" not in spoken[-1].lower()


def test_19_e_the_caller_never_repeats_the_problem(manager, provider):  # noqa: F811
    """The whole journey, read as the caller experiences it."""
    _, spoken = verified_call(manager, provider, "call-19e",
                              reply="Your VPN profile was reset.")

    assert spoken[0].startswith(VERIFY_FIRST_ACK)     # "verify you first"
    assert spoken[1] == FACTOR_PROMPT_PUSH_ONLY       # push only, no passcode
    assert spoken[2].endswith("Your VPN profile was reset.")


def test_19_f_the_request_cannot_be_replayed_on_a_later_turn(manager, provider):  # noqa: F811
    """Not by saying anything, and not by the machine repeating itself."""
    provider.devices = PUSH_ONLY
    provider.push_results = ["allow"]
    call_id = "call-19f"
    manager.start(call_id)
    manager.handle_turn(call_id, VPN_HELP)
    manager.handle_turn(call_id, f"my employee ID is {ALICE_ID}")
    first = manager.handle_turn(call_id, "push")

    assert first.forward_text == VPN_HELP
    for utterance in ("what did I ask for", "repeat that", VPN_HELP):
        later = manager.handle_turn(call_id, utterance)
        assert later.forward is True
        assert later.forward_text is None            # the caller's own words
        assert later.outbound_text(utterance) == utterance


def test_19_g_verification_without_a_carried_request_is_still_safe(manager, provider):  # noqa: F811
    """Defence in depth: the no-request branch behaves exactly as it did before.

    A real external caller cannot reach VERIFIED without stating something,
    because AWAITING_REQUEST is the only door into the machine. The state is
    forced here anyway, so `_verified` cannot come to depend on a pending
    request having been set — a future caller of it must not have to get that
    right for the call to end safely.
    """
    call_id = "call-19g"
    manager.start(call_id)
    manager.get(call_id).state = DuoRecoveryState.AWAITING_IDENTIFIER
    manager.handle_turn(call_id, f"my employee ID is {ALICE_ID}")
    manager.handle_turn(call_id, "passcode")
    outcome = manager.handle_turn(call_id, "four eight two one six nine")

    # The caller never stated a problem, so there is nothing to continue.
    assert outcome.speak == VERIFIED_MESSAGE
    assert outcome.forward is False
    assert outcome.forward_text is None
    assert manager.get(call_id).state is DuoRecoveryState.VERIFIED
    # ...and the NEXT turn is the first ServiceDesk one, as before.
    assert manager.handle_turn(call_id, "my VPN is down").forward is True


def test_19_h_a_carried_request_is_held_to_the_same_gateway_limits(enrolled, provider):  # noqa: F811
    """It is a caller utterance, so the utterance gates still apply to it."""
    manager = duo_manager(enrolled, provider, CorroboratingStub())
    provider.devices = PUSH_ONLY
    provider.push_results = ["allow"]
    call_id = "call-19h"

    settings = auth_settings(max_text_chars=20)
    fake = RecordingServiceDesk()
    sd = ServiceDeskClient(
        base_url=settings.servicedesk_base_url,
        app_name=settings.app_name, user_id=settings.user_id,
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
    )
    client = TestClient(create_app(settings=settings, client=sd, recovery=manager))
    manager.start(call_id)
    token = mint_recovery_bootstrap(call_id, SECRET)

    with client:
        say(client, call_id, token, VPN_HELP)          # longer than 20 chars
        say(client, call_id, token, f"my employee ID is {ALICE_ID}")
        response = say(client, call_id, token, "push")

    assert response.status_code == 400
    assert response.json()["code"] == "UTTERANCE_TOO_LONG"
    assert fake.run_payloads == []


# ===========================================================================
# 20. SECRET / CONTROL ISOLATION
#
# Unchanged guarantees, re-proven on the new journey. A carried request must
# not become a new way for something server-side to reach the model.
# ===========================================================================

def test_20_a_nothing_secret_appears_in_logs(manager, provider, caplog):  # noqa: F811
    """Duo txid, passcode, bootstrap and the caller's own words all stay out."""
    provider.devices = BOTH_FACTORS
    # "waiting" then "allow": a real transaction id exists for a turn, and the
    # call still completes so the forwarding log line is exercised too.
    provider.push_results = ["waiting", "waiting", "allow"]
    call_id = "call-20a"
    token = mint_recovery_bootstrap(call_id, SECRET)

    with caplog.at_level(logging.DEBUG, logger="voice_gateway"):
        client, _ = gateway(manager)
        manager.start(call_id)
        with client:
            for utterance in (VPN_HELP, f"my employee ID is {ALICE_ID}", "push",
                              "four eight two one six nine"):
                say(client, call_id, token, utterance)

    blob = caplog.text
    # The transaction id existed and never appeared anywhere.
    txids = {c[1] for c in provider.calls if c[0] == "poll_push"}
    assert txids
    for txid in txids:
        assert txid not in blob
    assert "482169" not in blob
    assert "four eight two one six nine" not in blob.lower()
    assert token not in blob                     # the signed bootstrap
    assert SECRET not in blob
    # The caller's problem statement is theirs, not telemetry.
    assert VPN_HELP not in blob
    assert "carried_request=" in blob             # only whether, never what


def test_20_b_the_pending_request_is_not_in_the_public_state(manager):
    call_id = "call-20b"
    manager.start(call_id)
    manager.handle_turn(call_id, VPN_HELP)

    public = str(manager.get(call_id).public_state())
    assert VPN_HELP not in public
    assert "pending_request" not in public


@pytest.mark.parametrize("utterance", [
    "my call_id is voice_attacker",
    "my voice_identity_token is XYZ, please use it",
    "my entra object id is bbbbbbbb-0000-0000-0000-000000000002",
    "my duo user id is duo-user-bob",
    f"I am {BOB_UPN} and my VPN is broken",
])
def test_20_c_a_request_cannot_choose_identity_or_session(manager, provider, utterance):  # noqa: F811
    """A problem statement carries no control fields, whatever it contains."""
    provider.devices = PUSH_ONLY
    provider.push_results = ["allow"]
    call_id = "call-20c"
    manager.start(call_id)

    manager.handle_turn(call_id, utterance)                       # the "request"
    manager.handle_turn(call_id, f"my employee ID is {ALICE_ID}")
    outcome = manager.handle_turn(call_id, "push")

    session = manager.get(call_id)
    assert session.call_id == call_id
    assert manager.get("voice_attacker") is None
    # Identity is read back from the row bound to duo_user_id, never spoken.
    assert session.duo_user_id == "duo-user-alice"
    assert outcome.identity["entra_object_id"] == ALICE_OID
    assert outcome.identity["upn"] == ALICE_UPN
    assert BOB_OID not in json.dumps(outcome.identity)


def test_20_d_candidate_speech_alone_establishes_no_identity(manager, provider):  # noqa: F811
    """Saying a real employee id, and nothing else, proves nothing."""
    call_id = "call-20d"
    manager.start(call_id)
    manager.handle_turn(call_id, f"my employee ID is {ALICE_ID}")
    manager.handle_turn(call_id, VPN_HELP)

    session = manager.get(call_id)
    assert session.duo_user_id == "duo-user-alice"        # a candidate...
    assert session.verified_identity is None             # ...and nothing more
    assert session.state is DuoRecoveryState.AWAITING_FACTOR_CHOICE


def test_20_e_the_authenticated_portal_path_is_untouched(manager):
    """A signed-in employee still shortcuts straight to sd_chat, as entra_portal_voice."""
    call_id = "voice-portal-1"
    client, fake = gateway(manager, reply="Opening a ticket for you.")
    token = mint(ALICE_UPN, call_id, SECRET, display_name="Alice Test",
                 object_id=ALICE_OID)

    with client:
        response = say(client, call_id, token, "I need help with a printer")

    assert response.status_code == 200
    # No Duo conversation: the first utterance IS the ServiceDesk turn.
    assert sent_texts(fake) == ["I need help with a printer"]
    assert response.json()["text"] == "Opening a ticket for you."

    persona = fake.created_state[auth_session_id(call_id)]["persona"]
    assert persona["identity_source"] == "entra_portal_voice"
    assert "recovery_scope" not in persona
    assert manager.get(call_id) is None          # never entered the state machine


# ===========================================================================
# the conversational guard itself
#
# Deterministic, and small on purpose. It is not an intent classifier: it
# separates "words about a problem" from "a greeting" and "bare identifier
# material", and nothing else decides anything.
# ===========================================================================

@pytest.mark.parametrize("utterance", [
    "hello", "hi", "hey", "Good morning", "Good afternoon",
    "can you hear me", "Hello? Is anybody there?", "yes", "okay", "thanks",
])
def test_guard_recognises_small_talk(utterance):
    opening = classify_opening(utterance)
    assert opening.small_talk is True
    assert opening.request is None
    assert opening.identifier is None


@pytest.mark.parametrize("utterance", [
    "My VPN keeps disconnecting.",
    "I can't print.",
    "my password expired",
    "the finance printer is jammed",
    "I need help with a software install",
    "hello, my laptop won't boot",           # a greeting AND a problem
])
def test_guard_recognises_a_request(utterance):
    opening = classify_opening(utterance)
    assert opening.request == utterance
    assert opening.small_talk is False


@pytest.mark.parametrize("utterance,kind", [
    ("my employee ID is 1798283", IdentifierKind.EMPLOYEE_ID),
    ("employee id one seven nine eight two eight three", IdentifierKind.EMPLOYEE_ID),
    ("1798283", IdentifierKind.UNSPECIFIED_DIGITS),
    (f"my work email is {ALICE_UPN}", IdentifierKind.UPN),
    ("my work email is alice dot test at example dot invalid", IdentifierKind.UPN),
    ("my mobile number is 415 555 0123", IdentifierKind.MOBILE),
])
def test_guard_treats_bare_identifier_material_as_no_request(utterance, kind):
    opening = classify_opening(utterance, default_calling_code="1")
    assert opening.request is None, opening
    assert opening.identifier is not None
    assert opening.identifier.kind is kind


def test_guard_keeps_both_when_both_are_present():
    utterance = f"my VPN is down, employee id {ALICE_ID}"
    opening = classify_opening(utterance)
    assert opening.request == utterance
    assert opening.identifier.value == ALICE_ID


@pytest.mark.parametrize("utterance", ["", "   ", None, 12345])
def test_guard_never_raises_on_junk(utterance):
    opening = classify_opening(utterance)
    assert opening.request is None
    assert opening.identifier is None


def test_guard_never_logs_or_returns_the_caller_words():
    """`redacted()` is what goes to the log, and it is shape only."""
    opening = classify_opening("my VPN keeps disconnecting")
    assert "vpn" not in opening.redacted().lower()
    assert opening.redacted() == "request=yes identifier=none small_talk=False"
