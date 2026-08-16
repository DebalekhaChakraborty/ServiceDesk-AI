"""Duo recovery: the properties that make a spoken identifier safe to act on.

The theme running through every test here is that speech selects a CANDIDATE
and Duo decides identity. A caller can be misheard, can lie, or can be an
attacker reading a colleague's employee id off a badge photo; none of that
changes who Duo authenticates.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import stat
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from voice_gateway.app import create_app
from voice_gateway.duo_provider import DuoConfig, DuoRecoveryProvider, canonicalize
from voice_gateway.duo_recovery import (
    DuoRecoveryManager,
    DuoRecoveryState,
    FACTOR_PROMPT,
    FACTOR_PROMPT_PASSCODE_ONLY,
    GENERIC_AUTH_FAILURE,
    GENERIC_LOOKUP_FAILURE,
    IDENTIFIER_RETRY,
    LOCKED_MESSAGE,
    PUSH_SENT_MESSAGE,
    PUSH_WAITING_MESSAGE,
    VERIFIED_MESSAGE,
    duo_persona,
)
from voice_gateway.graph_corroboration import (
    CorroborationResult,
    GraphCorroborator,
    NullGraphCorroborator,
)
from voice_gateway.identifiers import (
    IdentifierError,
    IdentifierKind,
    extract_identifier,
    normalize_mobile,
    parse_factor_choice,
)
from voice_gateway.identity import mint, mint_recovery_bootstrap
from voice_gateway.identity_map import (
    AmbiguousIdentifier,
    EmployeeIdentityMap,
    MAX_FAILURES,
    STATUS_ACTIVE,
    STATUS_PENDING,
)
from voice_gateway.mfa_provider import (
    CAP_MOBILE_OTP,
    CAP_PUSH,
    Device,
    MfaProviderError,
    PREAUTH_ALLOW,
    PREAUTH_DENY,
    PREAUTH_ENROLL,
)
from voice_gateway.recovery import RecoveryManager
from voice_gateway.servicedesk_client import ServiceDeskClient
from voice_gateway.session import auth_session_id

from fake_mfa import FakeMfaProvider
from test_authenticated_identity import RecordingServiceDesk, SECRET, auth_settings

TENANT = "11111111-2222-3333-4444-555555555555"
ALICE_OID = "aaaaaaaa-0000-0000-0000-000000000001"
BOB_OID = "bbbbbbbb-0000-0000-0000-000000000002"
ALICE_UPN = "alice.test@example.invalid"
BOB_UPN = "bob.test@example.invalid"
ALICE_ID = "1798283"
BOB_ID = "2244668"
ALICE_MOBILE = "+14155550123"


@pytest.fixture(autouse=True)
def _signing_secret(monkeypatch):
    monkeypatch.setenv("VOICE_IDENTITY_SIGNING_SECRET", SECRET)


@pytest.fixture
def identity_map(tmp_path):
    return EmployeeIdentityMap(path=tmp_path / "recovery_identity.db",
                               default_calling_code="1")


@pytest.fixture
def provider():
    return FakeMfaProvider()


@pytest.fixture
def enrolled(identity_map):
    """Alice, fully enrolled and recovery-ready. Bob exists but is not."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN,
                                 mobile=ALICE_MOBILE, display_name="Alice Test")
    identity_map.bind_duo_user(ALICE_ID, "duo-user-alice", None, "act-alice")
    identity_map.activate_duo(ALICE_ID)
    identity_map.upsert_employee(BOB_ID, TENANT, BOB_OID, BOB_UPN,
                                 display_name="Bob Test")
    return identity_map


@pytest.fixture
def manager(enrolled, provider):
    # sleep is stubbed out so bounded polling does not make tests slow.
    return DuoRecoveryManager(enrolled, provider, NullGraphCorroborator(),
                              sleep=lambda _: None)


@pytest.fixture
def duo_client(monkeypatch):
    """Factory for a TestClient whose enrollment admin key is a known value.

    Patched through monkeypatch so the real derived key is restored even if a
    test fails part-way.
    """
    from voice_gateway import app as app_module

    monkeypatch.setattr(app_module, "enrollment_admin_key", lambda: _ADMIN_KEY)

    def build(identity_map, provider, corroborator=None):
        manager = DuoRecoveryManager(identity_map, provider,
                                     corroborator or NullGraphCorroborator(),
                                     sleep=lambda _: None)
        client, _ = gateway_client(manager)
        return client, manager

    return build


def gateway_client(manager, fake=None):
    """TestClient over a mocked ServiceDesk, with `manager` as the recovery path."""
    fake = fake or RecordingServiceDesk()
    settings = auth_settings()
    sd = ServiceDeskClient(
        base_url=settings.servicedesk_base_url,
        app_name=settings.app_name, user_id=settings.user_id,
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
    )
    return TestClient(create_app(settings=settings, client=sd, recovery=manager)), fake


def start_call(manager, call_id="call-1"):
    manager.start(call_id)
    return call_id


def verify_by_passcode(manager, call_id="call-1"):
    """Drive a fresh call all the way to VERIFIED using a spoken passcode."""
    manager.start(call_id)
    manager.handle_turn(call_id, f"my employee ID is {ALICE_ID}")
    manager.handle_turn(call_id, "passcode")
    return manager.handle_turn(call_id, "four eight two one six nine")


# ---------------------------------------------------------------------------
# 1-8: identifier resolution
# ---------------------------------------------------------------------------

def test_1_spoken_name_is_never_an_identifier(manager, provider):
    """A name selects nobody, and never reaches a lookup."""
    call_id = start_call(manager)
    for utterance in ("My name is Alice Test",
                      "This is Alice speaking",
                      "I am Bob from finance"):
        outcome = manager.handle_turn(call_id, utterance)
        assert outcome.speak == IDENTIFIER_RETRY
        assert not outcome.forward

    # Nothing was asked of Duo, because no candidate was ever selected.
    assert provider.called("preauth") == []
    assert manager.get(call_id).state is DuoRecoveryState.AWAITING_IDENTIFIER


def test_1b_name_lookup_rejected_at_the_extractor(identity_map):
    with pytest.raises(IdentifierError) as exc:
        extract_identifier("my name is alice test")
    assert exc.value.category == "name_not_accepted"


def test_2_exact_employee_id_lookup(manager, provider):
    call_id = start_call(manager)
    outcome = manager.handle_turn(call_id, f"My employee ID is {ALICE_ID}")
    assert outcome.speak == FACTOR_PROMPT
    assert provider.called("preauth") == [("preauth", "duo-user-alice")]


def test_2b_near_miss_employee_id_does_not_match(manager, provider):
    """One wrong digit is a miss, not a nearest match."""
    call_id = start_call(manager)
    outcome = manager.handle_turn(call_id, "My employee ID is 1798284")
    assert outcome.speak == GENERIC_LOOKUP_FAILURE
    assert provider.called("preauth") == []


def test_3_employee_id_speech_normalisation(manager):
    """Spelled-out digits, spacing and punctuation all reach the same key."""
    spoken = [
        "employee id one seven nine eight two eight three",
        "my employee ID is 1 7 9 8 2 8 3",
        "employee number 179-8283",
        f"badge {ALICE_ID}",
    ]
    for index, utterance in enumerate(spoken):
        call_id = start_call(manager, f"call-norm-{index}")
        assert manager.handle_turn(call_id, utterance).speak == FACTOR_PROMPT


def test_4_exact_normalised_upn_lookup(manager):
    for index, utterance in enumerate([
        f"my work email is {ALICE_UPN}",
        f"my work email is {ALICE_UPN.upper()}",
        "my work email is alice dot test at example dot invalid",
    ]):
        call_id = start_call(manager, f"call-upn-{index}")
        assert manager.handle_turn(call_id, utterance).speak == FACTOR_PROMPT


def test_5_exact_e164_mobile_lookup(manager):
    for index, utterance in enumerate([
        "my registered mobile is plus one four one five five five five zero one two three",
        "my mobile number is 415 555 0123",
    ]):
        call_id = start_call(manager, f"call-mob-{index}")
        assert manager.handle_turn(call_id, utterance).speak == FACTOR_PROMPT


def test_5b_mobile_normalisation_refuses_to_guess_a_country(identity_map):
    assert normalize_mobile("+1 415 555 0123") == "+14155550123"
    assert normalize_mobile("415 555 0123", default_calling_code="1") == "+14155550123"
    with pytest.raises(IdentifierError) as exc:
        normalize_mobile("415 555 0123")
    assert exc.value.category == "mobile_requires_country_code"


def test_6_ambiguous_lookup_fails_closed(identity_map, provider):
    """A digit run matching two different people authenticates neither.

    Carol's employee id happens to be Dave's mobile number without its country
    code. Real directories do produce collisions like this, and resolving one by
    preference would hand an attacker a way to aim at whichever record wins.
    """
    identity_map.upsert_employee("9998887", TENANT, "cccccccc-0000-0000-0000-000000000003",
                                 "carol@example.invalid", mobile="+15550123999")
    identity_map.upsert_employee("4040404", TENANT, "dddddddd-0000-0000-0000-000000000004",
                                 "dave@example.invalid", mobile="+19998887")

    with pytest.raises(AmbiguousIdentifier):
        identity_map.lookup(extract_identifier("9998887"))

    manager = DuoRecoveryManager(identity_map, provider, NullGraphCorroborator(),
                                 sleep=lambda _: None)
    call_id = start_call(manager, "call-ambiguous")
    outcome = manager.handle_turn(call_id, "9998887")
    assert outcome.speak == GENERIC_LOOKUP_FAILURE
    assert provider.called("preauth") == []


def test_7_unknown_identifier_gets_the_generic_response(manager, provider):
    call_id = start_call(manager)
    outcome = manager.handle_turn(call_id, "my employee ID is 4040404")
    assert outcome.speak == GENERIC_LOOKUP_FAILURE
    assert provider.called("preauth") == []


def test_8_disabled_recovery_is_indistinguishable_from_unknown(manager, enrolled, provider):
    """Bob exists, is not enrolled, and produces the identical sentence."""
    unknown = manager.handle_turn(start_call(manager, "c-unknown"),
                                  "my employee ID is 4040404")
    not_enrolled = manager.handle_turn(start_call(manager, "c-bob"),
                                       f"my employee ID is {BOB_ID}")

    enrolled.set_recovery_enabled(ALICE_ID, False)
    switched_off = manager.handle_turn(start_call(manager, "c-alice-off"),
                                       f"my employee ID is {ALICE_ID}")

    assert unknown.speak == not_enrolled.speak == switched_off.speak == GENERIC_LOOKUP_FAILURE
    assert provider.called("preauth") == []


# ---------------------------------------------------------------------------
# 9-10: canonical Duo binding
# ---------------------------------------------------------------------------

def test_9_duo_user_id_is_the_canonical_binding(manager, enrolled):
    """Identity after allow is read back through duo_user_id and nothing else."""
    outcome = verify_by_passcode(manager)
    assert outcome.identity["duo_user_id"] == "duo-user-alice"
    assert outcome.identity["entra_object_id"] == ALICE_OID
    assert enrolled.by_duo_user_id("duo-user-alice").employee_id == ALICE_ID


def test_10_upn_change_cannot_move_the_duo_identity(manager, enrolled):
    """Renaming the alias leaves the Duo binding, and the oid, untouched."""
    enrolled.upsert_employee(ALICE_ID, TENANT, ALICE_OID, "alice.married@example.invalid",
                             mobile=ALICE_MOBILE, display_name="Alice Test")
    record = enrolled.get(ALICE_ID)
    assert record.duo_user_id == "duo-user-alice"
    assert record.entra_object_id == ALICE_OID

    # The old address now selects nobody; the Duo binding did not follow it.
    call_id = start_call(manager, "call-old-upn")
    assert manager.handle_turn(call_id, f"my work email is {ALICE_UPN}").speak \
        == GENERIC_LOOKUP_FAILURE
    assert enrolled.by_duo_user_id("duo-user-alice").employee_id == ALICE_ID


def test_10b_a_spoken_identifier_cannot_retarget_a_verified_identity(manager):
    """Saying somebody else's name or id after verifying changes nothing."""
    verify_by_passcode(manager)
    manager.handle_turn("call-1", "actually I am Bob")           # first forwarded turn
    session = manager.get("call-1")
    assert session.verified_identity["upn"] == ALICE_UPN
    assert session.verified_identity["entra_object_id"] == ALICE_OID


# ---------------------------------------------------------------------------
# 11-14: provider health and enrollment
# ---------------------------------------------------------------------------

def test_11_check_failure_disables_recovery(monkeypatch, tmp_path):
    """A Duo integration that cannot authenticate leaves recovery OFF."""
    from voice_gateway import app as app_module

    monkeypatch.setenv("DUO_IKEY", "DIXXXXXXXXXXXXXXXXXX")
    monkeypatch.setenv("DUO_SKEY", "x" * 40)
    monkeypatch.setenv("DUO_HOST", "api-abcd1234.duosecurity.com")
    monkeypatch.setenv("RECOVERY_IDENTITY_DB", str(tmp_path / "map.db"))

    class Failing(DuoRecoveryProvider):
        def check(self):
            from voice_gateway.mfa_provider import ProviderCheck
            return ProviderCheck(ok=False, reason="DUO_API_ERROR")

    monkeypatch.setattr(app_module, "DuoRecoveryProvider", Failing)
    settings = auth_settings()
    assert app_module._build_recovery(settings) is None


def test_11b_unconfigured_duo_disables_recovery(monkeypatch, tmp_path):
    from voice_gateway import app as app_module
    for name in ("DUO_IKEY", "DUO_SKEY", "DUO_HOST"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("voice_gateway.duo_provider.RUNTIME", tmp_path)
    assert app_module._build_recovery(auth_settings()) is None


def test_12_enroll_creates_a_pending_binding_only(identity_map, provider, duo_client):
    """A Duo user id exists, and the employee still cannot recover."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)

    response = client.post("/recovery/enroll/duo/begin",
                           json=enroll_body(), headers=admin_header())
    assert response.status_code == 200
    assert response.json()["status"] == "pending"

    record = identity_map.get(ALICE_ID)
    assert record.duo_user_id == "duo-user-fake-1"
    assert record.duo_enrollment_status == STATUS_PENDING
    assert record.recovery_enabled == 0
    assert not record.recovery_ready()


def test_13_enroll_status_success_activates(identity_map, provider, duo_client):
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)
    client.post("/recovery/enroll/duo/begin", json=enroll_body(), headers=admin_header())

    provider.enroll_status_state = "success"
    response = client.post("/recovery/enroll/duo/status",
                           json=enroll_body(), headers=admin_header())
    assert response.status_code == 200
    assert response.json()["status"] == "active"

    record = identity_map.get(ALICE_ID)
    assert record.duo_enrollment_status == STATUS_ACTIVE
    assert record.recovery_enabled == 1
    assert record.recovery_ready()
    # Duo was asked about the BOUND user and the stored activation code.
    assert provider.called("enroll_status") == [
        ("enroll_status", "duo-user-fake-1", "activation-code-1")
    ]


def test_14_rendering_a_qr_does_not_activate_anything(identity_map, provider, duo_client):
    """The QR is proof of nothing until Duo says the app was activated."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)

    begin = client.post("/recovery/enroll/duo/begin",
                        json=enroll_body(), headers=admin_header())
    assert begin.json()["qr_data_uri"].startswith("data:image/png;base64,")

    provider.enroll_status_state = "waiting"
    status = client.post("/recovery/enroll/duo/status",
                         json=enroll_body(), headers=admin_header())
    assert status.json()["status"] == "waiting"
    assert identity_map.get(ALICE_ID).recovery_enabled == 0

    # And a recovery call for that employee still gets the generic sentence.
    manager = DuoRecoveryManager(identity_map, provider, NullGraphCorroborator(),
                                 sleep=lambda _: None)
    call_id = start_call(manager, "call-pending")
    assert manager.handle_turn(call_id, f"employee id {ALICE_ID}").speak \
        == GENERIC_LOOKUP_FAILURE


def test_14b_enrollment_requires_the_admin_key(identity_map, provider, duo_client):
    """The gateway is on the bridge Dograh shares; enrollment is not open there."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)
    for path in ("/recovery/enroll/duo/begin", "/recovery/enroll/duo/status"):
        assert client.post(path, json=enroll_body()).status_code == 403
    assert provider.called("enroll") == []


def test_14c_enrollment_identity_must_match_the_map_row(identity_map, provider, duo_client):
    """A form-supplied identity cannot enroll Duo against somebody else."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)

    mismatched = dict(enroll_body(), upn=BOB_UPN)
    assert client.post("/recovery/enroll/duo/begin", json=mismatched,
                       headers=admin_header()).status_code == 404

    wrong_tenant = dict(enroll_body(), tenant_id="99999999-0000-0000-0000-000000000000")
    assert client.post("/recovery/enroll/duo/begin", json=wrong_tenant,
                       headers=admin_header()).status_code == 404
    assert provider.called("enroll") == []


# ---------------------------------------------------------------------------
# 15-21: preauth and push
# ---------------------------------------------------------------------------

def test_15_preauth_is_called_for_the_mapped_duo_user_only(manager, provider):
    call_id = start_call(manager)
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    assert provider.called("preauth") == [("preauth", "duo-user-alice")]


@pytest.mark.parametrize("result", [PREAUTH_DENY, PREAUTH_ENROLL, PREAUTH_ALLOW])
def test_15b_non_auth_preauth_results_never_authenticate(manager, provider, result):
    """Including "allow": a Duo policy bypass is not account-recovery proof."""
    provider.preauth_result = result
    call_id = start_call(manager, f"call-{result}")
    outcome = manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    assert outcome.speak == GENERIC_LOOKUP_FAILURE
    assert not outcome.forward
    assert manager.get(call_id).verified_identity is None


def test_16_no_push_device_offers_the_passcode(manager, provider):
    provider.devices = (Device(device_id="DEV2", display_name="Tablet",
                               capabilities=frozenset({CAP_MOBILE_OTP})),)
    call_id = start_call(manager, "call-nopush")
    outcome = manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    assert outcome.speak == FACTOR_PROMPT_PASSCODE_ONLY
    assert manager.get(call_id).state is DuoRecoveryState.AWAITING_PASSCODE
    assert provider.called("start_push") == []


def test_16b_capabilities_come_from_preauth_not_the_local_map(manager, provider, enrolled):
    """A stale local mobile number does not decide what factors exist."""
    assert enrolled.get(ALICE_ID).mobile_e164 == ALICE_MOBILE
    provider.devices = ()
    call_id = start_call(manager, "call-nodevices")
    outcome = manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    assert outcome.speak == FACTOR_PROMPT_PASSCODE_ONLY
    assert manager.get(call_id).push_device_id is None


def test_17_txid_is_retained_server_side_only(manager, provider):
    """The transaction id never appears in anything the caller or LLM sees."""
    provider.push_results = ["waiting"]
    call_id = start_call(manager, "call-push")
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    outcome = manager.handle_turn(call_id, "send a push")

    session = manager.get(call_id)
    assert session.txid and session.txid.startswith("txid-secret-")
    assert session.txid not in (outcome.speak or "")
    assert "txid" not in (outcome.speak or "").lower()
    assert session.txid not in str(session.public_state())


def test_18_push_waiting_keeps_the_call_open(manager, provider):
    provider.push_results = ["waiting"]
    call_id = start_call(manager, "call-wait")
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")

    first = manager.handle_turn(call_id, "push")
    assert first.speak == PUSH_SENT_MESSAGE
    assert not first.forward

    second = manager.handle_turn(call_id, "not yet")
    assert second.speak == PUSH_WAITING_MESSAGE
    assert manager.get(call_id).state is DuoRecoveryState.PUSH_PENDING
    assert manager.get(call_id).verified_identity is None


def test_19_push_denied_fails_the_call(manager, provider):
    """The person holding the enrolled phone said no. That is final."""
    provider.push_results = ["deny"]
    call_id = start_call(manager, "call-deny")
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    outcome = manager.handle_turn(call_id, "push")

    assert outcome.speak == LOCKED_MESSAGE
    assert not outcome.forward
    session = manager.get(call_id)
    assert session.state is DuoRecoveryState.FAILED_LOCKED
    assert session.verified_identity is None
    assert session.txid is None


def test_20_push_timeout_is_bounded_and_generic(manager, provider):
    """Polling stops. It does not loop, and it does not authenticate."""
    provider.push_results = ["waiting"]
    call_id = start_call(manager, "call-timeout")
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    manager.handle_turn(call_id, "push")

    # Force the absolute deadline into the past, as a real 90s wait would.
    manager.get(call_id).push_deadline = time.time() - 1
    outcome = manager.handle_turn(call_id, "still waiting")

    assert not outcome.forward
    assert manager.get(call_id).verified_identity is None
    assert manager.get(call_id).state in (
        DuoRecoveryState.AWAITING_FACTOR_CHOICE, DuoRecoveryState.FAILED_LOCKED
    )
    # Bounded: a finite number of polls, not an open loop.
    assert 0 < len(provider.called("poll_push")) <= 40


def test_21_push_allow_verifies(manager, provider):
    provider.push_results = ["allow"]
    call_id = start_call(manager, "call-allow")
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    outcome = manager.handle_turn(call_id, "send me a push")

    assert outcome.speak == VERIFIED_MESSAGE
    assert outcome.identity["auth_method"] == "duo_push"
    assert outcome.identity["upn"] == ALICE_UPN
    assert manager.get(call_id).state is DuoRecoveryState.VERIFIED


# ---------------------------------------------------------------------------
# 22-26: spoken passcode, and what must never leak
# ---------------------------------------------------------------------------

def test_22_spoken_passcode_allow_verifies(manager, provider):
    outcome = verify_by_passcode(manager)
    assert outcome.speak == VERIFIED_MESSAGE
    assert outcome.identity["auth_method"] == "duo_passcode"
    # The deterministic parser handed Duo six digits, not the utterance.
    assert provider.called("verify_passcode") == [
        ("verify_passcode", "duo-user-alice", "482169")
    ]


def test_23_spoken_passcode_deny_does_not_verify(manager, provider):
    provider.passcode_result = "deny"
    outcome = verify_by_passcode(manager)
    assert outcome.speak == GENERIC_AUTH_FAILURE
    assert not outcome.forward
    assert manager.get("call-1").verified_identity is None


def test_23b_unparseable_speech_is_not_an_authentication_attempt(manager, provider):
    """Transcription noise must not spend a legitimate caller's budget."""
    call_id = start_call(manager)
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    manager.handle_turn(call_id, "passcode")
    for _ in range(4):
        manager.handle_turn(call_id, "sorry, could you repeat the question")
    assert provider.called("verify_passcode") == []
    assert manager.get(call_id).factor_attempts == 0
    assert manager.get(call_id).state is DuoRecoveryState.AWAITING_PASSCODE


def test_23c_repeated_denials_lock_the_account_not_just_the_call(manager, provider, enrolled):
    """Hanging up and redialling inherits the failure count."""
    provider.passcode_result = "deny"
    for index in range(MAX_FAILURES):
        call_id = start_call(manager, f"call-brute-{index}")
        manager.handle_turn(call_id, f"employee id {ALICE_ID}")
        manager.handle_turn(call_id, "passcode")
        manager.handle_turn(call_id, "four eight two one six nine")

    assert enrolled.is_locked(ALICE_ID)
    # A fresh call gets nowhere, and a now-valid passcode does not unlock it.
    provider.passcode_result = "allow"
    fresh = start_call(manager, "call-after-lock")
    outcome = manager.handle_turn(fresh, f"employee id {ALICE_ID}")
    assert outcome.speak == LOCKED_MESSAGE
    assert manager.get(fresh).verified_identity is None


def test_24_passcode_never_reaches_servicedesk(manager, provider):
    """The verification turn is consumed by the state machine, not forwarded."""
    call_id = "call-sd-1"
    manager.start(call_id)
    client, fake = gateway_client(manager)
    token = mint_recovery_bootstrap(call_id, SECRET)

    with client:
        for utterance in (f"my employee ID is {ALICE_ID}",
                          "passcode",
                          "four eight two one six nine"):
            response = client.post("/voice/turn", json={
                "call_id": call_id, "voice_identity_token": token, "text": utterance,
            })
            assert response.status_code == 200

        # Not one byte has reached ServiceDesk: no session, no turn.
        assert fake.run_payloads == []
        assert fake.created_state == {}

        client.post("/voice/turn", json={
            "call_id": call_id, "voice_identity_token": token,
            "text": "I cannot sign in to my account",
        })

    assert len(fake.run_payloads) == 1
    sent = json.dumps(fake.run_payloads) + json.dumps(fake.created_state)
    assert "482169" not in sent
    assert "four eight two one six nine" not in sent.lower()
    assert "duo-user-alice" not in sent          # the Duo binding stays internal

    persona = fake.created_state[auth_session_id(call_id)]["persona"]
    assert persona["identity_source"] == "duo_recovery"
    assert persona["recovery_scope"] == "self_account_recovery"
    assert persona["userPrincipalName"] == ALICE_UPN


def test_25_duo_secret_never_appears_in_logs_or_reprs(caplog, tmp_path):
    """The skey is unrenderable: not in repr, not in a config dump, not in logs."""
    skey = "s3cr3t-duo-skey-value-do-not-print-0123456789"
    config = DuoConfig(ikey="DIABCDEFGHIJKLMNOPQR", skey=skey,
                       host="api-abcd1234.duosecurity.com")

    assert skey not in repr(config)
    assert skey not in str(config)
    assert skey not in str(config.redacted())
    assert config.redacted()["duo_skey"] == "<redacted>"

    provider = DuoRecoveryProvider(config)
    assert skey not in repr(provider)

    with caplog.at_level(logging.DEBUG, logger="voice_gateway"):
        logging.getLogger("voice_gateway").info("duo config=%s", config.redacted())
    assert skey not in caplog.text


def test_25b_signature_matches_duo_canonicalisation():
    """Signing input is the documented canonical form, byte for byte."""
    canonical = canonicalize(
        "POST", "api-XXXXXXXX.duosecurity.com", "/auth/v2/preauth",
        {"user_id": "DU123", "factor": "push"},
        "Tue, 21 Aug 2012 17:29:18 -0000",
    )
    assert canonical.split("\n") == [
        "Tue, 21 Aug 2012 17:29:18 -0000",
        "POST",
        "api-xxxxxxxx.duosecurity.com",
        "/auth/v2/preauth",
        "factor=push&user_id=DU123",          # sorted by key
    ]


def test_25c_duo_host_cannot_be_arbitrary():
    """No caller- or model-supplied hostname signs a request with our ikey."""
    for host in ("evil.example.com", "api-abcd1234.duosecurity.com.evil.net",
                 "http://api-abcd1234.duosecurity.com", ""):
        with pytest.raises(MfaProviderError):
            DuoConfig(ikey="DIABCDEFGHIJKLMNOPQR", skey="x" * 40, host=host)


def test_26_txid_and_passcode_absent_from_everything_the_llm_sees(manager, provider, caplog):
    provider.push_results = ["waiting"]
    call_id = start_call(manager, "call-leak")
    with caplog.at_level(logging.DEBUG, logger="voice_gateway"):
        manager.handle_turn(call_id, f"employee id {ALICE_ID}")
        manager.handle_turn(call_id, "push")
        manager.handle_turn(call_id, "four eight two one six nine")

    txid = manager.get(call_id).txid
    assert txid
    assert txid not in caplog.text
    assert "482169" not in caplog.text
    assert "four eight two one six nine" not in caplog.text.lower()


# ---------------------------------------------------------------------------
# 27-32: storage, isolation, scope
# ---------------------------------------------------------------------------

def test_27_identity_map_is_owner_only_and_gitignored(tmp_path):
    path = tmp_path / "recovery_identity.db"
    EmployeeIdentityMap(path=path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    repo = Path(__file__).resolve().parents[3]
    checked = subprocess.run(
        ["git", "check-ignore", "-q",
         "dograh_voice/runtime/recovery_identity.db"],
        cwd=repo, capture_output=True,
    )
    assert checked.returncode == 0, "recovery_identity.db must be git-ignored"


def test_27b_schema_is_versioned_and_deterministic(tmp_path):
    path = tmp_path / "map.db"
    first = EmployeeIdentityMap(path=path)
    assert first.schema_version() == 1
    # Re-opening is idempotent and does not duplicate the version row.
    second = EmployeeIdentityMap(path=path)
    assert second.schema_version() == 1

    with sqlite3.connect(path) as conn:
        rows = conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()
        assert rows[0] == 1


def test_27c_unique_constraints_hold(identity_map):
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    with pytest.raises(sqlite3.IntegrityError):
        # A second employee claiming Alice's object id must not be storable.
        identity_map.upsert_employee("9999999", TENANT, ALICE_OID, "other@example.invalid")


def test_28_concurrent_callers_are_isolated(manager, provider, enrolled):
    """Two calls in flight never share identity or state."""
    enrolled.bind_duo_user(BOB_ID, "duo-user-bob", None, "act-bob")
    enrolled.activate_duo(BOB_ID)

    a, b = start_call(manager, "call-a"), start_call(manager, "call-b")
    manager.handle_turn(a, f"employee id {ALICE_ID}")
    manager.handle_turn(b, f"employee id {BOB_ID}")

    assert manager.get(a).duo_user_id == "duo-user-alice"
    assert manager.get(b).duo_user_id == "duo-user-bob"

    manager.handle_turn(a, "passcode")
    manager.handle_turn(a, "four eight two one six nine")

    assert manager.get(a).verified_identity["upn"] == ALICE_UPN
    assert manager.get(b).verified_identity is None      # b proved nothing
    assert manager.get(b).state is DuoRecoveryState.AWAITING_FACTOR_CHOICE


def test_29_normal_entra_voice_flow_is_unchanged(manager):
    """A non-recovery authenticated call still reports entra_portal_voice."""
    call_id = "voice-normal-1"
    client, fake = gateway_client(manager)
    token = mint(ALICE_UPN, call_id, SECRET, display_name="Alice Test",
                 object_id=ALICE_OID)

    with client:
        response = client.post("/voice/turn", json={
            "call_id": call_id, "voice_identity_token": token,
            "text": "I need help with a printer",
        })
    assert response.status_code == 200

    persona = fake.created_state[auth_session_id(call_id)]["persona"]
    assert persona["identity_source"] == "entra_portal_voice"
    assert "recovery_scope" not in persona
    assert "auth_method" not in persona
    assert len(fake.run_payloads) == 1


def test_30_totp_provider_is_not_active_by_default(monkeypatch, tmp_path):
    """The retired verifier is only reachable by asking for it by name."""
    from voice_gateway import app as app_module
    from voice_gateway.config import load_settings

    monkeypatch.delenv("RECOVERY_PROVIDER", raising=False)
    assert load_settings().recovery_provider == "duo"

    # With Duo unconfigured, nothing falls back to TOTP.
    for name in ("DUO_IKEY", "DUO_SKEY", "DUO_HOST"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("voice_gateway.duo_provider.RUNTIME", tmp_path)
    assert app_module._build_recovery(load_settings()) is None

    monkeypatch.setenv("RECOVERY_PROVIDER", "totp")
    monkeypatch.setenv("RECOVERY_STORE_PATH", str(tmp_path / "store.json"))
    monkeypatch.setenv("RECOVERY_STORE_KEY",
                       "3q2sB1lNiVQxAJnO2tGnyE5t9y0wYUJcM3TPQq3hOCA=")
    assert isinstance(app_module._build_recovery(load_settings()), RecoveryManager)


def test_31_recovery_identity_is_scoped_to_the_caller_only(manager):
    outcome = verify_by_passcode(manager)
    persona = duo_persona(outcome.identity)
    assert persona["identity_source"] == "duo_recovery"
    assert persona["recovery_scope"] == "self_account_recovery"
    assert persona["userPrincipalName"] == ALICE_UPN
    assert persona["id"] == ALICE_OID
    # Nothing in the persona authorises acting for anyone else.
    assert BOB_UPN not in str(persona)
    assert BOB_OID not in str(persona)


def test_32_graph_corroboration_uses_the_mapped_oid(enrolled, provider):
    """The directory is asked about the mapped object id, not spoken input."""
    asked: list[tuple] = []

    class Recorder(GraphCorroborator):
        def corroborate(self, tenant_id, object_id, expected_upn):
            asked.append((tenant_id, object_id, expected_upn))
            return CorroborationResult(available=True, ok=True, reason="ok",
                                       object_exists=True, tenant_ok=True,
                                       account_enabled=False,
                                       directory_upn=expected_upn)

    manager = DuoRecoveryManager(enrolled, provider, Recorder(), sleep=lambda _: None)
    call_id = start_call(manager, "call-graph")
    manager.handle_turn(call_id, f"my employee ID is {ALICE_ID}, and my name is Bob")
    manager.handle_turn(call_id, "passcode")
    outcome = manager.handle_turn(call_id, "four eight two one six nine")

    assert asked == [(TENANT, ALICE_OID, ALICE_UPN)]
    assert outcome.identity["graph_corroboration"]["account_enabled"] is False


def test_32b_directory_contradiction_fails_closed(enrolled, provider):
    """A map row pointing at a missing object does not authenticate."""
    class Missing(GraphCorroborator):
        def corroborate(self, tenant_id, object_id, expected_upn):
            return CorroborationResult(available=True, ok=False,
                                       reason="object_not_found",
                                       object_exists=False)

    manager = DuoRecoveryManager(enrolled, provider, Missing(), sleep=lambda _: None)
    call_id = start_call(manager, "call-missing")
    outcome = verify_by_passcode(manager, call_id)
    assert outcome.speak == LOCKED_MESSAGE
    assert manager.get(call_id).verified_identity is None


def test_32c_upn_drift_is_surfaced_not_silently_followed(enrolled, provider):
    """The directory's new UPN never retargets the call mid-flight."""
    class Drifted(GraphCorroborator):
        def corroborate(self, tenant_id, object_id, expected_upn):
            return CorroborationResult(available=True, ok=True, reason="ok",
                                       object_exists=True, tenant_ok=True,
                                       directory_upn=BOB_UPN, upn_drift=True)

    manager = DuoRecoveryManager(enrolled, provider, Drifted(), sleep=lambda _: None)
    call_id = start_call(manager, "call-drift")
    outcome = verify_by_passcode(manager, call_id)

    persona = duo_persona(outcome.identity)
    assert persona["userPrincipalName"] == ALICE_UPN     # the mapped alias
    assert persona["id"] == ALICE_OID                    # the canonical key
    assert persona["upn_drift_detected"] is True
    assert BOB_UPN not in str(persona)


# ---------------------------------------------------------------------------
# factor-choice determinism
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("utterance,expected", [
    ("push", "push"),
    ("send a push", "push"),
    ("send me a notification", "push"),
    ("code", "passcode"),
    ("passcode", "passcode"),
    ("I'll read the code", "passcode"),
    ("whatever you think", None),
    ("push or passcode?", None),        # both mentioned: unclear, not guessed
    ("", None),
])
def test_factor_choice_is_deterministic(utterance, expected):
    assert parse_factor_choice(utterance) == expected


def test_unclear_factor_choice_asks_again(manager, provider):
    call_id = start_call(manager, "call-unclear")
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    outcome = manager.handle_turn(call_id, "um, whichever is easiest")
    assert not outcome.forward
    assert provider.called("start_push") == []
    assert manager.get(call_id).state is DuoRecoveryState.AWAITING_FACTOR_CHOICE


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def enroll_body():
    return {"tenant_id": TENANT, "object_id": ALICE_OID, "upn": ALICE_UPN}


def admin_header():
    return {"X-Recovery-Admin-Key": _ADMIN_KEY}


_ADMIN_KEY = "test-enrollment-admin-key-0123456789"
