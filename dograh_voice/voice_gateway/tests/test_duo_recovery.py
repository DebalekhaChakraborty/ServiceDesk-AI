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
import sys
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from voice_gateway.app import create_app
from voice_gateway.duo_provider import (
    DuoConfig,
    DuoRecoveryProvider,
    canonicalize,
    load_duo_config,
)
from voice_gateway.duo_recovery import (
    CORROBORATION_UNAVAILABLE,
    DuoRecoveryManager,
    DuoRecoveryState,
    FACTOR_PROMPT,
    FACTOR_PROMPT_PASSCODE_ONLY,
    FACTOR_PROMPT_PUSH_ONLY,
    FACTOR_RETRY_PUSH_ONLY,
    GENERIC_AUTH_FAILURE,
    GENERIC_LOOKUP_FAILURE,
    IDENTIFIER_RETRY,
    LOCKED_MESSAGE,
    PASSCODE_NOT_AVAILABLE,
    PROVIDER_UNAVAILABLE,
    PUSH_SENT_MESSAGE,
    PUSH_WAITING_MESSAGE,
    VERIFIED_CONTINUING,
    VERIFIED_MESSAGE,
    duo_persona,
)
from voice_gateway.graph_corroboration import (
    CorroborationResult,
    GraphCorroborator,
    LiveGraphCorroborator,
    NullGraphCorroborator,
)
from voice_gateway.identifiers import (
    IdentifierError,
    IdentifierKind,
    extract_identifier,
    normalize_mobile,
    parse_factor_choice,
)
from voice_gateway.identity import (
    IdentityTokenError,
    _b64e,
    _canonical,
    mint,
    mint_recovery_bootstrap,
    persona_from_claims,
    verify_recovery_bootstrap,
)
from voice_gateway.identity import verify as verify_identity_token
from voice_gateway.identity_map import (
    AmbiguousIdentifier,
    EmployeeIdentityMap,
    MAX_FAILURES,
    STATUS_ACTIVE,
    STATUS_NONE,
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


class CorroboratingStub(GraphCorroborator):
    """A directory that confirms the mapped object exists in the right tenant.

    The default for tests that are about something OTHER than corroboration.
    Corroboration is a hard requirement for VERIFIED, so without this every
    such test would fail closed before reaching the property it is checking.
    """

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def corroborate(self, tenant_id, object_id, expected_upn):
        self.calls.append((tenant_id, object_id, expected_upn))
        return CorroborationResult(available=True, ok=True, reason="ok",
                                   object_exists=True, tenant_ok=True,
                                   directory_upn=expected_upn,
                                   account_enabled=True)


@pytest.fixture
def manager(enrolled, provider):
    # sleep is stubbed out so bounded polling does not make tests slow.
    return DuoRecoveryManager(enrolled, provider, CorroboratingStub(),
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
                                     corroborator or CorroboratingStub(),
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


# Every external call now opens in AWAITING_REQUEST: the line asks what the
# caller needs before it asks who they are. This is the ordinary opening turn
# that gets a call to the point where an identifier is the next thing expected.
OPENING_REQUEST = "My VPN keeps disconnecting."


def start_call(manager, call_id="call-1", request=OPENING_REQUEST):
    """Start an external call and state the ServiceDesk request.

    Pass request=None for a call that never states one — the path where nothing
    is carried forward and verification simply asks how it can help.
    """
    manager.start(call_id)
    if request is not None:
        manager.handle_turn(call_id, request)
    return call_id


def verify_by_passcode(manager, call_id="call-1", request=OPENING_REQUEST):
    """Drive a fresh call all the way to VERIFIED using a spoken passcode."""
    start_call(manager, call_id, request)
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
    manager = DuoRecoveryManager(identity_map, provider, CorroboratingStub(),
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
# 14d-14j: activation-code lifecycle
#
# The activation code is temporary enrollment material and the only
# secret-like value the identity map ever holds. It must exist for exactly as
# long as enrollment is genuinely in progress and not one moment longer. The
# permanent Duo binding, duo_user_id, is on a different clock entirely.
# ---------------------------------------------------------------------------

def stored_activation_code(identity_map, employee_id):
    """Read the column straight off disk.

    Deliberately bypasses EmployeeRecord: the assertion is about what is at
    rest in the file, not about what an accessor chooses to expose.
    """
    with sqlite3.connect(identity_map.path) as conn:
        row = conn.execute(
            "SELECT duo_activation_code FROM employee_identity_map "
            "WHERE employee_id = ?", (employee_id,),
        ).fetchone()
    return row[0] if row else None


def test_14d_activation_code_is_retained_only_while_waiting(
        identity_map, provider, duo_client):
    """WAITING is the one state that still needs the code, so it keeps it."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)
    client.post("/recovery/enroll/duo/begin", json=enroll_body(), headers=admin_header())

    assert stored_activation_code(identity_map, ALICE_ID) == "activation-code-1"

    provider.enroll_status_state = "waiting"
    assert client.post("/recovery/enroll/duo/status", json=enroll_body(),
                       headers=admin_header()).json()["status"] == "waiting"

    # Still pending, so the code survives - the next poll has to present it.
    assert stored_activation_code(identity_map, ALICE_ID) == "activation-code-1"
    assert identity_map.get(ALICE_ID).duo_enrollment_status == STATUS_PENDING


def test_14e_activation_code_is_null_after_successful_enrollment(
        identity_map, provider, duo_client):
    """Terminal state "success": the code is gone, the binding is not."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)
    client.post("/recovery/enroll/duo/begin", json=enroll_body(), headers=admin_header())
    assert stored_activation_code(identity_map, ALICE_ID) is not None

    provider.enroll_status_state = "success"
    assert client.post("/recovery/enroll/duo/status", json=enroll_body(),
                       headers=admin_header()).json()["status"] == "active"

    assert stored_activation_code(identity_map, ALICE_ID) is None
    record = identity_map.get(ALICE_ID)
    assert record.duo_activation_code is None
    # The permanent binding is untouched, and recovery is now live.
    assert record.duo_user_id == "duo-user-fake-1"
    assert record.duo_enrollment_status == STATUS_ACTIVE
    assert record.recovery_ready()


def test_14f_activation_code_is_null_after_invalid_enrollment(
        identity_map, provider, duo_client):
    """Terminal state "invalid": a dead code is not left at rest."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)
    client.post("/recovery/enroll/duo/begin", json=enroll_body(), headers=admin_header())

    provider.enroll_status_state = "invalid"
    assert client.post("/recovery/enroll/duo/status", json=enroll_body(),
                       headers=admin_header()).json()["status"] == "invalid"

    assert stored_activation_code(identity_map, ALICE_ID) is None
    record = identity_map.get(ALICE_ID)
    assert record.duo_activation_code is None
    # duo_user_id is the permanent binding and survives a failed enrollment.
    assert record.duo_user_id == "duo-user-fake-1"
    # ...but nothing about this employee is recoverable.
    assert record.duo_enrollment_status == STATUS_NONE
    assert record.recovery_enabled == 0
    assert not record.recovery_ready()


@pytest.mark.parametrize("terminal_state", ["success", "invalid"])
def test_14g_no_terminal_enrollment_state_leaves_a_code(
        identity_map, provider, duo_client, terminal_state):
    """The invariant itself: NULL after every terminal state, without exception."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)
    client.post("/recovery/enroll/duo/begin", json=enroll_body(), headers=admin_header())

    provider.enroll_status_state = terminal_state
    client.post("/recovery/enroll/duo/status", json=enroll_body(), headers=admin_header())

    assert stored_activation_code(identity_map, ALICE_ID) is None


def test_14h_expired_enrollment_can_be_restarted_on_the_same_binding(
        identity_map, provider, duo_client):
    """Destroying the code does not strand the employee: re-enrollment works."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)
    client.post("/recovery/enroll/duo/begin", json=enroll_body(), headers=admin_header())

    provider.enroll_status_state = "invalid"       # the code expired unused
    client.post("/recovery/enroll/duo/status", json=enroll_body(), headers=admin_header())
    assert stored_activation_code(identity_map, ALICE_ID) is None

    # A fresh enrollment mints a fresh code and a fresh Duo user.
    provider.enroll_activation_code = "activation-code-2"
    provider.enroll_user_id = "duo-user-fake-2"
    client.post("/recovery/enroll/duo/begin", json=enroll_body(), headers=admin_header())
    assert stored_activation_code(identity_map, ALICE_ID) == "activation-code-2"

    provider.enroll_status_state = "success"
    assert client.post("/recovery/enroll/duo/status", json=enroll_body(),
                       headers=admin_header()).json()["status"] == "active"
    assert stored_activation_code(identity_map, ALICE_ID) is None
    assert identity_map.get(ALICE_ID).recovery_ready()


def test_14i_polling_after_activation_is_idempotent(
        identity_map, provider, duo_client):
    """Destroying the code on success must not make a repeat poll look broken."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    client, _ = duo_client(identity_map, provider)
    client.post("/recovery/enroll/duo/begin", json=enroll_body(), headers=admin_header())

    provider.enroll_status_state = "success"
    client.post("/recovery/enroll/duo/status", json=enroll_body(), headers=admin_header())

    second = client.post("/recovery/enroll/duo/status", json=enroll_body(),
                         headers=admin_header())
    assert second.status_code == 200
    assert second.json()["status"] == "active"
    # Answered from the record: Duo was asked exactly once, with the code that
    # existed at the time.
    assert provider.called("enroll_status") == [
        ("enroll_status", "duo-user-fake-1", "activation-code-1")
    ]


def test_14j_invalidate_keeps_the_duo_binding(identity_map):
    """At the map level: the code goes, duo_user_id stays."""
    identity_map.upsert_employee(ALICE_ID, TENANT, ALICE_OID, ALICE_UPN)
    identity_map.bind_duo_user(ALICE_ID, "duo-user-alice", "alice", "act-alice")
    assert stored_activation_code(identity_map, ALICE_ID) == "act-alice"

    identity_map.invalidate_duo_enrollment(ALICE_ID)

    record = identity_map.get(ALICE_ID)
    assert record.duo_activation_code is None
    assert record.duo_user_id == "duo-user-alice"        # permanent binding
    assert record.duo_username == "alice"
    assert record.entra_object_id == ALICE_OID           # identity untouched
    assert record.duo_enrollment_status == STATUS_NONE
    assert record.recovery_enabled == 0


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
    """A stale local mobile number does not decide what factors exist.

    Duo reports no devices at all. The map still holds a mobile number, and it
    confers nothing: with no advertised factor the call fails closed rather
    than prompting for a passcode no device can produce. (This assertion used
    to expect the passcode prompt, which is exactly the defect fixed in 7.1.)
    """
    assert enrolled.get(ALICE_ID).mobile_e164 == ALICE_MOBILE
    provider.devices = ()
    call_id = start_call(manager, "call-nodevices")
    outcome = manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    assert outcome.speak == PROVIDER_UNAVAILABLE
    assert manager.get(call_id).state is DuoRecoveryState.FAILED_UNAVAILABLE
    assert manager.get(call_id).push_device_id is None
    assert manager.get(call_id).passcode_capable is False
    assert enrolled.get(ALICE_ID).failures() == []


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

    assert outcome.speak == VERIFIED_CONTINUING
    assert outcome.identity["auth_method"] == "duo_push"
    assert outcome.identity["upn"] == ALICE_UPN
    # The call carried a request, so this turn IS the first ServiceDesk turn.
    assert manager.get(call_id).state is DuoRecoveryState.SERVICEDESK_ACTIVE


# ---------------------------------------------------------------------------
# 22-26: spoken passcode, and what must never leak
# ---------------------------------------------------------------------------

def test_22_spoken_passcode_allow_verifies(manager, provider):
    outcome = verify_by_passcode(manager)
    assert outcome.speak == VERIFIED_CONTINUING
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
    """Every pre-verification turn is consumed by the state machine.

    The caller's request, their identifier, their factor choice and the spoken
    passcode all happen before an identity exists, so none of them may reach
    sd_chat. The request is the newest member of that list and the one most
    likely to be leaked by accident, since — unlike a passcode — it is genuinely
    meant for sd_chat eventually.
    """
    call_id = "call-sd-1"
    manager.start(call_id)
    client, fake = gateway_client(manager)
    token = mint_recovery_bootstrap(call_id, SECRET)

    with client:
        for utterance in ("I cannot sign in to my account",
                          f"my employee ID is {ALICE_ID}",
                          "passcode",
                          "four eight two one six nine"):
            response = client.post("/voice/turn", json={
                "call_id": call_id, "voice_identity_token": token, "text": utterance,
            })
            assert response.status_code == 200
            if utterance != "four eight two one six nine":
                # Not one byte has reached ServiceDesk: no session, no turn.
                assert fake.run_payloads == [], utterance
                assert fake.created_state == {}, utterance

    # The passcode turn is the one that verifies, so it is also the one that
    # releases the request captured four turns earlier.
    assert len(fake.run_payloads) == 1
    sent = json.dumps(fake.run_payloads) + json.dumps(fake.created_state)
    assert "482169" not in sent
    assert "four eight two one six nine" not in sent.lower()
    assert "duo-user-alice" not in sent          # the Duo binding stays internal
    # What DID go through is the caller's original problem, verbatim.
    assert "I cannot sign in to my account" in sent

    persona = fake.created_state[auth_session_id(call_id)]["persona"]
    assert persona["identity_source"] == "duo_external_voice"
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
    assert persona["identity_source"] == "duo_external_voice"
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
# 33: corroboration fails CLOSED
#
# A Duo allow proves possession of the enrolled phone. It proves nothing about
# whether the local map row is still true, so it cannot establish an identity
# on its own. Every one of these tests drives a real, successful Duo
# authentication and then asserts that no identity came out of it.
# ---------------------------------------------------------------------------

class UnavailableCorroborator(GraphCorroborator):
    """Graph could not be reached at all."""

    def __init__(self, reason="graph_unavailable"):
        self.reason = reason

    def corroborate(self, tenant_id, object_id, expected_upn):
        return CorroborationResult(available=False, ok=False, reason=self.reason)


class ExplodingCorroborator(GraphCorroborator):
    """A corroborator whose own code fails."""

    def corroborate(self, tenant_id, object_id, expected_upn):
        raise RuntimeError("boom")


def duo_manager(identity_map, provider, corroborator):
    return DuoRecoveryManager(identity_map, provider, corroborator,
                              sleep=lambda _: None)


@pytest.mark.parametrize("corroborator,label", [
    (UnavailableCorroborator("graph_unavailable"), "graph down"),
    (UnavailableCorroborator("graph_error"), "graph returned 5xx"),
    (NullGraphCorroborator(), "no read credentials configured"),
    (ExplodingCorroborator(), "corroborator raised"),
])
def test_33_duo_allow_alone_establishes_no_identity(
        enrolled, provider, corroborator, label):
    """Duo said allow. Graph could not confirm. No identity_context is built."""
    manager = duo_manager(enrolled, provider, corroborator)
    call_id = start_call(manager, "call-unavailable")
    outcome = verify_by_passcode(manager, call_id)

    # Duo really did authenticate - this is not a Duo failure being caught.
    assert provider.called("verify_passcode") == [
        ("verify_passcode", "duo-user-alice", "482169")
    ]
    assert outcome.identity is None
    assert not outcome.forward
    assert outcome.speak == CORROBORATION_UNAVAILABLE
    assert manager.get(call_id).verified_identity is None
    assert manager.get(call_id).state is DuoRecoveryState.FAILED_UNAVAILABLE


def test_33b_graph_unavailable_never_forwards_to_servicedesk(enrolled, provider):
    """The turn after a failed corroboration is still not a ServiceDesk turn."""
    manager = duo_manager(enrolled, provider, UnavailableCorroborator())
    call_id = start_call(manager, "call-noforward")
    verify_by_passcode(manager, call_id)

    for utterance in ("hello?", "I need to reset my password", "are you there"):
        outcome = manager.handle_turn(call_id, utterance)
        assert not outcome.forward
        assert outcome.identity is None
        assert outcome.speak == CORROBORATION_UNAVAILABLE


def test_33c_graph_unavailable_says_retry_not_locked_out(enrolled, provider):
    """An outage is our fault, not the caller's, and is worded that way."""
    manager = duo_manager(enrolled, provider, UnavailableCorroborator())
    outcome = verify_by_passcode(manager, start_call(manager, "call-retry"))

    assert outcome.speak != LOCKED_MESSAGE
    assert outcome.speak not in (VERIFIED_MESSAGE, VERIFIED_CONTINUING)
    assert "again" in outcome.speak.lower()
    # And it discloses nothing about which dependency failed.
    for leak in ("graph", "directory", "microsoft", "entra", "duo", "tenant"):
        assert leak not in outcome.speak.lower()


def test_33d_graph_outage_does_not_charge_the_account_a_failure(enrolled, provider):
    """A directory outage must not lock every employee out of recovery."""
    manager = duo_manager(enrolled, provider, UnavailableCorroborator())
    for attempt in range(MAX_FAILURES + 2):
        verify_by_passcode(manager, f"call-outage-{attempt}")

    record = enrolled.get(ALICE_ID)
    assert record.failures() == []
    assert record.locked_until is None
    assert not enrolled.is_locked(ALICE_ID)

    # So when Graph comes back, the very next call verifies normally.
    recovered = duo_manager(enrolled, provider, CorroboratingStub())
    outcome = verify_by_passcode(recovered, "call-after-outage")
    assert outcome.speak == VERIFIED_CONTINUING
    assert outcome.identity["upn"] == ALICE_UPN


def test_33e_missing_object_fails_closed(enrolled, provider):
    """The map points at an object the directory does not have."""
    class Missing(GraphCorroborator):
        def corroborate(self, tenant_id, object_id, expected_upn):
            return CorroborationResult(available=True, ok=False,
                                       reason="object_not_found",
                                       object_exists=False, tenant_ok=True)

    manager = duo_manager(enrolled, provider, Missing())
    call_id = start_call(manager, "call-gone")
    outcome = verify_by_passcode(manager, call_id)

    assert outcome.identity is None
    assert not outcome.forward
    # A contradiction is terminal, not a retry-later.
    assert outcome.speak == LOCKED_MESSAGE
    assert manager.get(call_id).state is DuoRecoveryState.FAILED_LOCKED


def test_33f_wrong_tenant_fails_closed(enrolled, provider):
    """The object exists, but not in the tenant the map claims."""
    class WrongTenant(GraphCorroborator):
        def corroborate(self, tenant_id, object_id, expected_upn):
            return CorroborationResult(available=True, ok=False,
                                       reason="tenant_mismatch", tenant_ok=False)

    manager = duo_manager(enrolled, provider, WrongTenant())
    call_id = start_call(manager, "call-tenant")
    outcome = verify_by_passcode(manager, call_id)

    assert outcome.identity is None
    assert not outcome.forward
    assert outcome.speak == LOCKED_MESSAGE
    assert manager.get(call_id).state is DuoRecoveryState.FAILED_LOCKED


def test_33g_push_allow_is_also_gated_by_corroboration(enrolled, provider):
    """The gate is on the identity, not on one factor: push is gated too."""
    provider.push_results = ["allow"]
    manager = duo_manager(enrolled, provider, UnavailableCorroborator())
    call_id = start_call(manager, "call-push-gate")
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    outcome = manager.handle_turn(call_id, "send me a push")

    assert provider.called("start_push") != []
    assert outcome.identity is None
    assert outcome.speak == CORROBORATION_UNAVAILABLE
    assert manager.get(call_id).state is DuoRecoveryState.FAILED_UNAVAILABLE


def test_33h_only_a_live_uncontradicted_read_establishes_identity():
    """The gate itself: no combination other than available+ok is a pass."""
    assert CorroborationResult(available=True, ok=True).establishes_identity()
    assert not CorroborationResult(available=True, ok=False).establishes_identity()
    assert not CorroborationResult(available=False, ok=True).establishes_identity()
    assert not CorroborationResult(available=False, ok=False).establishes_identity()
    # The unconfigured corroborator can never be a pass.
    assert not NullGraphCorroborator().corroborate(
        TENANT, ALICE_OID, ALICE_UPN).establishes_identity()


def test_33i_live_corroborator_reports_outages_as_unavailable():
    """Transport failure and non-200 both produce a fail-closed result."""
    class Boom:
        def post(self, *a, **k):
            raise OSError("connection refused")

    result = LiveGraphCorroborator(TENANT, "cid", "secret", session=Boom()).corroborate(
        TENANT, ALICE_OID, ALICE_UPN
    )
    assert result.reason == "graph_unavailable"
    assert not result.establishes_identity()

    class ServerError:
        def post(self, *a, **k):
            return _FakeResponse(200, {"access_token": "t"})

        def get(self, *a, **k):
            return _FakeResponse(503, {})

    result = LiveGraphCorroborator(
        TENANT, "cid", "secret", session=ServerError()
    ).corroborate(TENANT, ALICE_OID, ALICE_UPN)
    assert result.reason == "graph_error"
    assert not result.establishes_identity()


def test_33j_live_corroborator_settles_a_tenant_mismatch_locally():
    """A wrong tenant is a contradiction, and is not worth a network call."""
    class NeverCalled:
        def post(self, *a, **k):
            raise AssertionError("no request should be made")

    result = LiveGraphCorroborator(
        TENANT, "cid", "secret", session=NeverCalled()
    ).corroborate("99999999-0000-0000-0000-000000000000", ALICE_OID, ALICE_UPN)

    assert result.available is True          # a definite answer, locally
    assert result.reason == "tenant_mismatch"
    assert not result.establishes_identity()


def test_33k_upn_drift_stays_informational(enrolled, provider):
    """Drift is still a pass, still surfaced, and still never retargets."""
    class Drifted(GraphCorroborator):
        def corroborate(self, tenant_id, object_id, expected_upn):
            return CorroborationResult(available=True, ok=True, reason="ok",
                                       object_exists=True, tenant_ok=True,
                                       directory_upn=BOB_UPN, upn_drift=True)

    manager = duo_manager(enrolled, provider, Drifted())
    outcome = verify_by_passcode(manager, start_call(manager, "call-drift-2"))

    assert outcome.speak == VERIFIED_CONTINUING        # informational, not fatal
    assert outcome.identity["entra_object_id"] == ALICE_OID
    assert outcome.identity["upn"] == ALICE_UPN
    persona = duo_persona(outcome.identity)
    assert persona["id"] == ALICE_OID                  # mapped oid is authoritative
    assert persona["upn_drift_detected"] is True
    assert BOB_UPN not in str(persona)


def _healthy_duo(monkeypatch, tmp_path):
    """Make Duo look fully configured and healthy WITHOUT any network call.

    Deliberately stubbed rather than driven by the real runtime credentials:
    a unit test must not sign a request to a live Duo tenant, and must not
    create the real identity map as a side effect of importing config.
    """
    from voice_gateway import app as app_module

    monkeypatch.delenv("RECOVERY_PROVIDER", raising=False)
    monkeypatch.setenv("RECOVERY_IDENTITY_DB", str(tmp_path / "map.db"))
    monkeypatch.setattr(
        app_module, "load_duo_config",
        lambda: DuoConfig(ikey="DI" + "X" * 18, skey="x" * 40,
                          host="api-abcd1234.duosecurity.com"),
    )

    class HealthyProvider(DuoRecoveryProvider):
        def check(self):
            from voice_gateway.mfa_provider import ProviderCheck
            return ProviderCheck(ok=True)

    monkeypatch.setattr(app_module, "DuoRecoveryProvider", HealthyProvider)
    return app_module


def test_33l_recovery_is_off_when_corroboration_is_unconfigured(monkeypatch, tmp_path):
    """A route that could only ever fail at the last step is not switched on."""
    from voice_gateway.config import load_settings

    app_module = _healthy_duo(monkeypatch, tmp_path)
    for name in ("RECOVERY_GRAPH_TENANT_ID", "RECOVERY_GRAPH_CLIENT_ID",
                 "RECOVERY_GRAPH_CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("voice_gateway.graph_corroboration.RUNTIME", tmp_path)

    assert isinstance(app_module.load_corroborator(), NullGraphCorroborator)
    # Duo is healthy, so corroboration is the ONLY thing switching recovery off.
    assert app_module._build_recovery(load_settings()) is None


def test_33m_configuring_corroboration_switches_recovery_back_on(monkeypatch, tmp_path):
    """The positive control for 33l: nothing else in that test was the cause."""
    from voice_gateway.config import load_settings

    app_module = _healthy_duo(monkeypatch, tmp_path)
    monkeypatch.setenv("RECOVERY_GRAPH_TENANT_ID", TENANT)
    monkeypatch.setenv("RECOVERY_GRAPH_CLIENT_ID", "graph-client-id")
    monkeypatch.setenv("RECOVERY_GRAPH_CLIENT_SECRET", "graph-client-secret")

    built = app_module._build_recovery(load_settings())
    assert isinstance(built, DuoRecoveryManager)
    assert isinstance(app_module.load_corroborator(), LiveGraphCorroborator)


def test_34_the_suite_never_touches_the_real_duo_tenant_or_map():
    """Guards the isolation fixture itself.

    Without this, provisioning the host silently turns the test suite into a
    client of the live Duo tenant and a writer of the real identity map. If
    the autouse fixture in conftest is ever removed, this fails immediately
    rather than at some later moment when a test run costs a real API call.
    """
    from voice_gateway import duo_provider, graph_corroboration
    from voice_gateway.identity_map import DEFAULT_DB, EmployeeIdentityMap

    real_runtime = Path(__file__).resolve().parents[2] / "runtime"
    assert duo_provider.RUNTIME != real_runtime
    assert graph_corroboration.RUNTIME != real_runtime

    # Unconfigured from the suite's point of view, whatever the host holds.
    assert load_duo_config() is None
    assert EmployeeIdentityMap().path != DEFAULT_DB


# ---------------------------------------------------------------------------
# 36: capability-safe factor selection
#
# preauth is the ONLY authority on what a device can do. A factor offered but
# not supported is not a cosmetic slip: accepting it sends the caller to read a
# code nothing can generate, and each attempt charges the ACCOUNT a failure, so
# an unusable option walks a legitimate caller into a lockout.
# ---------------------------------------------------------------------------

PUSH_ONLY = (Device(device_id="DEV-P", display_name="Android", device_type="phone",
                    capabilities=frozenset({CAP_PUSH})),)
OTP_ONLY = (Device(device_id="DEV-O", display_name="Tablet", device_type="tablet",
                   capabilities=frozenset({CAP_MOBILE_OTP})),)
BOTH = (Device(device_id="DEV-B", display_name="iPhone", device_type="phone",
               capabilities=frozenset({CAP_PUSH, CAP_MOBILE_OTP})),)
NEITHER = (Device(device_id="DEV-N", display_name="Landline", device_type="phone",
                  capabilities=frozenset({"phone"})),)


def offer_for(manager, provider, devices, call_id):
    provider.devices = devices
    start_call(manager, call_id)
    return manager.handle_turn(call_id, f"my employee ID is {ALICE_ID}")


@pytest.mark.parametrize("devices,expect_speak,expect_state", [
    (BOTH,     FACTOR_PROMPT,                DuoRecoveryState.AWAITING_FACTOR_CHOICE),
    (PUSH_ONLY, FACTOR_PROMPT_PUSH_ONLY,     DuoRecoveryState.AWAITING_FACTOR_CHOICE),
    (OTP_ONLY, FACTOR_PROMPT_PASSCODE_ONLY,  DuoRecoveryState.AWAITING_PASSCODE),
    (NEITHER,  PROVIDER_UNAVAILABLE,         DuoRecoveryState.FAILED_UNAVAILABLE),
])
def test_36_capability_matrix_offers_only_usable_factors(
        manager, provider, devices, expect_speak, expect_state):
    outcome = offer_for(manager, provider, devices, "call-cap")
    assert outcome.speak == expect_speak
    assert manager.get("call-cap").state is expect_state
    assert not outcome.forward


def test_36b_push_only_never_mentions_a_passcode(manager, provider):
    """The word must not reach the caller at all on a push-only device."""
    outcome = offer_for(manager, provider, PUSH_ONLY, "call-nomention")
    for banned in ("passcode", "code", "six-digit"):
        assert banned not in outcome.speak.lower(), outcome.speak

    # ...and the same holds for the retry and timeout wording.
    retry = manager.handle_turn("call-nomention", "um, whichever is easiest")
    assert retry.speak == FACTOR_RETRY_PUSH_ONLY
    for banned in ("passcode", "six-digit"):
        assert banned not in retry.speak.lower()


@pytest.mark.parametrize("utterance", ["passcode", "code", "I'll read the code"])
def test_36c_selecting_passcode_on_push_only_is_refused_without_cost(
        manager, provider, enrolled, utterance):
    """The load-bearing guarantee: refused, no state move, no failure charged."""
    offer_for(manager, provider, PUSH_ONLY, "call-refuse")
    before = enrolled.get(ALICE_ID).failures()

    outcome = manager.handle_turn("call-refuse", utterance)

    assert outcome.speak == PASSCODE_NOT_AVAILABLE
    assert manager.get("call-refuse").state is DuoRecoveryState.AWAITING_FACTOR_CHOICE
    assert manager.get("call-refuse").factor_attempts == 0
    assert enrolled.get(ALICE_ID).failures() == before          # account untouched
    assert not enrolled.is_locked(ALICE_ID)
    assert provider.called("verify_passcode") == []             # never asked Duo
    assert outcome.identity is None


def test_36d_repeated_passcode_requests_cannot_lock_a_push_only_caller(
        manager, provider, enrolled):
    """The lockout path this bug actually opened, driven past the limit."""
    offer_for(manager, provider, PUSH_ONLY, "call-nolock")
    for _ in range(MAX_FAILURES + 3):
        outcome = manager.handle_turn("call-nolock", "passcode")
        assert outcome.speak == PASSCODE_NOT_AVAILABLE

    assert enrolled.get(ALICE_ID).failures() == []
    assert not enrolled.is_locked(ALICE_ID)
    assert manager.get("call-nolock").state is DuoRecoveryState.AWAITING_FACTOR_CHOICE
    # Push is still reachable afterwards - the caller was never derailed.
    assert manager.handle_turn("call-nolock", "push").speak in (
        PUSH_SENT_MESSAGE, VERIFIED_CONTINUING)


def test_36e_push_still_works_on_a_push_only_device(manager, provider):
    provider.push_results = ["allow"]
    offer_for(manager, provider, PUSH_ONLY, "call-pushonly")
    outcome = manager.handle_turn("call-pushonly", "push")
    assert provider.called("start_push") == [("start_push", "duo-user-alice", "DEV-P")]
    assert outcome.speak == VERIFIED_CONTINUING
    assert outcome.identity["auth_method"] == "duo_push"


def test_36f_no_usable_factor_charges_nothing_and_builds_no_identity(
        manager, provider, enrolled):
    outcome = offer_for(manager, provider, NEITHER, "call-nofactor")
    assert outcome.speak == PROVIDER_UNAVAILABLE
    assert outcome.identity is None
    assert enrolled.get(ALICE_ID).failures() == []
    assert not enrolled.is_locked(ALICE_ID)
    assert provider.called("start_push") == []
    assert provider.called("verify_passcode") == []
    # Terminal, and it keeps saying the same thing rather than switching story.
    assert manager.handle_turn("call-nofactor", "hello?").speak == PROVIDER_UNAVAILABLE


def test_36g_no_usable_factor_is_indistinguishable_from_a_duo_outage(
        manager, provider):
    """Otherwise the phone line reports which accounts have no usable device."""
    no_factor = offer_for(manager, provider, NEITHER, "call-nf")

    provider.devices = BOTH
    provider.raise_on = "preauth"          # Duo unreachable
    start_call(manager, "call-outage")
    outage = manager.handle_turn("call-outage", f"employee id {ALICE_ID}")

    assert no_factor.speak == outage.speak == PROVIDER_UNAVAILABLE


def test_36h_capabilities_never_come_from_the_local_map(manager, provider, enrolled):
    """A stored mobile number says nothing about what the device can do."""
    assert enrolled.get(ALICE_ID).mobile_e164          # map has a mobile on file
    outcome = offer_for(manager, provider, PUSH_ONLY, "call-notmap")
    assert outcome.speak == FACTOR_PROMPT_PUSH_ONLY    # still push-only
    assert manager.get("call-notmap").passcode_capable is False


def test_36i_passcode_state_without_capability_is_refused(manager, provider, enrolled):
    """Defence in depth: force the state directly and it still cannot charge."""
    offer_for(manager, provider, PUSH_ONLY, "call-forced")
    session = manager.get("call-forced")
    session.state = DuoRecoveryState.AWAITING_PASSCODE     # simulate a future bug

    outcome = manager.handle_turn("call-forced", "four eight two one six nine")

    assert outcome.speak == PASSCODE_NOT_AVAILABLE
    assert provider.called("verify_passcode") == []
    assert enrolled.get(ALICE_ID).failures() == []
    assert session.state is DuoRecoveryState.AWAITING_FACTOR_CHOICE


@pytest.mark.parametrize("result", [PREAUTH_ALLOW, PREAUTH_DENY, PREAUTH_ENROLL])
def test_36j_capability_gating_did_not_weaken_the_preauth_rule(
        manager, provider, result):
    """'allow' is a policy bypass and stays refused alongside deny/enroll."""
    provider.preauth_result = result
    outcome = offer_for(manager, provider, PUSH_ONLY, f"call-pre-{result}")
    assert outcome.speak == GENERIC_LOOKUP_FAILURE
    assert manager.get(f"call-pre-{result}").verified_identity is None
    assert provider.called("start_push") == []


# ---------------------------------------------------------------------------
# 37: one reproducible start mechanism
#
# Recovery is now mandatory-corroborated, so a launch that silently resolves no
# Graph configuration silently disables recovery. Every required value must
# therefore come from ignored runtime files, with no exported environment and
# no wrapper script.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 38: the two bootstrap types, and nothing else
#
# EXTERNAL RECOVERY is the canonical journey: the caller has no corporate
# identity and the bootstrap asserts none. AUTHENTICATED PORTAL VOICE is an
# optional shortcut for someone who already signed in. Everything else - no
# token, wrong purpose, wrong audience, wrong call - must fail closed, because
# "no token means anonymous recovery" would be an unauthenticated bypass of
# the entire Duo/Graph chain.
# ---------------------------------------------------------------------------

RECOVERY_CLAIMS = {"aud", "call_id", "exp", "iat", "purpose", "ver"}
IDENTITY_CLAIM_NAMES = {"upn", "oid", "object_id", "employee_id", "mobile",
                        "name", "mail", "displayName", "claimed_upn_hint"}


def claims_of(token):
    import base64
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def test_38_external_bootstrap_asserts_no_identity():
    """The canonical caller is anonymous until Duo says otherwise."""
    call_id = "voice_ext_1"
    token = mint_recovery_bootstrap(call_id, SECRET)
    claims = claims_of(token)

    assert set(claims) == RECOVERY_CLAIMS
    assert claims["purpose"] == "account_recovery"
    assert not (set(claims) & IDENTITY_CLAIM_NAMES)
    # And it cannot be laundered into a full identity assertion.
    with pytest.raises(IdentityTokenError):
        verify_identity_token(token, SECRET, call_id)


def test_38b_authenticated_bootstrap_still_carries_trusted_identity():
    """The optional portal shortcut is unchanged by making recovery canonical."""
    call_id = "voice_auth_1"
    token = mint(ALICE_UPN, call_id, SECRET, display_name="Alice Test",
                 object_id=ALICE_OID)
    claims = verify_identity_token(token, SECRET, call_id)

    assert claims["upn"] == ALICE_UPN
    assert claims["oid"] == ALICE_OID
    assert "purpose" not in claims          # never a recovery token
    persona = persona_from_claims(claims)
    assert persona["identity_source"] == "entra_portal_voice"
    # ...and it is refused where a recovery bootstrap is required.
    with pytest.raises(IdentityTokenError):
        verify_recovery_bootstrap(token, SECRET, call_id)


@pytest.mark.parametrize("label,make", [
    ("missing token",   lambda cid: ""),
    ("garbage",         lambda cid: "not.a.token"),
    ("unsigned alg=none",
     lambda cid: _b64e(b'{"alg":"none","typ":"JWT"}') + "." +
                 _b64e(b'{"ver":1,"purpose":"account_recovery"}') + "."),
    ("wrong secret",    lambda cid: mint_recovery_bootstrap(cid, "z" * 48)),
    ("wrong call_id",   lambda cid: mint_recovery_bootstrap("voice_other", SECRET)),
    ("expired",         lambda cid: mint_recovery_bootstrap(
                            cid, SECRET, ttl_seconds=1, now=time.time() - 5000)),
    ("issued in future", lambda cid: mint_recovery_bootstrap(
                            cid, SECRET, now=time.time() + 5000)),
])
def test_38c_every_other_bootstrap_fails_closed(label, make):
    """No token and no context must never mean anonymous recovery."""
    call_id = "voice_closed"
    with pytest.raises(IdentityTokenError):
        verify_recovery_bootstrap(make(call_id), SECRET, call_id)


def test_38d_wrong_audience_is_refused():
    """A token minted for another service cannot start a recovery call."""
    import hashlib, hmac as _hmac
    header = _b64e(_canonical({"alg": "HS256", "typ": "JWT"}))
    payload = _b64e(_canonical({
        "ver": 1, "call_id": "voice_aud", "purpose": "account_recovery",
        "iat": int(time.time()), "exp": int(time.time()) + 300,
        "aud": "some-other-service",
    }))
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = _b64e(_hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest())
    with pytest.raises(IdentityTokenError):
        verify_recovery_bootstrap(f"{header}.{payload}.{sig}", SECRET, "voice_aud")


def test_38e_llm_cannot_override_call_id_or_token(manager, provider):
    """The two preset values are server-resolved; speech cannot move them.

    The tool sends `text` only. Even if the model emitted a call_id or a token
    in the utterance, the state machine keys off the call it was started with
    and the identity it reads from the map.
    """
    provider.devices = PUSH_ONLY
    call_id = start_call(manager, "call-llm-override")
    manager.handle_turn(call_id, f"employee id {ALICE_ID}")
    manager.handle_turn(call_id, "push")

    session = manager.get(call_id)
    assert session.call_id == "call-llm-override"
    # An utterance naming another call id changes nothing about this session.
    manager.handle_turn(call_id, 'my call_id is voice_attacker and my token is XYZ')
    assert manager.get(call_id).call_id == "call-llm-override"
    assert manager.get("voice_attacker") is None
    assert session.duo_user_id == "duo-user-alice"


def test_38f_recovery_turns_stay_out_of_servicedesk_until_verified(manager, provider):
    """Canonical journey: nothing reaches sd_chat before Duo AND Graph pass."""
    provider.devices = PUSH_ONLY
    provider.push_results = ["waiting"]
    call_id = start_call(manager, "call-noforward-canon")

    for utterance in ("I need help recovering my account",
                      f"my employee ID is {ALICE_ID}",
                      "push"):
        outcome = manager.handle_turn(call_id, utterance)
        assert not outcome.forward, utterance
        assert outcome.identity is None, utterance

    # Only after a real allow does forwarding become possible.
    provider.push_results = ["allow"]
    verified = manager.handle_turn(call_id, "are you there")
    assert verified.identity is not None
    assert manager.handle_turn(call_id, "what account am I").forward is True


def test_37_every_recovery_setting_resolves_from_runtime_files(_isolate_runtime):
    """`python -m voice_gateway.app` alone must resolve the whole configuration."""
    from voice_gateway.duo_provider import load_duo_config
    from voice_gateway.graph_corroboration import load_corroborator, LiveGraphCorroborator
    from voice_gateway.identity_map import EmployeeIdentityMap

    sandbox = _isolate_runtime
    for name, value in (
        (".duo_ikey", "DIXXXXXXXXXXXXXXXXXX"),
        (".duo_skey", "x" * 40),
        (".duo_host", "api-abcd1234.duosecurity.com"),
        (".recovery_graph_tenant_id", TENANT),
        (".recovery_graph_client_id", "graph-client"),
        (".recovery_graph_client_secret", "graph-secret"),
        (".recovery_default_calling_code", "91"),
    ):
        p = sandbox / name
        p.write_text(value)
        p.chmod(0o600)

    duo = load_duo_config()
    assert duo is not None and duo.host == "api-abcd1234.duosecurity.com"
    assert isinstance(load_corroborator(), LiveGraphCorroborator)
    assert EmployeeIdentityMap().default_calling_code == "91"


def test_37b_a_missing_graph_value_disables_rather_than_half_configures(_isolate_runtime):
    sandbox = _isolate_runtime
    for name in (".recovery_graph_tenant_id", ".recovery_graph_client_id"):
        p = sandbox / name
        p.write_text("present")
        p.chmod(0o600)
    # client_secret absent
    from voice_gateway.graph_corroboration import load_corroborator
    assert isinstance(load_corroborator(), NullGraphCorroborator)


def test_37c_a_world_readable_runtime_file_is_refused_and_logged(_isolate_runtime, caplog):
    """A chmod slip must not silently become 'recovery DISABLED' with no reason."""
    from voice_gateway.graph_corroboration import load_corroborator

    sandbox = _isolate_runtime
    for name in (".recovery_graph_tenant_id", ".recovery_graph_client_id",
                 ".recovery_graph_client_secret"):
        p = sandbox / name
        p.write_text("value")
        p.chmod(0o600)
    (sandbox / ".recovery_graph_client_secret").chmod(0o644)      # the slip

    with caplog.at_level(logging.WARNING, logger="voice_gateway"):
        assert isinstance(load_corroborator(), NullGraphCorroborator)
    assert any("not owner-only" in r.getMessage() for r in caplog.records)
    # ...and the file name is named, so the fix is obvious from the log alone.
    assert any(".recovery_graph_client_secret" in r.getMessage()
               for r in caplog.records)


def test_37d_calling_code_is_never_defaulted_in_code(_isolate_runtime):
    """Guessing a country would silently make a spoken mobile match nobody."""
    from voice_gateway.identity_map import EmployeeIdentityMap
    assert EmployeeIdentityMap().default_calling_code is None


def test_35_importing_the_app_module_builds_nothing(monkeypatch):
    """Importing must stay free of side effects, and uvicorn must still work.

    `app = create_app()` at module scope meant that importing this module read
    the Duo credentials, signed a live /check against the real tenant, and
    created the real identity map — before any fixture could intervene, since
    it happened during import. Every test module imports it.
    """
    from fastapi import FastAPI
    from voice_gateway import app as app_module

    assert app_module._app is None

    # `uvicorn voice_gateway.app:app` must still resolve, and to ONE instance.
    monkeypatch.setattr(app_module, "_app", None)
    resolved = app_module.app
    assert isinstance(resolved, FastAPI)
    assert app_module.app is resolved
    # main() reads the same accessor; a bare global would be a NameError now.
    assert app_module._asgi_app() is resolved

    with pytest.raises(AttributeError):
        app_module.not_a_real_attribute


def test_35b_importing_the_app_module_touches_no_real_state():
    """The same property, proven in a process with no fixtures at all."""
    runtime = Path(__file__).resolve().parents[2] / "runtime"
    db = runtime / "recovery_identity.db"
    existed = db.exists()

    result = subprocess.run(
        [sys.executable, "-c",
         "import voice_gateway.app as m; assert m._app is None; print('clean')"],
        cwd=str(Path(__file__).resolve().parents[2]),
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "clean" in result.stdout
    assert db.exists() == existed, "importing the app module created the real map"


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


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
