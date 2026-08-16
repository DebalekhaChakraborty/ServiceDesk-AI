"""Pre-enrolled TOTP recovery: the properties that make spoken OTP safe."""

from __future__ import annotations

import json
import logging
import time

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from voice_gateway.app import create_app
from voice_gateway.identity import mint, mint_recovery_bootstrap
from voice_gateway.recovery import (
    RecoveryManager,
    RecoveryState,
    recovery_persona,
)
from voice_gateway.recovery_store import (
    MAX_FAILURES,
    RecoveryStore,
    SecretCollision,
    _assert_no_collision,
)
from voice_gateway.servicedesk_client import ServiceDeskClient
from voice_gateway.session import auth_session_id
from voice_gateway.totp import (
    SpokenCodeError,
    current_timestep,
    generate_seed,
    parse_spoken_code,
    totp_at,
)

from test_authenticated_identity import RecordingServiceDesk, SECRET, auth_settings

ALICE = "alice.test@example.invalid"
BOB = "bob.test@example.invalid"


@pytest.fixture
def store(tmp_path):
    return RecoveryStore(path=tmp_path / "store.json", key=Fernet.generate_key())


@pytest.fixture(autouse=True)
def _signing_secret(monkeypatch):
    monkeypatch.setenv("VOICE_IDENTITY_SIGNING_SECRET", SECRET)


@pytest.fixture
def enrolled(store):
    """An ACTIVE enrollment for Alice, plus her seed for making codes.

    Activation happens two timesteps in the PAST on purpose. The proof code is
    itself consumed at activation (that is the design), so enrolling "now"
    would leave the current timestep already spent and every test code would
    be a legitimate replay rejection.
    """
    seed, _ = store.begin_enrollment(ALICE, "Alice Test", "oid-alice")
    past = time.time() - 2 * 30
    assert store.activate(ALICE, totp_at(seed, current_timestep(past)), now=past)
    return seed


def code_for(seed, offset=0, now=None):
    return totp_at(seed, current_timestep(now) + offset)


# ------------------------------------------------ 6 & 7. spoken parsing ----

@pytest.mark.parametrize("utterance,expected", [
    ("482169", "482169"),
    ("4 8 2 1 6 9", "482169"),
    ("four eight two one six nine", "482169"),
    ("four, eight, two, one, six, nine", "482169"),
    ("my code is 482169", "482169"),
    ("it's four eight 2 1 six nine", "482169"),
    ("48 21 69", "482169"),
    ("zero zero zero one two three", "000123"),
])
def test_spoken_code_parsing(utterance, expected):
    assert parse_spoken_code(utterance) == expected


# ------------------------------------------------ 8. ambiguity rejected ----

@pytest.mark.parametrize("utterance", [
    "four eight two one six",              # five digits
    "four eight two one six nine seven",   # seven digits
    "",
    "I don't have my phone",
    "oh eight two one six nine",           # "oh" is NOT accepted as zero
    "for eight to one six nine",           # homophones are NOT repaired
    "four eight two one six niner",
])
def test_ambiguous_speech_is_rejected_not_guessed(utterance):
    """A misheard code must be re-asked, never repaired into a valid one."""
    with pytest.raises(SpokenCodeError):
        parse_spoken_code(utterance)


def test_parse_failure_category_carries_no_digits():
    try:
        parse_spoken_code("four eight two")
    except SpokenCodeError as exc:
        assert exc.category == "not_six_digits"
        assert "four" not in str(exc) and "482" not in str(exc)


# --------------------------------------------------- 1-5. verification ----

def test_unenrolled_account_fails_generically(store):
    ok, category = store.verify("nobody@example.invalid", "123456")
    assert ok is False and category == "not_enrolled"


def test_wrong_code_is_rejected(store, enrolled):
    wrong = "000000" if code_for(enrolled) != "000000" else "111111"
    ok, _ = store.verify(ALICE, wrong)
    assert ok is False


def test_expired_code_is_rejected(store, enrolled):
    """Two steps back is outside the ±1 drift allowance."""
    ok, _ = store.verify(ALICE, code_for(enrolled, offset=-3))
    assert ok is False


def test_valid_code_is_accepted_once(store, enrolled):
    ok, category = store.verify(ALICE, code_for(enrolled))
    assert ok is True and category == "ok"


def test_replay_of_the_same_valid_code_is_rejected(store, enrolled):
    """The decisive property: still inside its window, but already consumed."""
    code = code_for(enrolled)
    assert store.verify(ALICE, code)[0] is True
    ok, category = store.verify(ALICE, code)
    assert ok is False and category == "replayed"


def test_earlier_timestep_cannot_be_used_after_a_later_one(store, enrolled):
    now = time.time()
    assert store.verify(ALICE, code_for(enrolled, 0, now), now)[0] is True
    ok, category = store.verify(ALICE, code_for(enrolled, -1, now), now)
    assert ok is False and category == "replayed"


# --------------------------------------------------- 9. rate limiting -----

def test_five_failures_lock_the_account(store, enrolled):
    for _ in range(MAX_FAILURES):
        store.verify(ALICE, "000000")
    ok, category = store.verify(ALICE, code_for(enrolled))
    assert ok is False and category == "locked", "a valid code must not unlock"


def test_new_code_generation_does_not_reset_the_failure_counter(store, enrolled):
    """The counter tracks attacker effort, not code age."""
    for _ in range(MAX_FAILURES - 1):
        store.verify(ALICE, "000000")
    later = time.time() + 60          # several new codes have existed since
    ok, category = store.verify(ALICE, "111111", later)
    assert ok is False
    assert store._get(ALICE).locked_until is not None


def test_backoff_grows_with_failures(store, enrolled):
    delays = []
    for _ in range(3):
        store.verify(ALICE, "000000")
        delays.append(store.backoff_seconds(ALICE))
    assert delays == sorted(delays) and delays[-1] > 0


# ------------------------------------- 12. cross-account isolation --------

def test_alice_code_cannot_authenticate_bob(store, enrolled):
    bob_seed, _ = store.begin_enrollment(BOB, "Bob Test", "oid-bob")
    past = time.time() - 60
    store.activate(BOB, totp_at(bob_seed, current_timestep(past)), now=past)
    ok, _ = store.verify(BOB, code_for(enrolled))
    assert ok is False


def test_identity_comes_from_the_enrollment_record(store, enrolled):
    identity = store.identity_for(ALICE)
    assert identity == {"upn": ALICE, "display_name": "Alice Test",
                        "object_id": "oid-alice"}


def test_pending_enrollment_is_not_usable(store):
    store.begin_enrollment(BOB, "Bob Test")
    ok, category = store.verify(BOB, "123456")
    assert ok is False and category == "not_enrolled"


def test_activation_requires_a_valid_code(store):
    store.begin_enrollment(BOB, "Bob Test")
    assert store.activate(BOB, "000000") is False
    assert store.status_for(BOB) == "pending"


# --------------------------------------- 16. seed never leaves the store --

def test_seed_is_encrypted_at_rest_and_never_returned(store, enrolled):
    raw = store.path.read_text()
    assert enrolled not in raw, "seed must not be stored in clear"
    assert "encrypted_seed" in raw
    assert enrolled not in json.dumps(store.identity_for(ALICE))


def test_recovery_key_collision_fails_closed():
    with pytest.raises(SecretCollision):
        secret = (RecoveryStore.__module__ and
                  __import__("pathlib").Path(
                      "runtime/.voice_identity_secret").read_text().strip())
        _assert_no_collision(secret)


# ------------------------------------------- state machine behaviour ------

@pytest.fixture
def manager(store):
    return RecoveryManager(store=store)


def test_state_machine_reaches_servicedesk_only_after_valid_otp(manager, enrolled):
    manager.start("voice_r1", ALICE)
    assert manager.get("voice_r1").state is RecoveryState.WAITING_FOR_OTP

    bad = manager.handle_turn("voice_r1", "one two three four five six")
    assert bad.forward is False

    ok = manager.handle_turn("voice_r1", " ".join(code_for(enrolled)))
    assert ok.forward is False                      # verification turn speaks
    assert ok.state is RecoveryState.OTP_VERIFIED
    assert ok.identity["auth_method"] == "recovery_totp"

    nxt = manager.handle_turn("voice_r1", "I can't access my corporate account.")
    assert nxt.forward is True                      # 18. now it reaches sd_chat
    assert nxt.state is RecoveryState.SERVICEDESK_ACTIVE


def test_parse_failure_does_not_consume_an_attempt(manager, enrolled):
    manager.start("voice_r1", ALICE)
    for _ in range(6):
        manager.handle_turn("voice_r1", "I can't find my phone")
    # Still usable: transcription noise must not lock a legitimate caller out.
    ok = manager.handle_turn("voice_r1", code_for(enrolled))
    assert ok.state is RecoveryState.OTP_VERIFIED


def test_locked_session_cannot_be_recovered_by_a_valid_code(manager, enrolled):
    manager.start("voice_r1", ALICE)
    for _ in range(MAX_FAILURES + 1):
        manager.handle_turn("voice_r1", "000000")
    result = manager.handle_turn("voice_r1", code_for(enrolled))
    assert result.forward is False
    assert manager.get("voice_r1").state is RecoveryState.FAILED_LOCKED


def test_unknown_call_id_is_refused(manager):
    assert manager.handle_turn("voice_never_started", "482169").forward is False


def test_recovery_persona_uses_the_existing_contract(manager, enrolled):
    manager.start("voice_r1", ALICE)
    manager.handle_turn("voice_r1", code_for(enrolled))
    persona = recovery_persona(manager.get("voice_r1").verified_identity)
    assert persona["userPrincipalName"] == ALICE       # -> identity.upn
    assert persona["identity_source"] == "recovery_totp"
    assert persona["recovery_scope"] == "self_account_recovery"


# --------------------------------------------- 14. no OTP in the logs -----

def test_raw_and_normalised_otp_never_reach_the_logs(manager, enrolled, caplog):
    code = code_for(enrolled)
    spoken = " ".join({"0": "zero", "1": "one", "2": "two", "3": "three",
                       "4": "four", "5": "five", "6": "six", "7": "seven",
                       "8": "eight", "9": "nine"}[d] for d in code)
    manager.start("voice_r1", ALICE)
    with caplog.at_level(logging.DEBUG, logger="voice_gateway"):
        manager.handle_turn("voice_r1", spoken)
        manager.handle_turn("voice_r1", "000000")
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert code not in blob, "normalised OTP leaked into logs"
    assert spoken not in blob, "raw utterance leaked into logs"
    assert enrolled not in blob, "seed leaked into logs"
    assert ALICE not in blob, "UPN leaked into logs"


# ------------------------------- 10, 11. bootstrap token integrity --------

def test_forged_recovery_bootstrap_is_rejected(store, enrolled, tmp_path):
    fake = RecordingServiceDesk()
    app = _app_with(store, fake)
    with TestClient(app) as c:
        r = c.post("/recovery/start", json={
            "call_id": "voice_r1", "claimed_upn": ALICE,
            "recovery_token": mint_recovery_bootstrap("voice_r1", "a-different-secret" * 3),
        })
    assert r.status_code == 401
    assert fake.run_payloads == []


def test_recovery_bootstrap_bound_to_another_call_is_rejected(store, enrolled):
    fake = RecordingServiceDesk()
    with TestClient(_app_with(store, fake)) as c:
        r = c.post("/recovery/start", json={
            "call_id": "voice_r2", "claimed_upn": ALICE,
            "recovery_token": mint_recovery_bootstrap("voice_r1", SECRET),
        })
    assert r.status_code == 401


def test_full_identity_token_cannot_start_a_recovery_call(store, enrolled):
    """An identity assertion and a recovery bootstrap are not interchangeable."""
    fake = RecordingServiceDesk()
    with TestClient(_app_with(store, fake)) as c:
        r = c.post("/recovery/start", json={
            "call_id": "voice_r1", "claimed_upn": ALICE,
            "recovery_token": mint(ALICE, "voice_r1", SECRET),
        })
    assert r.status_code == 401


def test_recovery_start_reveals_nothing_about_enrollment(store, enrolled):
    """An enrolled and an un-enrolled account must look identical."""
    fake = RecordingServiceDesk()
    seen = set()
    with TestClient(_app_with(store, fake)) as c:
        for upn, call in ((ALICE, "voice_r1"), ("nobody@example.invalid", "voice_r2")):
            r = c.post("/recovery/start", json={
                "call_id": call, "claimed_upn": upn,
                "recovery_token": mint_recovery_bootstrap(call, SECRET),
            })
            seen.add((r.status_code, json.dumps(r.json())))
    assert len(seen) == 1, f"enrollment status is distinguishable: {seen}"


# --------------------------- 15, 17, 18. sd_chat contact boundaries -------

def _app_with(store, fake):
    settings = auth_settings()
    sd = ServiceDeskClient(
        base_url=settings.servicedesk_base_url, app_name=settings.app_name,
        user_id=settings.user_id,
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
    )
    # Injected rather than assigned onto app.state: the route handlers close
    # over the constructor argument, so a post-hoc assignment would be silently
    # ignored and the tests would exercise the real runtime store.
    return create_app(settings=settings, client=sd,
                      recovery=RecoveryManager(store=store))


def test_otp_turn_never_contacts_servicedesk_and_post_verification_does(store, enrolled):
    fake = RecordingServiceDesk()
    app = _app_with(store, fake)
    manager = app.state.recovery
    code = code_for(enrolled)

    with TestClient(app) as c:
        c.post("/recovery/start", json={
            "call_id": "voice_r1", "claimed_upn": ALICE,
            "recovery_token": mint_recovery_bootstrap("voice_r1", SECRET),
        })
        # The spoken code turn.
        r1 = c.post("/voice/turn", json={"text": " ".join(code), "call_id": "voice_r1",
                                         "voice_identity_token": ""})
        assert r1.status_code == 200
        assert fake.run_payloads == [], "the OTP turn must not reach sd_chat"
        assert fake.created_state == {}

        # The next turn is the first real ServiceDesk one.
        r2 = c.post("/voice/turn", json={"text": "I can't access my corporate account.",
                                         "call_id": "voice_r1", "voice_identity_token": ""})
        assert r2.status_code == 200
        assert len(fake.run_payloads) == 1

    # 15. the code appears nowhere in what was sent downstream.
    sent = json.dumps(fake.run_payloads) + json.dumps(fake.created_state)
    assert code not in sent
    assert enrolled not in sent

    # Persona seeded from the enrollment record, before the first turn.
    persona = fake.created_state[auth_session_id("voice_r1")]["persona"]
    assert persona["userPrincipalName"] == ALICE
    assert persona["identity_source"] == "recovery_totp"


# ------------------------- 13, 19. claimed identity cannot be swapped -----

def test_browser_supplied_upn_cannot_change_the_verified_identity(store, enrolled):
    fake = RecordingServiceDesk()
    app = _app_with(store, fake)
    with TestClient(app) as c:
        c.post("/recovery/start", json={
            "call_id": "voice_r1", "claimed_upn": ALICE,
            "recovery_token": mint_recovery_bootstrap("voice_r1", SECRET),
        })
        c.post("/voice/turn", json={"text": code_for(enrolled), "call_id": "voice_r1",
                                    "voice_identity_token": ""})
        c.post("/voice/turn", json={
            "text": "I can't access my account", "call_id": "voice_r1",
            "voice_identity_token": "", "verified_upn": BOB, "claimed_upn": BOB,
        })
    persona = fake.created_state[auth_session_id("voice_r1")]["persona"]
    assert persona["userPrincipalName"] == ALICE      # not BOB
    assert BOB not in json.dumps(fake.created_state)


def test_recovery_scope_is_marked_as_self_only(store, enrolled):
    manager = RecoveryManager(store=store)
    manager.start("voice_r1", ALICE)
    manager.handle_turn("voice_r1", code_for(enrolled))
    identity = manager.get("voice_r1").verified_identity
    assert identity["recovery_scope"] == "self_account_recovery"
    assert identity["purpose"] == "account_recovery"


# ------------------------------------------- 20. no regression -----------

def test_normal_authenticated_voice_flow_is_unchanged(store):
    """A non-recovery call still takes the ordinary signed-identity path."""
    fake = RecordingServiceDesk()
    app = _app_with(store, fake)
    with TestClient(app) as c:
        r = c.post("/voice/turn", json={
            "text": "Hello", "call_id": "voice_normal",
            "voice_identity_token": mint("employee@example.com", "voice_normal", SECRET),
        })
    assert r.status_code == 200
    persona = fake.created_state[auth_session_id("voice_normal")]["persona"]
    assert persona["identity_source"] == "entra_portal_voice"
    assert persona["userPrincipalName"] == "employee@example.com"


# ------------------------- enrollment authorisation (bridge exposure) -----

def test_enrollment_requires_the_admin_key(store, tmp_path):
    """The gateway's bridge address is reachable by every container on the
    host, including Dograh. Enrollment must not be open to them."""
    fake = RecordingServiceDesk()
    with TestClient(_app_with(store, fake)) as c:
        for path, body in (
            ("/recovery/enroll/begin", {"upn": ALICE, "display_name": "A"}),
            ("/recovery/enroll/confirm", {"upn": ALICE, "code": "123456"}),
        ):
            assert c.post(path, json=body).status_code == 403
            assert c.post(path, json=body,
                          headers={"X-Recovery-Admin-Key": "wrong"}).status_code == 403


def test_enrollment_admin_key_is_derived_not_the_store_key():
    from cryptography.fernet import Fernet
    from voice_gateway.recovery_store import enrollment_admin_key
    key = Fernet.generate_key()
    derived = enrollment_admin_key(key)
    assert derived != key.decode()
    assert enrollment_admin_key(key) == derived          # deterministic
    assert enrollment_admin_key(Fernet.generate_key()) != derived
