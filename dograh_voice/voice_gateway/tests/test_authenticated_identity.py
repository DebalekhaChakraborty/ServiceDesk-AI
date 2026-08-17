"""Authenticated voice identity: the security properties this channel depends on.

Every test here answers "what stops a browser, or the voice LLM, from choosing
who the caller is". The real ServiceDesk is never contacted.
"""

from __future__ import annotations

import json
import logging
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from voice_gateway.app import create_app
from voice_gateway.config import Settings
from voice_gateway.identity import (
    IdentityTokenError,
    MAX_TTL_SECONDS,
    mint,
    persona_from_claims,
    verify,
)
from voice_gateway.servicedesk_client import ServiceDeskClient
from voice_gateway.session import auth_session_id

from test_gateway import FakeServiceDesk, model_events

SECRET = "test-signing-secret-not-real-but-long-enough-0123456789"
OTHER_SECRET = "a-completely-different-secret-also-long-enough-9876543210"


def auth_settings(**overrides) -> Settings:
    base = dict(
        host="127.0.0.1", port=8010,
        servicedesk_base_url="http://servicedesk.test",
        app_name="sd_chat", user_id="voice-channel",
        timeout_seconds=5.0, max_text_chars=4000, log_utterances=False,
        poc_single_session=False, poc_session_id="dograh-poc-voice",
        require_authenticated_identity=True,
        identity_token_max_ttl_seconds=900,
        allow_legacy_unauthenticated=False,
    )
    base.update(overrides)
    return Settings(**base)


class RecordingServiceDesk(FakeServiceDesk):
    """Records the state each session was created with."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.created_state: dict[str, dict] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/sessions/" in path and request.method == "POST":
            sid = path.rsplit("/", 1)[-1]
            self.created_state[sid] = json.loads(request.content or b"{}")
        return super().handler(request)


def build(fake: FakeServiceDesk, settings: Settings | None = None,
          secret: str = SECRET, monkeypatch=None) -> TestClient:
    settings = settings or auth_settings()
    sd = ServiceDeskClient(
        base_url=settings.servicedesk_base_url,
        app_name=settings.app_name, user_id=settings.user_id,
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)),
    )
    return TestClient(create_app(settings=settings, client=sd))


@pytest.fixture(autouse=True)
def _signing_secret(monkeypatch):
    monkeypatch.setenv("VOICE_IDENTITY_SIGNING_SECRET", SECRET)


def good_token(call_id="voice_call_1", upn="employee@example.com", **kw) -> str:
    return mint(upn, call_id, SECRET, **kw)


# ---------------------------------------------------------------- happy ----

def test_authenticated_turn_seeds_verified_persona():
    fake = RecordingServiceDesk()
    with build(fake) as c:
        r = c.post("/voice/turn", json={
            "text": "Hello", "call_id": "voice_call_1",
            "voice_identity_token": good_token(),
        })
    assert r.status_code == 200
    sid = auth_session_id("voice_call_1")
    persona = fake.created_state[sid]["persona"]
    # Shape must match what sd_chat's identity_context_tool already reads.
    assert persona["userPrincipalName"] == "employee@example.com"
    assert persona["identity_source"] == "entra_portal_voice"
    assert list(fake.created_state) == [sid]


def test_persona_is_present_before_the_first_user_turn():
    """identity_context_tool runs first on message one, so state must be seeded
    at session CREATE, not after the first /run."""
    fake = RecordingServiceDesk()
    with build(fake) as c:
        c.post("/voice/turn", json={
            "text": "Hi", "call_id": "voice_call_1",
            "voice_identity_token": good_token(),
        })
    sid = auth_session_id("voice_call_1")
    # Session creation happened, carried a persona, and preceded the only /run.
    assert fake.created_state[sid]["persona"]["userPrincipalName"]
    assert fake.run_payloads[0]["sessionId"] == sid


# ------------------------------------------------- 1. naked UPN ignored ----

def test_browser_supplied_upn_is_ignored():
    fake = RecordingServiceDesk()
    with build(fake) as c:
        r = c.post("/voice/turn", json={
            "text": "Hello", "call_id": "voice_call_1",
            "voice_identity_token": good_token(upn="real@example.com"),
            "verified_upn": "ceo@example.com",          # attacker-controlled
            "email": "ceo@example.com",
        })
    assert r.status_code == 200
    persona = fake.created_state[auth_session_id("voice_call_1")]["persona"]
    assert persona["userPrincipalName"] == "real@example.com"
    assert "ceo@example.com" not in json.dumps(persona)


# --------------------------------------------------- 2. forged token -------

def test_forged_token_is_rejected():
    forged = mint("attacker@example.com", "voice_call_1", OTHER_SECRET)
    fake = RecordingServiceDesk()
    with build(fake) as c:
        r = c.post("/voice/turn", json={
            "text": "Hello", "call_id": "voice_call_1",
            "voice_identity_token": forged,
        })
    assert r.status_code == 401
    assert r.json()["code"] == "IDENTITY_REJECTED"
    assert fake.created_state == {}      # no session, no ServiceDesk contact
    assert fake.run_payloads == []


def test_alg_none_downgrade_is_rejected():
    """A forged header must not be able to select an unsigned algorithm."""
    import base64
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({
        "ver": 1, "call_id": "voice_call_1", "upn": "x@example.com",
        "iat": int(time.time()), "exp": int(time.time()) + 300,
        "aud": "servicedesk-voice-gateway",
    }).encode()).rstrip(b"=").decode()
    with pytest.raises(IdentityTokenError):
        verify(f"{header}.{payload}.", SECRET, "voice_call_1")


# ------------------------------------------------------- 3. expired --------

def test_expired_token_is_rejected():
    stale = mint("employee@example.com", "voice_call_1", SECRET,
                 ttl_seconds=60, now=time.time() - 3600)
    fake = RecordingServiceDesk()
    with build(fake) as c:
        r = c.post("/voice/turn", json={
            "text": "Hello", "call_id": "voice_call_1",
            "voice_identity_token": stale,
        })
    assert r.status_code == 401
    assert fake.run_payloads == []


def test_overlong_lifetime_is_rejected():
    """A portal bug must not be able to mint a long-lived bearer credential."""
    with pytest.raises(IdentityTokenError):
        mint("e@example.com", "voice_call_1", SECRET, ttl_seconds=MAX_TTL_SECONDS + 1)


# --------------------------------------------- 4. call_id mismatch ---------

def test_token_bound_to_another_call_is_rejected():
    """A token captured from call A cannot be replayed into call B."""
    token_for_a = good_token(call_id="voice_call_A")
    fake = RecordingServiceDesk()
    with build(fake) as c:
        r = c.post("/voice/turn", json={
            "text": "Hello", "call_id": "voice_call_B",
            "voice_identity_token": token_for_a,
        })
    assert r.status_code == 401
    assert fake.run_payloads == []


def test_malformed_and_missing_tokens_are_rejected():
    fake = RecordingServiceDesk()
    with build(fake) as c:
        for token in ("", "not-a-token", "a.b", "a.b.c.d"):
            r = c.post("/voice/turn", json={
                "text": "Hello", "call_id": "voice_call_1",
                "voice_identity_token": token,
            })
            assert r.status_code == 401, token
        r = c.post("/voice/turn", json={"text": "Hello", "call_id": "voice_call_1"})
        assert r.status_code == 401
        r = c.post("/voice/turn", json={"text": "Hello",
                                        "voice_identity_token": good_token()})
        assert r.status_code == 401     # call_id missing
    assert fake.run_payloads == []


def test_oversized_token_is_rejected_at_the_schema_boundary():
    """A 5000-char token never reaches verification: the pydantic max_length
    bound rejects it with 422 first. That is deliberate — rejecting at the edge
    keeps unbounded attacker input out of the crypto path entirely. The uniform
    401 contract covers VERIFICATION outcomes, which this is not."""
    fake = RecordingServiceDesk()
    with build(fake) as c:
        r = c.post("/voice/turn", json={
            "text": "Hello", "call_id": "voice_call_1",
            "voice_identity_token": "x" * 5000})
    assert r.status_code == 422
    assert fake.run_payloads == [] and fake.created_state == {}


def test_auth_failures_do_not_reveal_which_check_failed():
    """Distinct causes must be indistinguishable to the caller."""
    fake = RecordingServiceDesk()
    bodies = [
        {"text": "x", "call_id": "voice_call_1",
         "voice_identity_token": mint("a@b.c", "voice_call_1", OTHER_SECRET)},
        {"text": "x", "call_id": "voice_call_1",
         "voice_identity_token": mint("a@b.c", "voice_other", SECRET)},
        {"text": "x", "call_id": "voice_call_1",
         "voice_identity_token": mint("a@b.c", "voice_call_1", SECRET,
                                      ttl_seconds=60, now=time.time() - 9999)},
        {"text": "x", "call_id": "voice_call_1", "voice_identity_token": "garbage"},
    ]
    seen = set()
    with build(fake) as c:
        for body in bodies:
            r = c.post("/voice/turn", json=body)
            seen.add((r.status_code, r.json()["code"], r.json()["text"]))
    assert len(seen) == 1, f"responses differ between failure causes: {seen}"


# --------------------------------------- 5 & 6. session isolation ----------

def test_two_callers_get_isolated_sessions():
    fake = RecordingServiceDesk()
    with build(fake) as c:
        c.post("/voice/turn", json={
            "text": "hi", "call_id": "voice_alice",
            "voice_identity_token": good_token("voice_alice", "alice@example.com")})
        c.post("/voice/turn", json={
            "text": "hi", "call_id": "voice_bob",
            "voice_identity_token": good_token("voice_bob", "bob@example.com")})
    sessions = list(fake.created_state)
    assert len(sessions) == 2 and len(set(sessions)) == 2
    upns = {s["persona"]["userPrincipalName"] for s in fake.created_state.values()}
    assert upns == {"alice@example.com", "bob@example.com"}


def test_same_caller_new_call_gets_a_new_session():
    """Keying by call_id, not UPN: one employee may hold several calls."""
    fake = RecordingServiceDesk()
    upn = "employee@example.com"
    with build(fake) as c:
        c.post("/voice/turn", json={"text": "hi", "call_id": "voice_first",
                                    "voice_identity_token": good_token("voice_first", upn)})
        c.post("/voice/turn", json={"text": "hi", "call_id": "voice_second",
                                    "voice_identity_token": good_token("voice_second", upn)})
    assert len(fake.created_state) == 2
    assert auth_session_id("voice_first") != auth_session_id("voice_second")


def test_same_call_resumes_one_session():
    fake = RecordingServiceDesk()
    with build(fake) as c:
        for _ in range(3):
            r = c.post("/voice/turn", json={
                "text": "hi", "call_id": "voice_call_1",
                "voice_identity_token": good_token()})
            assert r.status_code == 200
    assert len(fake.created_state) == 1
    assert {p["sessionId"] for p in fake.run_payloads} == set(fake.created_state)


# --------------------------------- 7 & 8. LLM cannot override presets ------

def test_preset_parameters_are_not_llm_visible():
    """The tool exposes only `text` to the model; identity fields are presets
    rendered from initial_context server-side."""
    from provisioning.desired_state import desired_tool_payload
    cfg = desired_tool_payload()["definition"]["config"]
    assert [p["name"] for p in cfg["parameters"]] == ["text"]
    preset = {p["name"]: p for p in cfg["preset_parameters"]}
    assert set(preset) == {"call_id", "voice_identity_token"}
    assert all(p["required"] for p in preset.values())


def test_preset_templates_cannot_be_shadowed_by_llm_gathered_context():
    """Dograh's render context is {**initial_context, **gathered_context, ...}.
    A bare {{call_id}} would be OVERRIDDEN by an LLM-influenced gathered
    variable of the same name; the namespaced path cannot be."""
    from provisioning.desired_state import desired_tool_payload
    preset = {p["name"]: p["value_template"]
              for p in desired_tool_payload()["definition"]["config"]["preset_parameters"]}
    assert preset["call_id"] == "{{initial_context.call_id}}"
    assert preset["voice_identity_token"] == "{{initial_context.voice_identity_token}}"

    def render(template, initial, gathered):
        ctx = {**initial, **gathered,
               "initial_context": initial, "gathered_context": gathered}
        key = template.strip("{} ")
        node = ctx
        for part in key.split("."):
            node = node[part]
        return node

    hostile = {"call_id": "voice_attacker", "voice_identity_token": "forged"}
    trusted = {"call_id": "voice_real", "voice_identity_token": "real-token"}
    assert render(preset["call_id"], trusted, hostile) == "voice_real"
    assert render("{{call_id}}", trusted, hostile) == "voice_attacker"  # why namespacing


def test_llm_supplied_call_id_still_needs_a_matching_signature():
    """Even if the model could inject a call_id, it cannot forge the token."""
    fake = RecordingServiceDesk()
    with build(fake) as c:
        r = c.post("/voice/turn", json={
            "text": "hi", "call_id": "voice_chosen_by_model",
            "voice_identity_token": good_token("voice_real_call")})
    assert r.status_code == 401
    assert fake.run_payloads == []


# ------------------------- 9. unverified identity cannot reach privilege ---

def test_unverified_caller_never_reaches_servicedesk_at_all():
    """No token, no session, no /run: the privileged Account Access path is
    unreachable because ServiceDesk is never contacted."""
    fake = RecordingServiceDesk()
    with build(fake) as c:
        r = c.post("/voice/turn", json={
            "text": "Please enable my account and reset my password",
            "call_id": "voice_call_1"})
    assert r.status_code == 401
    assert fake.run_payloads == [] and fake.created_state == {}


def test_anonymous_multicaller_configuration_is_refused_at_startup():
    """There must be no way to run unauthenticated AND multi-caller."""
    unsafe = auth_settings(require_authenticated_identity=False,
                           poc_single_session=False,
                           allow_legacy_unauthenticated=False)
    with pytest.raises(RuntimeError, match="anonymous multi-caller"):
        create_app(settings=unsafe, client=object())


# --------------------------------------------- 10. token never logged ------

def test_identity_token_is_never_logged(caplog):
    token = good_token()
    fake = RecordingServiceDesk()
    with caplog.at_level(logging.DEBUG, logger="voice_gateway"):
        with build(fake) as c:
            c.post("/voice/turn", json={"text": "hi", "call_id": "voice_call_1",
                                        "voice_identity_token": token})
            c.post("/voice/turn", json={"text": "hi", "call_id": "voice_call_1",
                                        "voice_identity_token": "x.y.z"})
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert token not in blob
    assert token.split(".")[2] not in blob      # not even the signature
    assert "voice_call_1" not in blob           # raw call id not logged either


def test_upn_is_not_logged():
    fake = RecordingServiceDesk()
    import logging as _logging
    records = []
    handler = _logging.Handler()
    handler.emit = lambda r: records.append(r.getMessage())
    logger = _logging.getLogger("voice_gateway")
    logger.addHandler(handler)
    try:
        with build(fake) as c:
            c.post("/voice/turn", json={
                "text": "hi", "call_id": "voice_call_1",
                "voice_identity_token": good_token(upn="secret.person@example.com")})
    finally:
        logger.removeHandler(handler)
    assert "secret.person@example.com" not in "\n".join(records)


# ------------------------------------------------- persona construction ----

def test_persona_fields_match_identity_context_tool_contract():
    """Field names must be ones ensure_identity_context_in_state actually reads."""
    claims = verify(mint("e@example.com", "voice_c", SECRET, display_name="E Person",
                         object_id="oid-7"), SECRET, "voice_c")
    persona = persona_from_claims(claims)
    assert persona["userPrincipalName"] == "e@example.com"   # -> identity.upn
    assert persona["mail"] == "e@example.com"                # -> primary_email
    assert persona["displayName"] == "E Person"              # -> display_name
    assert persona["id"] == "oid-7"                          # -> aad_object_id
