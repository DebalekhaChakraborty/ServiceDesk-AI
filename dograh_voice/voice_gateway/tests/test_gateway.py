"""Voice gateway tests.

Downstream ServiceDesk is faked with httpx.MockTransport — the real sd_chat is
never contacted, and no ServiceDesk test is touched.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from voice_gateway.app import create_app
from voice_gateway.config import Settings
from voice_gateway.servicedesk_client import ServiceDeskClient, extract_final_text
from voice_gateway.session import adk_session_id, redact_session_id

GATEWAY_DIR = Path(__file__).resolve().parents[1]


def make_settings(**overrides) -> Settings:
    base = dict(
        host="127.0.0.1",
        port=8010,
        servicedesk_base_url="http://servicedesk.test",
        app_name="sd_chat",
        user_id="voice-channel",
        timeout_seconds=5.0,
        max_text_chars=4000,
        log_utterances=False,
        poc_single_session=False,
        poc_session_id="dograh-poc-voice",
        # Existing tests cover the unauthenticated PoC paths; authenticated
        # mode has its own suite in test_authenticated_identity.py.
        require_authenticated_identity=False,
        identity_token_max_ttl_seconds=900,
        allow_legacy_unauthenticated=True,
    )
    base.update(overrides)
    return Settings(**base)


def model_events(text: str):
    """An ADK /run reply shaped like the real one: tool call, tool result, text."""
    return [
        {
            "author": "sd_chat",
            "content": {
                "role": "model",
                "parts": [{"functionCall": {"name": "resolve_identity_context", "args": {}}}],
            },
        },
        {
            "author": "sd_chat",
            "content": {
                "role": "user",
                "parts": [
                    {
                        "functionResponse": {
                            "name": "resolve_identity_context",
                            "response": {"ok": False, "source": "none"},
                        }
                    }
                ],
            },
        },
        {"author": "sd_chat", "content": {"role": "model", "parts": [{"text": text}]}},
    ]


class FakeServiceDesk:
    """Records what the gateway sent downstream."""

    def __init__(self, reply="Hello from ServiceDesk.", run_status=200, run_body=None):
        self.reply = reply
        self.run_status = run_status
        self.run_body = run_body
        self.created_sessions: list[str] = []
        self.run_payloads: list[dict] = []
        self.existing: set[str] = set()

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if path.endswith("/run"):
            payload = json.loads(request.content)
            self.run_payloads.append(payload)
            if self.run_body is not None:
                return httpx.Response(self.run_status, content=self.run_body)
            if self.run_status != 200:
                return httpx.Response(self.run_status, json={"detail": "boom"})
            return httpx.Response(200, json=model_events(self.reply))
        if "/sessions/" in path:
            sid = path.rsplit("/", 1)[-1]
            if request.method == "GET":
                return httpx.Response(200 if sid in self.existing else 404, json={})
            self.created_sessions.append(sid)
            self.existing.add(sid)
            return httpx.Response(200, json={"id": sid})
        return httpx.Response(404, json={})


def build_client(fake: FakeServiceDesk, settings: Settings | None = None) -> TestClient:
    settings = settings or make_settings()
    transport = httpx.MockTransport(fake.handler)
    sd = ServiceDeskClient(
        base_url=settings.servicedesk_base_url,
        app_name=settings.app_name,
        user_id=settings.user_id,
        client=httpx.AsyncClient(transport=transport),
    )
    return TestClient(create_app(settings=settings, client=sd))


# --------------------------------------------------------------------------
# Contract / validation
# --------------------------------------------------------------------------

def test_health_reports_downstream():
    with build_client(FakeServiceDesk()) as c:
        r = c.get("/health")
        assert r.status_code == 200
        assert r.json() == {
            "status": "ok",
            "servicedesk": "reachable",
            "poc_single_session": False,
        }


def test_happy_path_returns_servicedesk_text_verbatim():
    fake = FakeServiceDesk(reply="I can help with account access.")
    with build_client(fake) as c:
        r = c.post("/voice/turn", json={"voice_session_id": "call-1", "text": "Hi"})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["voice_session_id"] == "call-1"
        assert body["text"] == "I can help with account access."


def test_empty_utterance_rejected():
    fake = FakeServiceDesk()
    with build_client(fake) as c:
        r = c.post("/voice/turn", json={"voice_session_id": "call-1", "text": "   "})
        assert r.status_code == 400
        assert r.json()["code"] == "EMPTY_UTTERANCE"
        assert fake.run_payloads == []  # nothing reached ServiceDesk


def test_missing_fields_rejected():
    with build_client(FakeServiceDesk()) as c:
        assert c.post("/voice/turn", json={"text": "hi"}).status_code == 422
        assert c.post("/voice/turn", json={"voice_session_id": "x"}).status_code == 422
        assert c.post(
            "/voice/turn", json={"voice_session_id": "", "text": "hi"}
        ).status_code == 422


def test_overlong_utterance_rejected():
    fake = FakeServiceDesk()
    with build_client(fake, make_settings(max_text_chars=10)) as c:
        r = c.post("/voice/turn", json={"voice_session_id": "c", "text": "x" * 50})
        assert r.status_code == 400
        assert r.json()["code"] == "UTTERANCE_TOO_LONG"
        assert fake.run_payloads == []


# --------------------------------------------------------------------------
# Session continuity — the critical requirement
# --------------------------------------------------------------------------

def test_same_voice_session_reuses_one_servicedesk_session():
    fake = FakeServiceDesk()
    with build_client(fake) as c:
        for utterance in ("I cannot access my account.", "Yes."):
            assert c.post(
                "/voice/turn",
                json={"voice_session_id": "dograh-call-abc123", "text": utterance},
            ).status_code == 200

    assert len(fake.run_payloads) == 2
    ids = {p["sessionId"] for p in fake.run_payloads}
    assert len(ids) == 1, "both turns must land on the same ServiceDesk session"
    assert len(fake.created_sessions) == 1, "session must be created only once"


def test_different_voice_sessions_are_isolated():
    fake = FakeServiceDesk()
    with build_client(fake) as c:
        c.post("/voice/turn", json={"voice_session_id": "call-A", "text": "hi"})
        c.post("/voice/turn", json={"voice_session_id": "call-B", "text": "hi"})

    ids = [p["sessionId"] for p in fake.run_payloads]
    assert ids[0] != ids[1]
    assert len(fake.created_sessions) == 2


def test_session_mapping_is_deterministic_and_collision_safe():
    assert adk_session_id("call-1") == adk_session_id("call-1")
    # Distinct ids that normalise to the same readable form must stay distinct.
    assert adk_session_id("call/1") != adk_session_id("call:1")
    assert adk_session_id("call-1").startswith("voice-")
    with pytest.raises(ValueError):
        adk_session_id("   ")


def test_gateway_reuses_existing_servicedesk_session_without_recreating():
    fake = FakeServiceDesk()
    fake.existing.add(adk_session_id("resumed-call"))
    with build_client(fake) as c:
        c.post("/voice/turn", json={"voice_session_id": "resumed-call", "text": "hi"})
    assert fake.created_sessions == [], "must not recreate an existing session"


# --------------------------------------------------------------------------
# Downstream failure handling
# --------------------------------------------------------------------------

def test_downstream_timeout_is_structured():
    def handler(request):
        if request.url.path == "/health":
            return httpx.Response(200, json={})
        raise httpx.TimeoutException("timed out", request=request)

    sd = ServiceDeskClient(
        "http://servicedesk.test", "sd_chat", "voice-channel",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with TestClient(create_app(settings=make_settings(), client=sd)) as c:
        r = c.post("/voice/turn", json={"voice_session_id": "c", "text": "hi"})
        assert r.status_code == 502
        assert r.json()["code"] == "SERVICEDESK_TIMEOUT"


def test_downstream_connection_error_is_structured():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    sd = ServiceDeskClient(
        "http://servicedesk.test", "sd_chat", "voice-channel",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with TestClient(create_app(settings=make_settings(), client=sd)) as c:
        r = c.post("/voice/turn", json={"voice_session_id": "c", "text": "hi"})
        assert r.status_code == 502
        assert r.json()["code"] == "SERVICEDESK_UNAVAILABLE"


def test_downstream_non_200_is_structured():
    with build_client(FakeServiceDesk(run_status=500)) as c:
        r = c.post("/voice/turn", json={"voice_session_id": "c", "text": "hi"})
        assert r.status_code == 502
        assert r.json()["code"] == "SERVICEDESK_BAD_STATUS"


def test_malformed_downstream_body_is_structured():
    with build_client(FakeServiceDesk(run_body=b"not json")) as c:
        r = c.post("/voice/turn", json={"voice_session_id": "c", "text": "hi"})
        assert r.status_code == 502
        assert r.json()["code"] == "SERVICEDESK_MALFORMED_RESPONSE"


def test_events_without_model_text_are_malformed():
    with build_client(FakeServiceDesk(run_body=json.dumps([]).encode())) as c:
        r = c.post("/voice/turn", json={"voice_session_id": "c", "text": "hi"})
        assert r.json()["code"] == "SERVICEDESK_MALFORMED_RESPONSE"


def test_error_bodies_never_leak_internals():
    with build_client(FakeServiceDesk(run_status=500)) as c:
        body = c.post("/voice/turn", json={"voice_session_id": "c", "text": "hi"}).text
    lowered = body.lower()
    for leak in ("traceback", "httpx", "file \"", "servicedesk.test", "boom", "/run"):
        assert leak not in lowered


def test_extract_final_text_picks_last_model_text():
    assert extract_final_text(model_events("final")) == "final"
    assert extract_final_text([]) is None
    assert extract_final_text("nonsense") is None
    # role=user tool results must never be mistaken for the reply
    assert extract_final_text(
        [{"content": {"role": "user", "parts": [{"text": "user said"}]}}]
    ) is None


# --------------------------------------------------------------------------
# Security posture
# --------------------------------------------------------------------------

def test_only_expected_routes_exist():
    app = create_app(settings=make_settings(), client=ServiceDeskClient(
        "http://x", "sd_chat", "voice-channel",
        client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))),
    ))
    paths = {r.path for r in app.routes if hasattr(r, "path")}
    # Enumerated deliberately: this guard exists so a new route cannot appear
    # on the gateway unnoticed. The /recovery/enroll/* routes ALL require an
    # admin key, because the gateway's bridge address is reachable by every
    # container on the host - including Dograh, which runs LLM-driven tool code.
    # The duo/* pair is the active provider; the other two are the retired TOTP
    # path, kept until Duo acceptance completes.
    assert paths == {
        "/health",
        "/voice/turn",
        "/recovery/enroll/duo/begin",
        "/recovery/enroll/duo/status",
        "/recovery/enroll/begin",
        "/recovery/enroll/confirm",
        "/recovery/start",
    }, f"unexpected routes: {paths}"


def test_no_api_docs_or_schema_exposed():
    with build_client(FakeServiceDesk()) as c:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert c.get(path).status_code == 404


def test_no_privileged_tool_references_in_source():
    forbidden = [
        "enable_account", "reset_password", "graph_patch", "aad_tool",
        "ad_account_tool", "win_tool", "graph.microsoft.com", "servicenow",
    ]
    # ONE deliberate exception. graph_corroboration.py talks to Graph so a
    # Duo-verified identity can be checked against the directory before it is
    # used. Its read-only nature is asserted below rather than assumed, so this
    # exemption cannot quietly grow into a write path.
    exempt = {"graph_corroboration.py": {"graph.microsoft.com"}}

    for py in GATEWAY_DIR.glob("*.py"):
        source = py.read_text().lower()
        allowed = exempt.get(py.name, set())
        for term in forbidden:
            if term in allowed:
                continue
            assert term not in source, f"{py.name} references privileged tool {term!r}"


def test_graph_corroboration_is_read_only():
    """The gateway's only Graph capability must be a GET, and nothing else."""
    source = (GATEWAY_DIR / "graph_corroboration.py").read_text()

    # The single POST is the token request to login.microsoftonline.com; every
    # Graph call itself is a GET.
    graph_calls = [line for line in source.splitlines() if "GRAPH_BASE_URL" in line]
    assert graph_calls, "expected at least one Graph call"

    for verb in (".post(", ".patch(", ".put(", ".delete("):
        for line in source.splitlines():
            if verb in line:
                assert "login.microsoftonline.com" in source, verb
                assert "oauth2/v2.0/token" in source, verb

    # No Graph write scope is ever requested, and no mutation endpoint named.
    lowered = source.lower()
    assert ".default" in lowered
    for term in ("readwrite", "accountenabled\":", "$batch",
                 "authentication/methods", "revokesigninsessions"):
        assert term not in lowered, f"graph_corroboration.py names {term!r}"


def test_gateway_never_imports_sd_chat():
    for py in GATEWAY_DIR.glob("*.py"):
        source = py.read_text()
        assert "import sd_chat" not in source
        assert "from sd_chat" not in source


def test_wildcard_bind_is_rejected():
    assert make_settings(host="0.0.0.0").is_private_bind() is False
    assert make_settings(host="::").is_private_bind() is False
    assert make_settings(host="127.0.0.1").is_private_bind() is True
    assert make_settings(host="localhost").is_private_bind() is True
    assert make_settings(host="172.18.0.1").is_private_bind() is True  # docker bridge
    assert make_settings(host="10.128.0.2").is_private_bind() is True   # VPC NIC
    # Real globally-routable addresses must be refused. (Note 203.0.113.0/24 is
    # NOT a valid stand-in for "public" — Python classifies documentation ranges
    # as private, so a genuinely global address is required here.)
    assert make_settings(host="8.8.8.8").is_private_bind() is False
    assert make_settings(host="34.44.75.208").is_private_bind() is False  # TURN edge


def test_private_bind_uses_real_classification_not_string_prefix():
    """172.32.0.0/12 upward is PUBLIC despite starting with '172.'."""
    assert make_settings(host="172.31.255.254").is_private_bind() is True
    assert make_settings(host="172.32.0.1").is_private_bind() is False
    assert make_settings(host="not-an-ip").is_private_bind() is False


# --------------------------------------------------------------------------
# PoC single-session mode
# --------------------------------------------------------------------------

def poc_settings(**kw):
    return make_settings(poc_single_session=True, **kw)


def test_poc_mode_accepts_body_with_only_text():
    fake = FakeServiceDesk()
    with build_client(fake, poc_settings()) as c:
        r = c.post("/voice/turn", json={"text": "Hello, what can you help me with?"})
        assert r.status_code == 200
        assert r.json()["voice_session_id"] == "dograh-poc-voice"
    assert len(fake.run_payloads) == 1


def test_poc_mode_pins_every_turn_to_one_servicedesk_session():
    fake = FakeServiceDesk()
    with build_client(fake, poc_settings()) as c:
        for t in ("Hello", "What did I just say?", "Thanks"):
            assert c.post("/voice/turn", json={"text": t}).status_code == 200
    ids = {p["sessionId"] for p in fake.run_payloads}
    assert len(ids) == 1
    assert ids.pop() == adk_session_id("dograh-poc-voice")
    assert len(fake.created_sessions) == 1


def test_poc_mode_ignores_any_caller_supplied_session_id():
    """The LLM must never be able to steer which conversation a turn joins."""
    fake = FakeServiceDesk()
    with build_client(fake, poc_settings()) as c:
        c.post("/voice/turn", json={"text": "hi", "voice_session_id": "llm-invented-id"})
    assert fake.run_payloads[0]["sessionId"] == adk_session_id("dograh-poc-voice")


def test_non_poc_mode_still_requires_a_session_id():
    fake = FakeServiceDesk()
    with build_client(fake) as c:
        r = c.post("/voice/turn", json={"text": "hi"})
        assert r.status_code == 422
        assert r.json()["code"] == "MISSING_VOICE_SESSION_ID"
    assert fake.run_payloads == []


def test_health_surfaces_poc_mode():
    with build_client(FakeServiceDesk(), poc_settings()) as c:
        assert c.get("/health").json()["poc_single_session"] is True


def test_concurrent_turn_fails_closed_rather_than_sharing():
    """A second overlapping turn must be refused, never merged into the first.

    Driven through ASGITransport in one event loop. TestClient serialises
    requests, so it cannot express genuine overlap and would pass vacuously.
    """
    import asyncio

    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/health":
                return httpx.Response(200, json={})
            if path.endswith("/run"):
                entered.set()
                await release.wait()
                return httpx.Response(200, json=model_events("slow reply"))
            if "/sessions/" in path:
                return httpx.Response(
                    200 if request.method == "POST" else 404, json={}
                )
            return httpx.Response(404, json={})

        sd = ServiceDeskClient(
            "http://servicedesk.test", "sd_chat", "voice-channel",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        app = create_app(settings=poc_settings(), client=sd)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gw"
        ) as ac:
            first = asyncio.create_task(ac.post("/voice/turn", json={"text": "one"}))
            await asyncio.wait_for(entered.wait(), timeout=5)
            second = await ac.post("/voice/turn", json={"text": "two"})
            release.set()
            return await first, second

    r1, r2 = asyncio.run(scenario())
    assert r2.status_code == 409
    assert r2.json()["code"] == "CONCURRENT_TURN_REJECTED"
    assert r1.status_code == 200, "the first turn must still succeed"


def test_unverified_identity_assertion_is_not_forwarded():
    fake = FakeServiceDesk()
    with build_client(fake) as c:
        r = c.post("/voice/turn", json={
            "voice_session_id": "call-1",
            "text": "hi",
            "verified_upn": "ceo@example.com",
        })
        assert r.status_code == 200

    payload = fake.run_payloads[0]
    blob = json.dumps(payload).lower()
    assert "ceo@example.com" not in blob
    assert payload["userId"] == "voice-channel"  # constant channel namespace
    assert payload["newMessage"]["parts"][0]["text"] == "hi"  # text unaltered


def test_session_state_is_never_seeded_with_a_persona():
    """Creating a session with non-empty state would change identity behaviour."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/health":
            return httpx.Response(200, json={})
        if "/sessions/" in path and request.method == "POST":
            captured["state"] = json.loads(request.content)
            return httpx.Response(200, json={})
        if "/sessions/" in path:
            return httpx.Response(404, json={})
        return httpx.Response(200, json=model_events("ok"))

    sd = ServiceDeskClient(
        "http://servicedesk.test", "sd_chat", "voice-channel",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with TestClient(create_app(settings=make_settings(), client=sd)) as c:
        c.post("/voice/turn", json={"voice_session_id": "c", "text": "hi"})
    assert captured["state"] == {}


def test_logs_contain_no_utterance_or_raw_session_id(caplog):
    fake = FakeServiceDesk()
    secret_utterance = "my password is hunter2"
    with caplog.at_level(logging.DEBUG, logger="voice_gateway"):
        with build_client(fake) as c:
            c.post("/voice/turn", json={
                "voice_session_id": "dograh-call-secret",
                "text": secret_utterance,
            })
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert secret_utterance not in blob
    assert "hunter2" not in blob
    assert "dograh-call-secret" not in blob        # raw id never logged
    assert redact_session_id("dograh-call-secret") in blob  # hashed handle is


# --------------------------------------------------------------------------
# Stale session registry — self-recovery
#
# The registry is a cache, so it goes stale whenever something outside this
# process removes the ADK session (operator cleanup, ADK restart with
# in-memory storage, session TTL). Before this was handled, the gateway
# skipped the existence check, POSTed /run against a dead session, and turned
# ADK's 404 into a 502 SERVICEDESK_BAD_STATUS on every subsequent turn.
# --------------------------------------------------------------------------

class VanishingServiceDesk(FakeServiceDesk):
    """A ServiceDesk whose session can be deleted behind the gateway's back."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.run_attempts = 0
        self.always_missing = False

    def vanish(self) -> None:
        """Delete every session, exactly as an external cleanup would."""
        self.existing.clear()

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/run"):
            self.run_attempts += 1
            payload = json.loads(request.content)
            self.run_payloads.append(payload)
            sid = payload["sessionId"]
            if self.always_missing or sid not in self.existing:
                return httpx.Response(
                    404, json={"detail": f"Session not found: {sid}"}
                )
            return httpx.Response(200, json=model_events(self.reply))
        return super().handler(request)


def test_stale_registry_self_recovers_exactly_once():
    fake = VanishingServiceDesk()
    with build_client(fake) as c:
        first = c.post("/voice/turn", json={"voice_session_id": "call-1", "text": "hi"})
        assert first.status_code == 200
        assert len(fake.created_sessions) == 1

        # The session disappears downstream; the registry still believes in it.
        fake.vanish()

        second = c.post("/voice/turn", json={"voice_session_id": "call-1", "text": "again"})

    assert second.status_code == 200
    assert second.json()["text"] == fake.reply
    # Recreated once, and the retry was a single extra /run (2 for this turn).
    assert len(fake.created_sessions) == 2
    assert fake.run_attempts == 3


def test_persistent_session_loss_fails_without_looping():
    fake = VanishingServiceDesk()
    fake.always_missing = True
    with build_client(fake) as c:
        r = c.post("/voice/turn", json={"voice_session_id": "call-2", "text": "hi"})

    assert r.status_code == 502
    assert r.json()["code"] == "SERVICEDESK_SESSION_LOST"
    # Exactly one retry: two attempts total, never an unbounded loop.
    assert fake.run_attempts == 2


def test_non_404_errors_are_not_treated_as_session_loss():
    """A 500 must stay BAD_STATUS — never silently retried as session loss."""
    for status in (400, 403, 429, 500, 503):
        fake = FakeServiceDesk(run_status=status)
        with build_client(fake) as c:
            r = c.post("/voice/turn", json={"voice_session_id": "call-3", "text": "hi"})
        assert r.status_code == 502
        assert r.json()["code"] == "SERVICEDESK_BAD_STATUS", status
        assert len(fake.created_sessions) == 1      # no recreate attempt
        assert len(fake.run_payloads) == 1          # no retry


def test_recovered_turn_reuses_the_same_session_id():
    """Recovery must not invent a new conversation id."""
    fake = VanishingServiceDesk()
    with build_client(fake) as c:
        c.post("/voice/turn", json={"voice_session_id": "call-4", "text": "hi"})
        fake.vanish()
        c.post("/voice/turn", json={"voice_session_id": "call-4", "text": "again"})
    assert len(set(fake.created_sessions)) == 1
    assert {p["sessionId"] for p in fake.run_payloads} == set(fake.created_sessions)
