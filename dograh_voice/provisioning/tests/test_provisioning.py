"""Provisioning tests. The real Dograh API is never contacted.

Fixture shapes mirror the live v1.45.0 deployment: workflow nodes are
`startCall` and carry attached tools in `tool_uuids`, and model configuration
is the organization V2 envelope, not the derived user-level view.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest

from provisioning import configure_agent, configure_tool
from provisioning.configure_models import (
    DograhFallbackDetected,
    active_dograh_providers,
    apply as apply_models,
    inactive_dograh_providers,
)
from provisioning.dograh_client import DograhClient, redact
from provisioning.desired_state import (
    TOOL_NAME,
    VERTEX_LLM_LOCATION,
    VERTEX_REALTIME_LOCATION,
    desired_model_config,
    desired_tool_payload,
    find_dograh_providers,
    vertex_services,
)

PROV_DIR = Path(__file__).resolve().parents[1]

DOGRAH_V2 = {
    "configuration": {"version": 2, "mode": "dograh",
                      "dograh": {"api_key": "x", "voice": "default"}},
    "effective_configuration": {
        "llm": {"provider": "dograh"}, "tts": {"provider": "dograh"},
        "stt": {"provider": "dograh"}, "embeddings": {"provider": "dograh"},
        "realtime": None, "is_realtime": False,
    },
    "source": "organization_v2",
}


def effective_for(config: dict) -> dict:
    """What Dograh derives for a byok/realtime configuration."""
    rt = (config.get("byok") or {}).get("realtime") or {}
    return {"llm": rt.get("llm"), "realtime": rt.get("realtime"),
            "tts": None, "stt": None, "embeddings": None, "is_realtime": True}


class FakeDograh:
    """In-memory stand-in for the Dograh REST API."""

    def __init__(self, tools=None, v2=None, workflows=None, definitions=None):
        self.tools = list(tools or [])
        self.v2 = copy.deepcopy(v2 or DOGRAH_V2)
        self.workflows = workflows or []
        self.definitions = definitions or {}
        self.created, self.updated = [], []
        self.config_puts, self.workflow_puts = [], []

    def handler(self, request: httpx.Request) -> httpx.Response:
        p, m = request.url.path, request.method
        if p == "/api/v1/tools/" and m == "GET":
            return httpx.Response(200, json=self.tools)
        if p == "/api/v1/tools/" and m == "POST":
            body = json.loads(request.content)
            body["tool_uuid"] = "uuid-new"
            self.tools.append(body)
            self.created.append(body)
            return httpx.Response(200, json=body)
        if p.startswith("/api/v1/tools/") and m == "PUT":
            self.updated.append(json.loads(request.content))
            return httpx.Response(200, json={"tool_uuid": p.rsplit("/", 1)[-1]})
        if p == "/api/v1/organizations/model-configurations/v2" and m == "GET":
            return httpx.Response(200, json=self.v2)
        if p == "/api/v1/organizations/model-configurations/v2" and m == "PUT":
            body = json.loads(request.content)
            self.config_puts.append(body)
            self.v2 = {"configuration": body,
                       "effective_configuration": effective_for(body),
                       "source": "organization_v2"}
            return httpx.Response(200, json=self.v2)
        if p == "/api/v1/workflow/fetch" and m == "GET":
            return httpx.Response(200, json=self.workflows)
        if p.startswith("/api/v1/workflow/fetch/"):
            return httpx.Response(200, json=self.definitions[p.rsplit("/", 1)[-1]])
        if p.endswith("/validate") and m == "POST":
            return httpx.Response(200, json={"valid": True})
        if p.startswith("/api/v1/workflow/") and m == "PUT":
            self.workflow_puts.append(json.loads(request.content))
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={})


def client_for(fake: FakeDograh) -> DograhClient:
    return DograhClient(
        base_url="http://dograh.test",
        api_key="test-key-not-real",
        client=httpx.Client(transport=httpx.MockTransport(fake.handler)),
    )


# ---------------------------------------------------------------- tool ----

def test_creates_tool_when_absent():
    fake = FakeDograh(tools=[])
    r = configure_tool.apply(client_for(fake))
    assert r["action"] == "create"
    assert len(fake.created) == 1
    assert fake.created[0]["name"] == TOOL_NAME


def test_second_run_is_noop_and_creates_no_duplicate():
    fake = FakeDograh(tools=[])
    configure_tool.apply(client_for(fake))
    r = configure_tool.apply(client_for(fake))
    assert r["action"] == "noop"
    assert len(fake.created) == 1
    assert len([t for t in fake.tools if t["name"] == TOOL_NAME]) == 1


def test_updates_only_when_configuration_differs():
    existing = copy.deepcopy(desired_tool_payload())
    existing["tool_uuid"] = "uuid-1"
    existing["definition"]["config"]["url"] = "http://stale.invalid/voice/turn"
    fake = FakeDograh(tools=[existing])
    r = configure_tool.apply(client_for(fake))
    assert r["action"] == "update"
    assert r["tool_uuid"] == "uuid-1"
    assert fake.updated[0]["definition"]["config"]["url"].endswith(":8010/voice/turn")


def test_update_preserves_unmanaged_config_fields():
    """A PUT built from desired state must not reset fields Dograh owns."""
    existing = copy.deepcopy(desired_tool_payload())
    existing["tool_uuid"] = "uuid-1"
    existing["definition"]["config"]["timeout_ms"] = 500000
    existing["definition"]["config"]["credential_uuid"] = "cred-123"
    existing["definition"]["config"]["body_template"] = "{{keep}}"
    fake = FakeDograh(tools=[existing])
    configure_tool.apply(client_for(fake))
    sent = fake.updated[0]["definition"]["config"]
    assert sent["timeout_ms"] == 120000          # managed: corrected
    assert sent["credential_uuid"] == "cred-123"  # unmanaged: preserved
    assert sent["body_template"] == "{{keep}}"


def test_dry_run_mutates_nothing():
    fake = FakeDograh(tools=[])
    r = configure_tool.apply(client_for(fake), dry_run=True)
    assert r["dry_run"] is True
    assert fake.created == [] and fake.updated == []


def test_tool_exposes_only_text_parameter():
    cfg = desired_tool_payload()["definition"]["config"]
    names = [p["name"] for p in cfg["parameters"]]
    assert names == ["text"]
    assert "voice_session_id" not in names


def test_tool_timeout_exceeds_dograh_default():
    """HttpApiConfig defaults to 5000ms, which would cut real ServiceDesk turns off."""
    assert desired_tool_payload()["definition"]["config"]["timeout_ms"] == 120000


# ------------------------------------------------------------- models ----

def test_desired_config_is_byok_realtime_envelope():
    cfg = desired_model_config()
    assert cfg["mode"] == "byok" and cfg["version"] == 2
    assert cfg["byok"]["mode"] == "realtime"
    assert set(cfg["byok"]["realtime"]) == {"realtime", "llm"}   # both required


def test_model_config_has_no_dograh_provider():
    assert find_dograh_providers(desired_model_config()) == []


def test_current_dograh_mode_is_detected():
    assert find_dograh_providers({"mode": "dograh"}) == ["mode=dograh"]
    assert find_dograh_providers({"llm": {"provider": "dograh"}}) == ["llm.provider=dograh"]


def test_credentials_omitted_for_adc():
    services = vertex_services(desired_model_config())
    assert len(services) == 2
    for service in services:
        assert "credentials" not in service
        assert "api_key" not in service
        assert service["project_id"] == "ai-and-automation-coe"


def test_each_service_pins_its_own_verified_location():
    """Dograh falls back to us-east4 on empty location, where both models 404
    or the realtime media path leaves the VM's region."""
    cfg = desired_model_config()["byok"]["realtime"]
    assert cfg["realtime"]["location"] == VERTEX_REALTIME_LOCATION == "us-central1"
    assert cfg["llm"]["location"] == VERTEX_LLM_LOCATION == "global"
    assert cfg["realtime"]["location"] != cfg["llm"]["location"]


def test_switch_clears_every_dograh_provider():
    fake = FakeDograh()
    assert active_dograh_providers(fake.v2["effective_configuration"])
    r = apply_models(client_for(fake))
    assert r["after_mode"] == "byok"
    assert r["active_dograh"] == [] and r["inactive_dograh"] == []


def test_model_switch_fails_closed_if_dograh_still_active():
    class Stubborn(FakeDograh):
        def handler(self, request):
            if (request.url.path == "/api/v1/organizations/model-configurations/v2"
                    and request.method == "PUT"):
                # Simulate Dograh silently retaining its managed provider.
                self.v2 = {"configuration": {"mode": "byok"},
                           "effective_configuration": {"llm": {"provider": "dograh"}}}
                return httpx.Response(200, json=self.v2)
            return super().handler(request)

    with pytest.raises(DograhFallbackDetected):
        apply_models(client_for(Stubborn()))


def test_model_switch_fails_closed_if_mode_reverts():
    class Reverting(FakeDograh):
        def handler(self, request):
            if (request.url.path == "/api/v1/organizations/model-configurations/v2"
                    and request.method == "PUT"):
                self.v2 = {"configuration": {"mode": "dograh"},
                           "effective_configuration": {}}
                return httpx.Response(200, json=self.v2)
            return super().handler(request)

    with pytest.raises(DograhFallbackDetected):
        apply_models(client_for(Reverting()))


def test_unused_slot_dograh_is_reported_not_failed():
    """Realtime mode never builds STT/TTS, so a residual value there is inert."""
    eff = {"realtime": {"provider": "google_vertex_realtime"},
           "llm": {"provider": "google_vertex"},
           "stt": {"provider": "dograh"}}
    assert active_dograh_providers(eff) == []
    assert inactive_dograh_providers(eff) == ["stt.provider=dograh"]


def test_model_dry_run_does_not_put():
    fake = FakeDograh()
    apply_models(client_for(fake), dry_run=True)
    assert fake.config_puts == []


# ------------------------------------------------------------ workflow ----

def workflow_fixture():
    """Mirrors the live workflow: a `startCall` node holding `tool_uuids`."""
    return {
        "id": 1,
        "name": "Testing",
        "workflow_definition": {
            "nodes": [
                {"id": "1", "type": "startCall",
                 "data": {"prompt": "old", "tool_uuids": [], "name": "start call",
                          "greeting_type": "text", "allow_interrupt": True}},
                {"id": "2", "type": "endCall", "data": {"message": "Bye"}},
            ],
            "edges": [{"source": "1", "target": "2"}],
            "viewport": {"x": 30.75, "y": 177.75, "zoom": 0.75},
        },
    }


def test_workflow_patch_preserves_unrelated_structure():
    wf = workflow_fixture()
    fake = FakeDograh(workflows=[{"id": 1, "name": "Testing"}], definitions={"1": wf})
    r = configure_agent.apply(client_for(fake), tool_uuid="uuid-1", workflow_id=1)
    assert r["action"] == "updated"
    sent = fake.workflow_puts[0]["workflow_definition"]
    assert len(sent["nodes"]) == 2
    assert sent["edges"] == wf["workflow_definition"]["edges"]
    assert sent["viewport"] == wf["workflow_definition"]["viewport"]
    assert sent["nodes"][0]["data"]["greeting_type"] == "text"
    assert sent["nodes"][1]["data"]["message"] == "Bye"


def test_tool_is_attached_via_tool_uuids_not_tools():
    """Dograh reads `tool_uuids`; writing `tools` would be silently ignored."""
    fake = FakeDograh(workflows=[{"id": 1, "name": "Testing"}],
                      definitions={"1": workflow_fixture()})
    configure_agent.apply(client_for(fake), tool_uuid="uuid-1", workflow_id=1)
    nodes = {n["id"]: n for n in fake.workflow_puts[0]["workflow_definition"]["nodes"]}
    assert nodes["1"]["data"]["tool_uuids"] == ["uuid-1"]
    assert "tools" not in nodes["1"]["data"]
    assert "tool_uuids" not in nodes["2"]["data"]


def test_keep_prompt_leaves_a_hand_tuned_prompt_alone():
    wf = workflow_fixture()
    wf["workflow_definition"]["nodes"][0]["data"]["prompt"] = "human written"
    fake = FakeDograh(workflows=[{"id": 1, "name": "Testing"}], definitions={"1": wf})
    configure_agent.apply(client_for(fake), tool_uuid="uuid-1", workflow_id=1,
                          set_prompt=False)
    sent = fake.workflow_puts[0]["workflow_definition"]
    assert sent["nodes"][0]["data"]["prompt"] == "human written"


def test_workflow_patch_is_idempotent():
    wf = workflow_fixture()
    wf["workflow_definition"]["nodes"][0]["data"]["tool_uuids"] = ["uuid-1"]
    wf["workflow_definition"]["nodes"][0]["data"]["prompt"] = configure_agent.AGENT_PROMPT
    fake = FakeDograh(workflows=[{"id": 1, "name": "Testing"}], definitions={"1": wf})
    r = configure_agent.apply(client_for(fake), tool_uuid="uuid-1", workflow_id=1)
    assert r["action"] == "noop"
    assert fake.workflow_puts == []


def test_ambiguous_workflow_is_refused_not_guessed():
    fake = FakeDograh(workflows=[{"id": 1, "name": "A voice"}, {"id": 2, "name": "B voice"}],
                      definitions={})
    with pytest.raises(RuntimeError, match="unambiguously"):
        configure_agent.apply(client_for(fake), tool_uuid="u", name_hint="voice")


def test_multiple_agent_nodes_require_explicit_node_id():
    wf = workflow_fixture()
    wf["workflow_definition"]["nodes"].append(
        {"id": "3", "type": "startCall", "data": {}}
    )
    fake = FakeDograh(workflows=[{"id": 1, "name": "Testing"}], definitions={"1": wf})
    with pytest.raises(RuntimeError, match="Multiple agent nodes"):
        configure_agent.apply(client_for(fake), tool_uuid="u", workflow_id=1)


def test_workflow_dry_run_does_not_put():
    fake = FakeDograh(workflows=[{"id": 1, "name": "Testing"}],
                      definitions={"1": workflow_fixture()})
    configure_agent.apply(client_for(fake), tool_uuid="u", workflow_id=1, dry_run=True)
    assert fake.workflow_puts == []


# ------------------------------------------------------------ secrets ----

def test_redact_masks_secret_fields():
    out = redact({"api_key": "abc", "credentials": {"x": 1}, "nested": {"token": "t"},
                  "url": "http://ok"})
    assert out["api_key"] == "<redacted>"
    assert out["credentials"] == "<redacted>"
    assert out["nested"]["token"] == "<redacted>"
    assert out["url"] == "http://ok"


def test_no_service_account_json_or_key_material_in_source():
    banned = ["-----BEGIN", "private_key", "service_account", "dgr_", "refresh_token"]
    for py in PROV_DIR.glob("*.py"):
        src = py.read_text()
        for term in banned:
            assert term not in src, f"{py.name} contains {term!r}"


def test_api_key_is_never_logged(capsys):
    fake = FakeDograh(tools=[])
    configure_tool.apply(client_for(fake), dry_run=True)
    out = capsys.readouterr().out
    assert "test-key-not-real" not in out
    assert "X-API-Key" not in out
