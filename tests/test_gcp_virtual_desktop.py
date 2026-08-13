import inspect
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


os.environ.setdefault("WINRM_PORT", "5986")

from sd_chat.agent import root_agent, sd_chat
from sd_chat.planner import reasoning_composer
from sd_chat.tools import gcp_virtual_desktop_cleanup as cleanup_tool
from sd_chat.tools import gcp_virtual_desktop_tool as gcp_tool


CALLER_UPN = "fake.caller@example.test"


def _context(upn=CALLER_UPN):
    state = {} if upn is None else {"identity_context": {"upn": upn}}
    return SimpleNamespace(state=state)


def _write_mapping(path: Path, payload=None):
    if payload is None:
        payload = {
            CALLER_UPN: {
                "project_id": "fake-vdi-project",
                "zone": "us-central1-b",
                "instance_name": "fake-assigned-vdi",
                "windows_username": "fakeuser",
            }
        }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _safe_plan(issue_type="login", preconditions=None):
    spec = gcp_tool._ORCHESTRATION_SPECS[issue_type]
    return {
        "status": "ok",
        "plan": {
            "required_inputs": [],
            "preconditions": list(preconditions or []),
            "tool_sequence": [
                {
                    "tool": spec["tool"],
                    "action": spec["action"],
                    "action_id": spec["action_id"],
                    "args": {"target_upn": "${target_upn}"},
                }
            ],
            "unmapped": [],
            "can_execute_fully": True,
            "low_confidence": False,
            "confidence": 0.99,
        },
    }


@pytest.fixture(autouse=True)
def demo_environment(monkeypatch, tmp_path):
    mapping_path = _write_mapping(tmp_path / "mapping.json")
    monkeypatch.setenv("GCP_VDI_MODE", "demo")
    monkeypatch.setenv("GCP_VDI_MAPPING_PATH", str(mapping_path))
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", "running_healthy")
    monkeypatch.delenv("GCP_VDI_DEMO_FIXTURE_PATH", raising=False)
    monkeypatch.setattr(
        gcp_tool,
        "_sop_retriever",
        lambda **kwargs: {
            "status": "ok",
            "snippets": ["Approved read-only GCP virtual desktop diagnosis."],
            "meta": {"results_count": 1},
        },
    )

    def planner(**kwargs):
        issue_type = next(
            name
            for name, spec in gcp_tool._ORCHESTRATION_SPECS.items()
            if kwargs["user_text"] == spec["step"]
        )
        return _safe_plan(issue_type)

    monkeypatch.setattr(gcp_tool, "_propose_plan", planner)
    monkeypatch.setattr(
        gcp_tool,
        "_check_list",
        lambda **kwargs: {"status": "ok", "details": {}},
    )
    return mapping_path


def _login(tool_context=None):
    return gcp_tool.gcp_diagnose_virtual_desktop_login.func(
        CALLER_UPN,
        tool_context or _context(),
    )


def _performance(tool_context=None):
    return gcp_tool.gcp_diagnose_virtual_desktop_performance.func(
        CALLER_UPN,
        tool_context or _context(),
    )


def _cleanup(tool_context):
    return gcp_tool.gcp_confirm_virtual_desktop_system_file_cleanup.func(tool_context)


@pytest.mark.parametrize(
    ("call_tool", "issue_type"),
    [(_login, "login"), (_performance, "performance")],
)
def test_controller_enforces_sop_plan_policy_before_backend(
    monkeypatch,
    call_tool,
    issue_type,
):
    calls = []
    expected = gcp_tool._ORCHESTRATION_SPECS[issue_type]

    def retrieve(**kwargs):
        calls.append(("sop", kwargs))
        return {"status": "ok", "snippets": ["retrieved"], "meta": {"results_count": 2}}

    def plan(**kwargs):
        calls.append(("plan", kwargs))
        return _safe_plan(issue_type, ["verbatim_policy_condition"])

    def policy(**kwargs):
        calls.append(("policy", kwargs))
        return {"status": "ok", "details": {}}

    original_backend = gcp_tool._load_demo_snapshot

    def backend(mapping):
        calls.append(("backend", mapping))
        return original_backend(mapping)

    monkeypatch.setattr(gcp_tool, "_sop_retriever", retrieve)
    monkeypatch.setattr(gcp_tool, "_propose_plan", plan)
    monkeypatch.setattr(gcp_tool, "_check_list", policy)
    monkeypatch.setattr(gcp_tool, "_load_demo_snapshot", backend)

    result = call_tool()

    assert [name for name, _ in calls] == ["sop", "plan", "policy", "backend"]
    assert calls[1][1] == {
        "user_text": expected["step"],
        "ctx_vars": ["target_upn"],
        "sop_texts": [expected["step"]],
    }
    assert calls[2][1]["preconditions"] == ["verbatim_policy_condition"]
    assert calls[2][1]["caller_upn"] == CALLER_UPN
    assert calls[2][1]["target_upn"] == CALLER_UPN
    assert result["orchestration"] == {
        "sop_retrieved": True,
        "sop_results_count": 2,
        "plan_action_id": expected["action_id"],
        "plan_confidence": 0.99,
        "policy_status": "ok",
    }


@pytest.mark.parametrize(
    "retrieved,expected_code",
    [
        (
            {"status": "error", "meta": {"results_count": 0}},
            "GCP_VDI_SOP_RETRIEVAL_FAILED",
        ),
        (
            {"status": "ok", "snippets": [], "meta": {"results_count": 0}},
            "GCP_VDI_SOP_NOT_FOUND",
        ),
    ],
)
def test_sop_failure_stops_before_planner_policy_and_backend(
    monkeypatch,
    retrieved,
    expected_code,
):
    planner = Mock()
    policy = Mock()
    backend = Mock()
    monkeypatch.setattr(gcp_tool, "_sop_retriever", Mock(return_value=retrieved))
    monkeypatch.setattr(gcp_tool, "_propose_plan", planner)
    monkeypatch.setattr(gcp_tool, "_check_list", policy)
    monkeypatch.setattr(gcp_tool, "_load_demo_snapshot", backend)

    result = _login()

    assert result["code"] == expected_code
    planner.assert_not_called()
    policy.assert_not_called()
    backend.assert_not_called()


@pytest.mark.parametrize(
    "mutation",
    [
        {"can_execute_fully": False},
        {"low_confidence": True},
        {"unmapped": [{"name": "unknown"}]},
        {"required_inputs": ["target_host"]},
        {"tool_sequence": []},
        {
            "tool_sequence": [
                {
                    "tool": "gcp_virtual_desktop_tool",
                    "action": "diagnose_virtual_desktop_performance",
                    "action_id": "gcp.virtual_desktop.diagnose_performance",
                }
            ]
        },
    ],
)
def test_unsafe_or_unexpected_plan_stops_before_policy_and_backend(
    monkeypatch, mutation
):
    planned = _safe_plan("login")
    planned["plan"].update(mutation)
    policy = Mock()
    backend = Mock()
    monkeypatch.setattr(gcp_tool, "_propose_plan", Mock(return_value=planned))
    monkeypatch.setattr(gcp_tool, "_check_list", policy)
    monkeypatch.setattr(gcp_tool, "_load_demo_snapshot", backend)

    result = _login()

    assert result["code"] == "GCP_VDI_PLAN_NOT_EXECUTABLE"
    policy.assert_not_called()
    backend.assert_not_called()


def test_policy_denial_stops_before_backend(monkeypatch):
    backend = Mock()
    monkeypatch.setattr(
        gcp_tool,
        "_check_list",
        Mock(return_value={"status": "error", "code": "UNKNOWN_PRECONDITION"}),
    )
    monkeypatch.setattr(gcp_tool, "_load_demo_snapshot", backend)

    result = _performance()

    assert result["code"] == "GCP_VDI_POLICY_DENIED"
    backend.assert_not_called()


def test_safe_default_mode_is_off(monkeypatch):
    monkeypatch.delenv("GCP_VDI_MODE", raising=False)

    result = _login()

    assert result == {
        "status": "error",
        "code": "GCP_VDI_BACKEND_OFF",
        "message": "GCP virtual desktop diagnosis is disabled.",
        "backend": "off",
    }


def test_invalid_mode_is_fail_closed(monkeypatch):
    monkeypatch.setenv("GCP_VDI_MODE", "automatic")

    result = _login()

    assert result["status"] == "error"
    assert result["code"] == "GCP_VDI_MODE_INVALID"


def test_unknown_caller_stops_before_backend(monkeypatch):
    backend = Mock()
    monkeypatch.setattr(gcp_tool, "_load_demo_snapshot", backend)

    result = _login(_context(None))

    assert result["code"] == "GCP_VDI_CALLER_UNKNOWN"
    backend.assert_not_called()


def test_self_service_only_stops_before_backend(monkeypatch):
    backend = Mock()
    monkeypatch.setattr(gcp_tool, "_load_demo_snapshot", backend)

    result = gcp_tool.gcp_diagnose_virtual_desktop_login.func(
        "another.user@example.test",
        _context(),
    )

    assert result["code"] == "GCP_VDI_SELF_SERVICE_ONLY"
    backend.assert_not_called()


def test_missing_mapping_for_known_caller(monkeypatch, tmp_path):
    empty_mapping = _write_mapping(tmp_path / "empty.json", {})
    monkeypatch.setenv("GCP_VDI_MAPPING_PATH", str(empty_mapping))

    result = _login()

    assert result["code"] == "GCP_VDI_MAPPING_NOT_FOUND"


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {CALLER_UPN: "not-an-object"},
        {
            CALLER_UPN: {
                "project_id": "INVALID",
                "zone": "x",
                "instance_name": "x",
                "windows_username": "x",
            }
        },
        {
            CALLER_UPN: {
                "project_id": "fake-vdi-project",
                "zone": "us-central1-b",
                "instance_name": "UPPERCASE",
                "windows_username": "fakeuser",
            }
        },
        {
            CALLER_UPN: {
                "project_id": "fake-vdi-project",
                "zone": "us-central1-b",
                "instance_name": "fake-vdi",
                "windows_username": "bad/user",
            }
        },
    ],
)
def test_malformed_mapping_fails_closed(monkeypatch, tmp_path, payload):
    malformed = _write_mapping(tmp_path / "malformed.json", payload)
    monkeypatch.setenv("GCP_VDI_MAPPING_PATH", str(malformed))

    result = _login()

    assert result["code"] == "GCP_VDI_MAPPING_INVALID"


@pytest.mark.parametrize(
    ("scenario", "finding"),
    [
        ("not_found", "VDI_INSTANCE_NOT_FOUND"),
        ("stopped", "VDI_INSTANCE_NOT_RUNNING"),
        ("running_healthy", "NO_GCP_VDI_LOGIN_CAUSE_FOUND"),
        ("rdp_login_failure", "RDP_AUTH_FAILURE_DETECTED"),
        ("rdp_disconnect", "RDP_RECENT_DISCONNECT"),
        ("missing_telemetry", "RDP_TELEMETRY_UNAVAILABLE"),
    ],
)
def test_login_findings(monkeypatch, scenario, finding):
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", scenario)

    result = _login()

    assert result["status"] == "ok"
    assert result["diagnosis"]["finding_code"] == finding
    assert result["diagnosis"]["backend"] == "demo"


def test_login_contract_is_read_only_and_never_resets_password():
    result = _login()["diagnosis"]

    assert result["read_only"] is True
    assert result["infrastructure_mutation_performed"] is False
    assert result["automatic_password_reset_performed"] is False
    assert "windows_username" not in result


def test_arbitrary_vm_cannot_be_selected_from_tool_arguments():
    parameters = inspect.signature(
        gcp_tool.gcp_diagnose_virtual_desktop_login.func
    ).parameters

    assert list(parameters) == ["target_upn", "tool_context"]
    assert _login()["diagnosis"]["instance_name"] == "fake-assigned-vdi"


def test_gcp_failure_never_falls_back_to_demo(monkeypatch):
    real_backend = Mock(side_effect=RuntimeError("api unavailable"))
    demo_backend = Mock()
    monkeypatch.setenv("GCP_VDI_MODE", "gcp")
    monkeypatch.setattr(gcp_tool, "_load_gcp_snapshot", real_backend)
    monkeypatch.setattr(gcp_tool, "_load_demo_snapshot", demo_backend)

    result = _login()

    assert result["status"] == "error"
    assert result["code"] == "GCP_VDI_API_FAILURE"
    assert result["backend"] == "gcp"
    real_backend.assert_called_once()
    demo_backend.assert_not_called()


@pytest.mark.parametrize(
    ("scenario", "value", "finding"),
    [
        ("delay_below_200", 199.0, "NO_RDP_INPUT_DELAY_THRESHOLD_BREACH"),
        ("delay_exactly_200", 200.0, "NO_RDP_INPUT_DELAY_THRESHOLD_BREACH"),
        ("delay_above_200", 243.0, "RDP_USER_INPUT_DELAY_ELEVATED"),
    ],
)
def test_user_input_delay_threshold_is_strictly_greater_than_200(
    monkeypatch,
    scenario,
    value,
    finding,
):
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", scenario)

    diagnosis = _performance()["diagnosis"]

    assert diagnosis["metrics"]["rdp_user_input_delay_ms"]["value"] == value
    assert diagnosis["finding_code"] == finding
    assert diagnosis["threshold_rule"] == "RDP User Input Delay > 200 ms"


@pytest.mark.parametrize(
    ("scenario", "has_offer"),
    [
        ("delay_below_200", False),
        ("delay_exactly_200", False),
        ("missing_telemetry", False),
        ("delay_above_200", True),
    ],
)
def test_cleanup_offer_is_created_only_for_strictly_elevated_delay(
    monkeypatch, scenario, has_offer
):
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", scenario)
    context = SimpleNamespace(
        state={"identity_context": {"upn": CALLER_UPN}}, invocation_id="offer-turn"
    )

    result = _performance(context)

    assert bool(result["cleanup_offer"]) is has_offer
    if has_offer:
        offer = context.state[gcp_tool.GCP_VDI_CLEANUP_OFFER_STATE_KEY]
        assert offer["caller_upn"] == CALLER_UPN
        assert offer["target"] == {
            "project_id": "fake-vdi-project",
            "zone": "us-central1-b",
            "instance_name": "fake-assigned-vdi",
        }
        assert offer["action_id"] == "gcp.virtual_desktop.system_file_cleanup"


def test_cleanup_requires_later_confirmation_and_checks_policy_once(monkeypatch):
    context = SimpleNamespace(
        state={"identity_context": {"upn": CALLER_UPN}}, invocation_id="offer-turn"
    )
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", "delay_above_200")
    _performance(context)
    policy = Mock(return_value={"status": "ok", "details": {}})
    cleanup = Mock(return_value={"status": "ok", "backend": "demo"})
    monkeypatch.setattr(gcp_tool, "_check_list", policy)
    monkeypatch.setattr(gcp_tool, "execute_system_file_cleanup", cleanup)

    same_turn = _cleanup(context)
    assert same_turn["code"] == "GCP_VDI_CLEANUP_NEW_CONFIRMATION_REQUIRED"
    cleanup.assert_not_called()

    context.invocation_id = "confirm-turn"
    result = _cleanup(context)

    assert result["status"] == "ok"
    cleanup.assert_called_once()
    assert policy.call_count == 1
    assert policy.call_args.kwargs["tool_context"] is None
    assert context.state[gcp_tool.GCP_VDI_CLEANUP_OFFER_STATE_KEY]["phase"] == "executed"
    second_attempt = _cleanup(context)
    assert second_attempt["code"] == "GCP_VDI_CLEANUP_OFFER_MISSING"


@pytest.mark.parametrize(
    "mutation,expected_code",
    [
        ({"expires_at": 0}, "GCP_VDI_CLEANUP_OFFER_EXPIRED"),
        ({"action_id": "wrong.action"}, "GCP_VDI_CLEANUP_ACTION_INVALID"),
    ],
)
def test_cleanup_rejects_invalid_retained_offer(monkeypatch, mutation, expected_code):
    context = SimpleNamespace(
        state={"identity_context": {"upn": CALLER_UPN}}, invocation_id="offer-turn"
    )
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", "delay_above_200")
    _performance(context)
    context.state[gcp_tool.GCP_VDI_CLEANUP_OFFER_STATE_KEY].update(mutation)
    context.invocation_id = "confirm-turn"

    result = _cleanup(context)

    assert result["code"] == expected_code


def test_cleanup_rejects_changed_mapping_and_caller(monkeypatch):
    context = SimpleNamespace(
        state={"identity_context": {"upn": CALLER_UPN}}, invocation_id="offer-turn"
    )
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", "delay_above_200")
    _performance(context)
    context.invocation_id = "confirm-turn"
    context.state["identity_context"]["upn"] = "different@example.test"
    assert _cleanup(context)["code"] == "GCP_VDI_CLEANUP_CALLER_CHANGED"

    context.state["identity_context"]["upn"] = CALLER_UPN
    context.state[gcp_tool.GCP_VDI_CLEANUP_OFFER_STATE_KEY]["phase"] = "offered"
    context.state[gcp_tool.GCP_VDI_CLEANUP_OFFER_STATE_KEY]["target"]["instance_name"] = "other-vm"
    assert _cleanup(context)["code"] == "GCP_VDI_CLEANUP_MAPPING_CHANGED"


@pytest.mark.parametrize(
    "mutation",
    [
        {"can_execute_fully": False},
        {"low_confidence": True},
        {"unmapped": [{"name": "unexpected"}]},
        {"required_inputs": ["target_host"]},
        {
            "tool_sequence": [
                {
                    "tool": "gcp_virtual_desktop_tool",
                    "action": "diagnose_virtual_desktop_performance",
                    "action_id": "gcp.virtual_desktop.diagnose_performance",
                }
            ]
        },
    ],
)
def test_cleanup_unsafe_or_unexpected_plan_stops_before_policy_and_backend(
    monkeypatch, mutation
):
    context = SimpleNamespace(
        state={"identity_context": {"upn": CALLER_UPN}}, invocation_id="offer-turn"
    )
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", "delay_above_200")
    _performance(context)
    context.invocation_id = "confirm-turn"
    planned = _safe_plan("cleanup")
    planned["plan"].update(mutation)
    policy = Mock()
    cleanup = Mock()
    monkeypatch.setattr(gcp_tool, "_propose_plan", Mock(return_value=planned))
    monkeypatch.setattr(gcp_tool, "_check_list", policy)
    monkeypatch.setattr(gcp_tool, "execute_system_file_cleanup", cleanup)

    result = _cleanup(context)

    assert result["code"] == "GCP_VDI_PLAN_NOT_EXECUTABLE"
    policy.assert_not_called()
    cleanup.assert_not_called()


def test_cleanup_policy_denial_stops_before_backend_and_account_access_state(monkeypatch):
    context = SimpleNamespace(
        state={"identity_context": {"upn": CALLER_UPN}}, invocation_id="offer-turn"
    )
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", "delay_above_200")
    _performance(context)
    context.invocation_id = "confirm-turn"
    cleanup = Mock()
    monkeypatch.setattr(
        gcp_tool,
        "_check_list",
        Mock(return_value={"status": "error", "code": "DENIED"}),
    )
    monkeypatch.setattr(gcp_tool, "execute_system_file_cleanup", cleanup)

    result = _cleanup(context)

    assert result["code"] == "GCP_VDI_POLICY_DENIED"
    cleanup.assert_not_called()
    assert "temp:account_access_authorization" not in context.state
    assert "account_access_identity_verification" not in context.state


def test_cleanup_failure_and_missing_post_telemetry_never_claim_resolution(monkeypatch):
    context = SimpleNamespace(
        state={"identity_context": {"upn": CALLER_UPN}}, invocation_id="offer-turn"
    )
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", "delay_above_200")
    _performance(context)
    context.invocation_id = "confirm-turn"
    monkeypatch.setattr(
        gcp_tool,
        "execute_system_file_cleanup",
        Mock(return_value={"status": "error", "code": "transport_failed"}),
    )
    failed = _cleanup(context)
    assert failed["code"] == "GCP_VDI_CLEANUP_FAILED"
    assert "completed successfully" not in failed["message"].lower()

    context.state[gcp_tool.GCP_VDI_CLEANUP_OFFER_STATE_KEY]["phase"] = "offered"
    monkeypatch.setattr(
        gcp_tool,
        "execute_system_file_cleanup",
        Mock(return_value={"status": "ok", "backend": "demo"}),
    )
    monkeypatch.setattr(
        gcp_tool,
        "_load_snapshot",
        Mock(side_effect=RuntimeError("telemetry delayed")),
    )
    unavailable = _cleanup(context)
    assert unavailable["status"] == "ok"
    assert "not available yet" in unavailable["message"]
    assert unavailable["post_cleanup_diagnosis"]["code"] == (
        "GCP_VDI_POST_CLEANUP_EVIDENCE_UNAVAILABLE"
    )


def test_real_cleanup_reuses_existing_winrm_with_controller_owned_private_host(
    monkeypatch,
):
    mapping = {
        "project_id": "fake-vdi-project",
        "zone": "us-central1-b",
        "instance_name": "fake-assigned-vdi",
    }
    monkeypatch.setattr(
        cleanup_tool,
        "_resolve_private_target",
        lambda value: "10.0.0.8",
    )
    execute = Mock(
        return_value={
            "status": "success",
            "code": 0,
            "stdout": json.dumps(
                {
                    "status": "ok",
                    "profile": "KB0019144-Compatible LAB Cleanup Profile",
                    "selected_categories": ["Delivery Optimization Files"],
                    "verification": "native_disk_cleanup_completed",
                }
            ),
            "stderr": "",
        }
    )
    monkeypatch.setattr(cleanup_tool.win_tool, "execute_winrm_ps", execute)

    result = cleanup_tool.execute_system_file_cleanup(mapping, "gcp")

    assert result["status"] == "ok"
    assert result["transport"] == "private_winrm"
    execute.assert_called_once()
    target_host, script = execute.call_args.args
    assert target_host == "10.0.0.8"
    assert "Invoke-ServiceDeskVdiLabCleanup.ps1" in script
    assert "gcloud" not in script.lower()


def test_cleanup_transport_has_no_second_remote_execution_framework():
    source = inspect.getsource(cleanup_tool)

    assert "execute_winrm_ps" in source
    assert "subprocess" not in source
    assert "tunnel-through-iap" not in source
    assert "metadata" not in source.lower()
    assert "scheduled remediation" not in source.lower()


@pytest.mark.parametrize("address", ["203.0.113.8", "127.0.0.1", "169.254.1.2"])
def test_private_target_rejects_non_rfc1918_addresses(monkeypatch, address):
    instance = SimpleNamespace(
        name="fake-assigned-vdi",
        status="RUNNING",
        network_interfaces=[SimpleNamespace(network_i_p=address)],
    )
    from google.cloud import compute_v1

    monkeypatch.setattr(
        compute_v1,
        "InstancesClient",
        lambda: SimpleNamespace(get=lambda **kwargs: instance),
    )

    with pytest.raises(ValueError, match="private_address_unavailable"):
        cleanup_tool._resolve_private_target(
            {
                "project_id": "fake-vdi-project",
                "zone": "us-central1-b",
                "instance_name": "fake-assigned-vdi",
            }
        )


def test_missing_rdp_telemetry_is_not_zero(monkeypatch):
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", "missing_telemetry")

    diagnosis = _performance()["diagnosis"]
    telemetry = diagnosis["metrics"]["rdp_user_input_delay_ms"]

    assert telemetry["status"] == "unavailable"
    assert telemetry["value"] is None
    assert diagnosis["finding_code"] == "NO_RECENT_RDP_TELEMETRY"


def test_inactive_rdp_session_is_distinct_from_missing_telemetry():
    mapping = {
        "project_id": "fake-vdi-project",
        "zone": "us-central1-b",
        "instance_name": "fake-assigned-vdi",
        "windows_username": "fakeuser",
    }
    snapshot = gcp_tool._load_demo_snapshot(mapping)
    snapshot["rdp_telemetry"] = {
        "status": "unavailable",
        "value": None,
        "timestamp": "2030-01-01T00:02:00Z",
        "session_active": False,
        "session_count": 0,
        "counter_available": True,
        "source": "windows_user_input_delay",
        "reason": "no_active_rdp_session",
    }

    diagnosis = gcp_tool._performance_diagnosis("demo", CALLER_UPN, mapping, snapshot)[
        "diagnosis"
    ]
    telemetry = diagnosis["metrics"]["rdp_user_input_delay_ms"]

    assert telemetry["status"] == "unavailable"
    assert telemetry["value"] is None
    assert telemetry["reason"] == "no_active_rdp_session"
    assert diagnosis["finding_code"] == "NO_ACTIVE_RDP_SESSION"


def test_inactive_real_session_zero_is_unavailable_and_preserves_record_time(
    monkeypatch,
):
    entry = SimpleNamespace(
        payload={
            "timestamp": "2030-01-01T00:02:00Z",
            "session_active": False,
            "session_count": 0,
            "counter_available": True,
            "max_user_input_delay_ms": 0,
        },
        timestamp="2030-01-01T00:03:00Z",
        log_name="projects/fake-vdi-project/logs/servicedesk_rdp_telemetry",
    )
    client = Mock()
    client.list_entries.return_value = [entry]
    monkeypatch.setattr("google.cloud.logging_v2.Client", Mock(return_value=client))

    telemetry, events, errors = gcp_tool._collect_logs("fake-vdi-project", "123")

    assert telemetry["status"] == "unavailable"
    assert telemetry["value"] is None
    assert telemetry["timestamp"] == "2030-01-01T00:02:00Z"
    assert telemetry["reason"] == "no_active_rdp_session"
    assert telemetry["counter_available"] is True
    assert events == []
    assert errors == []
    assert client.list_entries.call_count == 2
    telemetry_call, events_call = client.list_entries.call_args_list
    assert telemetry_call.kwargs["max_results"] == 1
    assert "servicedesk_rdp_telemetry" in telemetry_call.kwargs["filter_"]
    assert "windows_event_log" in telemetry_call.kwargs["filter_"]
    assert (
        'jsonPayload.ProviderName="ServiceDeskVDI"' in telemetry_call.kwargs["filter_"]
    )
    assert "jsonPayload.EventID=7101" in telemetry_call.kwargs["filter_"]
    assert "windows_event_log" in events_call.kwargs["filter_"]
    assert 'jsonPayload.Channel="Security"' in events_call.kwargs["filter_"]
    assert (
        "TerminalServices-LocalSessionManager/Operational"
        in events_call.kwargs["filter_"]
    )
    telemetry_since = (
        telemetry_call.kwargs["filter_"].split('timestamp>="', 1)[1].split('"', 1)[0]
    )
    events_since = (
        events_call.kwargs["filter_"].split('timestamp>="', 1)[1].split('"', 1)[0]
    )
    assert telemetry_since > events_since


def test_newer_rdp_connection_event_supersedes_negative_session_sample(monkeypatch):
    telemetry_entry = SimpleNamespace(
        payload={
            "timestamp": "2030-01-01T00:02:00Z",
            "session_active": False,
            "session_count": 0,
            "counter_available": True,
            "max_user_input_delay_ms": None,
        },
        timestamp="2030-01-01T00:02:01Z",
        log_name="projects/fake-vdi-project/logs/servicedesk_rdp_telemetry",
    )
    session_entry = SimpleNamespace(
        payload={
            "EventID": 25,
            "Channel": (
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
            ),
        },
        timestamp="2030-01-01T00:03:00Z",
        log_name="projects/fake-vdi-project/logs/windows_event_log",
    )
    client = Mock()
    client.list_entries.side_effect = [[telemetry_entry], [session_entry]]
    monkeypatch.setattr("google.cloud.logging_v2.Client", Mock(return_value=client))

    telemetry, events, errors = gcp_tool._collect_logs("fake-vdi-project", "123")

    assert telemetry["status"] == "unavailable"
    assert telemetry["value"] is None
    assert telemetry["session_active"] is None
    assert telemetry["session_count"] is None
    assert telemetry["reason"] == "session_state_changed_after_sample_latest_session"
    assert events[0]["category"] == "session"
    assert errors == []


def test_application_event_telemetry_message_is_parsed(monkeypatch):
    entry = SimpleNamespace(
        payload={
            "Channel": "Application",
            "ProviderName": "ServiceDeskVDI",
            "EventID": 7101,
            "Message": json.dumps(
                {
                    "timestamp": "2030-01-01T00:02:00Z",
                    "session_active": True,
                    "session_count": 1,
                    "counter_available": True,
                    "max_user_input_delay_ms": 17.0,
                }
            ),
        },
        timestamp="2030-01-01T00:03:00Z",
        log_name="projects/fake-vdi-project/logs/windows_event_log",
    )
    client = Mock()
    client.list_entries.side_effect = [[entry], []]
    monkeypatch.setattr("google.cloud.logging_v2.Client", Mock(return_value=client))

    telemetry, events, errors = gcp_tool._collect_logs("fake-vdi-project", "123")

    assert telemetry["status"] == "available"
    assert telemetry["value"] == 17.0
    assert telemetry["session_active"] is True
    assert telemetry["session_count"] == 1
    assert telemetry["timestamp"] == "2030-01-01T00:02:00Z"
    assert events == []
    assert errors == []


def test_latest_disconnect_after_reconnect_keeps_superseded_sample_unknown():
    telemetry = {
        "status": "unavailable",
        "value": None,
        "timestamp": "2030-01-01T00:02:00Z",
        "session_active": False,
        "session_count": 0,
        "reason": "no_active_rdp_session",
    }
    events = [
        {
            "timestamp": "2030-01-01T00:03:00Z",
            "event_id": 25,
            "category": "session",
        },
        {
            "timestamp": "2030-01-01T00:04:00Z",
            "event_id": 24,
            "category": "disconnect",
        },
    ]

    gcp_tool._reconcile_telemetry_session_state(telemetry, events)

    assert telemetry["session_active"] is None
    assert telemetry["session_count"] is None
    assert telemetry["value"] is None
    assert telemetry["reason"] == (
        "session_state_changed_after_sample_latest_disconnect"
    )


@pytest.mark.parametrize(
    ("event_id", "channel", "expected"),
    [
        (4625, "Security", True),
        (4625, "Application", False),
        (
            24,
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            True,
        ),
        (24, "System", False),
        (
            1149,
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            True,
        ),
        (1149, "Application", False),
        (4779, "Security", True),
        (4779, "System", False),
    ],
)
def test_rdp_event_ids_are_bound_to_authoritative_windows_channels(
    event_id,
    channel,
    expected,
):
    assert gcp_tool._is_relevant_rdp_event(event_id, channel) is expected


def test_security_4625_without_explicit_rdp_logon_type_is_not_classified(monkeypatch):
    entry = SimpleNamespace(
        payload={"EventID": 4625, "Channel": "Security"},
        timestamp="2030-01-01T00:03:00Z",
        log_name="projects/fake-vdi-project/logs/windows_event_log",
    )
    client = Mock()
    client.list_entries.side_effect = [[], [entry]]
    monkeypatch.setattr("google.cloud.logging_v2.Client", Mock(return_value=client))

    telemetry, events, errors = gcp_tool._collect_logs("fake-vdi-project", "123")

    assert telemetry["status"] == "unavailable"
    assert events == []
    assert errors == []


def test_performance_surfaces_host_observations_without_invented_thresholds():
    diagnosis = _performance()["diagnosis"]
    metrics = diagnosis["metrics"]

    assert metrics["cpu"]["value"] == 0.24
    assert metrics["memory_percent_used"]["value"] == 48.0
    assert metrics["disk_percent_used"]["value"] == 37.0
    assert metrics["network_received_bytes"]["status"] == "available"
    assert metrics["network_sent_bytes"]["status"] == "available"
    assert "cpu_threshold" not in diagnosis
    assert "memory_threshold" not in diagnosis
    assert "disk_threshold" not in diagnosis


def test_performance_surfaces_disconnects_and_preserves_timestamp(monkeypatch):
    monkeypatch.setenv("GCP_VDI_DEMO_SCENARIO", "rdp_disconnect")

    diagnosis = _performance()["diagnosis"]

    assert diagnosis["recent_disconnect_count"] == 2
    assert diagnosis["finding_code"] == "RDP_RECENT_DISCONNECTS"
    assert (
        diagnosis["metrics"]["rdp_user_input_delay_ms"]["timestamp"]
        == "2030-01-01T00:02:00Z"
    )


def test_correlated_disconnect_event_ids_count_as_one_episode():
    events = [
        {
            "timestamp": "2030-01-01T00:00:00Z",
            "event_id": 40,
            "category": "disconnect",
            "_correlation": "activity-a",
        },
        {
            "timestamp": "2030-01-01T00:00:01Z",
            "event_id": 24,
            "category": "disconnect",
            "_correlation": "activity-a",
        },
        {
            "timestamp": "2030-01-01T00:00:02Z",
            "event_id": 40,
            "category": "disconnect",
            "_correlation": "activity-a",
        },
    ]

    assert gcp_tool._disconnect_episode_count(events) == 1
    assert all(
        "_correlation" not in event
        for event in gcp_tool._safe_events({"events": events})
    )


def test_distinct_correlation_ids_are_not_collapsed_by_time_alone():
    events = [
        {
            "timestamp": "2030-01-01T00:00:00Z",
            "event_id": 40,
            "category": "disconnect",
            "_correlation": "activity-a",
        },
        {
            "timestamp": "2030-01-01T00:00:01Z",
            "event_id": 24,
            "category": "disconnect",
            "_correlation": "activity-b",
        },
    ]

    assert gcp_tool._disconnect_episode_count(events) == 2


def test_diagnosis_uses_private_correlation_but_never_returns_it():
    snapshot = {
        "instance": {"exists": True, "id": "123", "status": "RUNNING"},
        "metrics": {},
        "rdp_telemetry": {"status": "unavailable", "value": None},
        "events": [
            {
                "timestamp": "2030-01-01T00:00:00Z",
                "event_id": 40,
                "channel": "fake",
                "category": "disconnect",
                "_correlation": "activity-a",
            },
            {
                "timestamp": "2030-01-01T00:00:01Z",
                "event_id": 24,
                "channel": "fake",
                "category": "disconnect",
                "_correlation": "activity-b",
            },
        ],
        "collection_errors": [],
    }

    diagnosis = gcp_tool._performance_diagnosis(
        "demo",
        CALLER_UPN,
        {
            "project_id": "fake-vdi-project",
            "zone": "us-central1-b",
            "instance_name": "fake-assigned-vdi",
        },
        snapshot,
    )["diagnosis"]

    assert diagnosis["recent_disconnect_count"] == 2
    assert diagnosis["finding_code"] == "RDP_RECENT_DISCONNECTS"
    assert "activity-a" not in json.dumps(diagnosis)
    assert "activity-b" not in json.dumps(diagnosis)


def test_two_separate_disconnect_episodes_trigger_repeated_finding(monkeypatch):
    snapshot = gcp_tool._load_demo_snapshot(
        {
            "project_id": "fake-vdi-project",
            "zone": "us-central1-b",
            "instance_name": "fake-assigned-vdi",
            "windows_username": "fakeuser",
        }
    )
    snapshot["events"] = [
        {
            "timestamp": "2030-01-01T00:00:00Z",
            "event_id": 40,
            "category": "disconnect",
            "_correlation": "activity-a",
        },
        {
            "timestamp": "2030-01-01T00:00:01Z",
            "event_id": 24,
            "category": "disconnect",
            "_correlation": "activity-a",
        },
        {
            "timestamp": "2030-01-01T00:01:00Z",
            "event_id": 40,
            "category": "disconnect",
            "_correlation": "activity-a",
        },
        {
            "timestamp": "2030-01-01T00:01:01Z",
            "event_id": 24,
            "category": "disconnect",
            "_correlation": "activity-a",
        },
    ]

    diagnosis = gcp_tool._performance_diagnosis(
        "demo",
        CALLER_UPN,
        {
            "project_id": "fake-vdi-project",
            "zone": "us-central1-b",
            "instance_name": "fake-assigned-vdi",
        },
        snapshot,
    )["diagnosis"]

    assert diagnosis["recent_disconnect_count"] == 2
    assert diagnosis["finding_code"] == "RDP_RECENT_DISCONNECTS"


def test_gcp_contract_contains_no_aws_metric_terminology():
    serialized = json.dumps(_performance()).lower()

    assert "aws" not in serialized
    assert "workspaces" not in serialized
    assert "insessionlatency" not in serialized
    assert '"backend": "demo"' in serialized


def test_metric_map_uses_confirmed_google_metric_types():
    assert (
        gcp_tool._METRIC_SPECS["cpu"]["type"]
        == "compute.googleapis.com/instance/cpu/utilization"
    )
    assert (
        gcp_tool._METRIC_SPECS["memory_percent_used"]["type"]
        == "agent.googleapis.com/memory/percent_used"
    )
    assert (
        gcp_tool._METRIC_SPECS["disk_percent_used"]["type"]
        == "agent.googleapis.com/disk/percent_used"
    )
    assert all(
        spec["type"] != "compute.googleapis.com/instance/uptime"
        for spec in gcp_tool._METRIC_SPECS.values()
    )
    for name in ("network_received_bytes", "network_sent_bytes"):
        assert gcp_tool._METRIC_SPECS[name]["aggregation"] == "latest_delta"
        assert gcp_tool._METRIC_SPECS[name]["observation_period_seconds"] == 60


def test_network_metric_is_labeled_as_latest_60_second_delta():
    value = SimpleNamespace(int64_value=1234)
    value._pb = SimpleNamespace(WhichOneof=lambda _: "int64_value")
    point = SimpleNamespace(
        value=value,
        interval=SimpleNamespace(
            start_time=gcp_tool.datetime(
                2030, 1, 1, 0, 0, 0, tzinfo=gcp_tool.timezone.utc
            ),
            end_time=gcp_tool.datetime(
                2030, 1, 1, 0, 1, 0, tzinfo=gcp_tool.timezone.utc
            ),
        ),
    )
    client = Mock()
    client.list_time_series.return_value = [SimpleNamespace(points=[point])]

    observation = gcp_tool._metric_observation(
        client,
        "fake-vdi-project",
        "123",
        gcp_tool._METRIC_SPECS["network_received_bytes"],
        gcp_tool.datetime(2029, 12, 31, tzinfo=gcp_tool.timezone.utc),
        gcp_tool.datetime(2030, 1, 2, tzinfo=gcp_tool.timezone.utc),
    )

    assert observation["value"] == 1234
    assert observation["aggregation"] == "latest_delta"
    assert observation["observation_period_seconds"] == 60
    assert observation["unit"] == "bytes"


def test_uptime_uses_compute_instance_last_start_not_latest_delta_bucket():
    instance = SimpleNamespace(
        status="RUNNING",
        last_start_timestamp="2030-01-01T00:00:00Z",
    )

    observation = gcp_tool._instance_uptime_observation(
        instance,
        observed_at=gcp_tool.datetime(
            2030, 1, 1, 1, 2, 3, tzinfo=gcp_tool.timezone.utc
        ),
    )

    assert observation == {
        "status": "available",
        "value": 3723.0,
        "timestamp": "2030-01-01T01:02:03Z",
        "source": "compute_instance_last_start_timestamp",
        "started_at": "2030-01-01T00:00:00Z",
    }


def test_tool_implementation_has_no_compute_or_password_mutation_calls():
    source = inspect.getsource(gcp_tool)

    for forbidden in (
        ".start(",
        ".stop(",
        ".insert(",
        ".delete(",
        ".patch(",
        "reset_password(",
    ):
        assert forbidden not in source


def test_gcp_action_registry_contains_two_diagnostics_and_one_cleanup_action():
    registry_dir = Path(reasoning_composer.REG_DIR)
    entries = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in registry_dir.glob("gcp*.json")
    ]

    assert {entry["id"] for entry in entries} == {
        "gcp.virtual_desktop.diagnose_login",
        "gcp.virtual_desktop.diagnose_performance",
        "gcp.virtual_desktop.system_file_cleanup",
    }
    assert {
        entry["id"]: entry["inputs"] for entry in entries
    } == {
        "gcp.virtual_desktop.diagnose_login": ["target_upn"],
        "gcp.virtual_desktop.diagnose_performance": ["target_upn"],
        "gcp.virtual_desktop.system_file_cleanup": [],
    }


@pytest.mark.parametrize(
    ("step", "expected_action"),
    [
        (
            "Validate the GCP virtual desktop state and recent RDP login/session health.",
            "gcp.virtual_desktop.diagnose_login",
        ),
        (
            "Check the GCP virtual desktop's host performance and Remote Desktop responsiveness.",
            "gcp.virtual_desktop.diagnose_performance",
        ),
    ],
)
def test_realistic_planner_step_maps_to_one_gcp_action(
    monkeypatch,
    step,
    expected_action,
):
    monkeypatch.setattr(reasoning_composer, "GENAI_AVAILABLE", False)

    result = reasoning_composer.propose_plan(
        user_text=step,
        ctx_vars=["target_upn"],
        sop_texts=[step],
    )

    plan = result["plan"]
    assert plan["can_execute_fully"] is True
    assert plan["low_confidence"] is False
    assert plan["unmapped"] == []
    assert len(plan["tool_sequence"]) == 1
    assert plan["tool_sequence"][0]["action_id"] == expected_action


def test_cleanup_planner_step_maps_to_only_the_new_cleanup_action(monkeypatch):
    monkeypatch.setattr(reasoning_composer, "GENAI_AVAILABLE", False)
    step = gcp_tool._ORCHESTRATION_SPECS["cleanup"]["step"]

    result = reasoning_composer.propose_plan(
        user_text=step,
        ctx_vars=[],
        sop_texts=[step],
    )

    plan = result["plan"]
    assert plan["can_execute_fully"] is True
    assert plan["low_confidence"] is False
    assert plan["unmapped"] == []
    assert plan["required_inputs"] == []
    assert [step["action_id"] for step in plan["tool_sequence"]] == [
        "gcp.virtual_desktop.system_file_cleanup"
    ]


def test_new_cleanup_registry_entry_does_not_change_existing_title_mappings(monkeypatch):
    """Global-registry collision guard for every action that predates cleanup."""
    monkeypatch.setattr(reasoning_composer, "GENAI_AVAILABLE", False)
    entries = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in Path(reasoning_composer.REG_DIR).glob("*.json")
    ]
    existing = [
        entry
        for entry in entries
        if entry["id"] != "gcp.virtual_desktop.system_file_cleanup"
    ]

    for entry in existing:
        result = reasoning_composer.propose_plan(
            user_text=entry["title"],
            ctx_vars=["target_upn", "target_host", "package_id"],
            sop_texts=[entry["title"]],
        )
        plan = result["plan"]
        assert plan["can_execute_fully"] is True, entry["id"]
        assert plan["low_confidence"] is False, entry["id"]
        assert plan["unmapped"] == [], entry["id"]
        assert [step["action_id"] for step in plan["tool_sequence"]] == [
            entry["id"]
        ], entry["id"]


def test_focused_gcp_routing_contract_preserves_other_system_flows():
    instruction = sd_chat.instruction
    normalized_instruction = " ".join(instruction.split())

    assert root_agent is sd_chat
    assert "GCP VIRTUAL DESKTOP" in instruction
    assert (
        "Once explicitly bound, this named-system path owns the initial diagnosis"
        in normalized_instruction
    )
    assert (
        "Do not route it to generic Account Access, AWS WorkSpaces, HOST login"
        in normalized_instruction
    )
    assert "call exactly one appropriate GCP diagnostic" in instruction
    assert (
        "Do not manually call sop_retriever, propose_plan, or check_list" in instruction
    )
    assert "internally enforces mandatory SOP retrieval" in instruction
    assert "generic planner's exact single expected action" in instruction
    assert "using the\n  planner's verbatim preconditions" in instruction
    assert (
        "expected controller action is gcp.virtual_desktop.diagnose_login"
        in instruction
    )
    assert "gcp.virtual_desktop.diagnose_performance" in instruction
    assert "I can't access my account" in instruction
    assert "explicit unlock, enable, or password-reset request" in instruction
    assert "report each available CPU, memory, disk" in instruction
    assert (
        "Never describe those host values as normal, healthy, high, low" in instruction
    )
    assert "INVALID if it omits an available metric or its" in instruction
    assert "assigns severity without an approved threshold" in instruction
    assert "aggregation=latest_delta" in instruction
    assert "Never call it bandwidth, throughput" in instruction
    assert "root_agent = sd_chat" in Path("sd_chat/agent.py").read_text(
        encoding="utf-8"
    )


def test_shared_workstation_routing_uses_target_class_not_cloud_provider():
    instruction = " ".join(sd_chat.instruction.split())

    assert "Cloud provider is NOT the target-class discriminator" in instruction
    assert "virtual desktop, or VDI" in instruction
    assert '"my GCP system is slow" remains target-class ambiguous' in instruction
    assert '"my GCP virtual desktop is slow" clearly identifies' in instruction
    assert "A named AWS WorkSpace remains owned by the AWS WorkSpaces path" in instruction


@pytest.mark.parametrize(
    ("user_text", "scope_signal"),
    [
        ("my virtual desktop is slow", "shared_virtual_workstation"),
        ("my VDI won't connect", "shared_virtual_workstation"),
        ("my account isn't working", "ambiguous"),
        ("my desktop is lagging", "ambiguous"),
    ],
)
def test_target_class_routing_contract_for_generic_requests(user_text, scope_signal):
    instruction = " ".join(sd_chat.instruction.split())

    assert user_text
    if scope_signal == "shared_virtual_workstation":
        assert "shared virtual workstation, virtual desktop, or VDI" in instruction
    else:
        assert "If the endpoint class is not clear, call resolve_endpoint_targets()" in instruction


@pytest.mark.parametrize(
    "explicit_request",
    [
        "my GCP virtual desktop is lagging",
        "my Google Cloud desktop is freezing",
        "my Compute Engine Windows desktop won't connect",
    ],
)
def test_cloud_hosted_shared_workstation_requests_still_require_workstation_signal(
    explicit_request,
):
    instruction = " ".join(sd_chat.instruction.split())

    assert explicit_request
    assert "The cloud-provider word alone does not select this path" in instruction
    assert '"my GCP virtual desktop is slow" clearly identifies' in instruction


def test_public_tool_surface_contains_diagnostics_and_retained_cleanup_controller():
    assert gcp_tool.gcp_virtual_desktop_tools == [
        gcp_tool.gcp_diagnose_virtual_desktop_login,
        gcp_tool.gcp_diagnose_virtual_desktop_performance,
        gcp_tool.gcp_confirm_virtual_desktop_system_file_cleanup,
    ]


def test_readme_reports_active_session_validation_without_fabrication():
    readme = Path("README.md").read_text(encoding="utf-8")

    assert (
        "Recurring scheduled collection, active-session User Input Delay, and production"
        in readme
    )
    assert "diagnosis consumption are live-validated." in readme
    assert "session_count=1" in readme
    assert "genuine `0 ms` value" in readme
    assert "inactive or unavailable evidence remains" in readme
    assert (
        "Portal conversational wording/routing still requires manual validation."
        in readme
    )
    assert "autonomous scheduled cycles verified" not in readme
    assert "aggregation=latest_delta" in readme


def test_windows_bootstrap_writes_ops_agent_yaml_without_utf8_bom():
    script = Path("scripts/configure_gcp_vdi_windows.ps1").read_text(encoding="utf-8")

    assert "System.Text.UTF8Encoding($false)" in script
    assert "[System.IO.File]::WriteAllText($OpsAgentTempPath" in script
    assert (
        "Move-Item -Path $OpsAgentTempPath -Destination $OpsAgentConfigPath" in script
    )
    assert "Set-Content -Path $OpsAgentConfigPath" not in script


def test_windows_bootstrap_preserves_unowned_ops_agent_user_config():
    script = Path("scripts/configure_gcp_vdi_windows.ps1").read_text(encoding="utf-8")

    assert 'OpsAgentOwnershipMarker = "# managed-by: ServiceDeskVDI"' in script
    assert "config.pre-servicedesk.bak" in script
    assert "ops_agent_servicedesk_config.yaml" in script
    assert "ManagedSnapshotMatches" in script
    assert "LegacyServiceDeskConfigMatches" in script
    assert "not ServiceDesk-owned; it was preserved" in script
    assert "Copy-Item -Path $OpsAgentConfigPath" in script
    assert "ServiceDesk Ops Agent rendered config" not in script


def test_windows_bootstrap_boundedly_waits_for_all_ops_agent_services():
    script = Path("scripts/configure_gcp_vdi_windows.ps1").read_text(encoding="utf-8")

    assert '"google-cloud-ops-agent-fluent-bit"' in script
    assert '"google-cloud-ops-agent-opentelemetry-collector"' in script
    assert "AddSeconds(60)" in script
    assert "Start-Sleep -Seconds 5" in script
    assert "did not reach running state within 60 seconds" in script


def test_windows_bootstrap_proves_one_window_and_registers_recurring_task():
    script = Path("scripts/configure_gcp_vdi_windows.ps1").read_text(encoding="utf-8")

    assert "CollectorValidationStarted" in script
    assert 'Phase "collector_validation"' in script
    assert "validation did not produce a fresh sample" in script
    assert 'CollectorTask.State -eq "Ready"' in script
    assert "TelemetryFile.LastWriteTimeUtc -lt $CollectorValidationStarted" in script
    assert script.count('Filter "rdp_telemetry_*.jsonl"') >= 3
    assert "collector validation returned exit code" in script
    assert "bounded scheduled supervisor" in script
    assert 'Phase "scheduled_task_validation"' not in script
    assert "ScheduledSampleDeadline" not in script


def test_windows_bootstrap_captures_existing_task_truth_before_replacement():
    script = Path("scripts/configure_gcp_vdi_windows.ps1").read_text(encoding="utf-8")

    assert "Write-ExistingTaskDiagnostic" in script
    assert script.index("Write-ExistingTaskDiagnostic\n") < script.index(
        "Stop-ScheduledTask -TaskName $TaskName"
    )
    for field in (
        "last_run_time",
        "next_run_time",
        "last_task_result",
        "missed_runs",
        "action_execute",
        "action_arguments",
        "trigger_start_boundary",
        "repetition_interval",
        "repetition_duration",
        "principal_logon_type",
        "principal_run_level",
        "telemetry_last_write_time",
        "telemetry_size_bytes",
        "audit_last_write_time",
        "audit_size_bytes",
    ):
        assert field in script
    assert 'LogName = "Microsoft-Windows-TaskScheduler/Operational"' in script
    assert 'phase = "existing_task_scheduler_event"' in script
    assert '"unexpected_redacted"' in script


def test_windows_collector_is_one_shot_under_a_repeating_bounded_task():
    script = Path("scripts/configure_gcp_vdi_windows.ps1").read_text(encoding="utf-8")
    collector = script.split("$CollectorScript = @'", 1)[1].split("'@", 1)[0]
    counter_probe = script.split("$CounterProbeScript = @'", 1)[1].split("'@", 1)[0]

    assert "while ($true)" not in collector
    assert "$TaskTrigger = New-ScheduledTaskTrigger `" in script
    assert "-Once `" in script
    assert "$TaskStartTime = (Get-Date).AddMinutes(2)" in script
    assert "-RepetitionInterval (New-TimeSpan -Minutes 1) `" in script
    assert "-RepetitionDuration (New-TimeSpan -Hours 3)" in script
    assert "New-ScheduledTaskTrigger -AtLogOn" not in script
    assert '-UserId "SYSTEM"' in script
    assert "-LogonType ServiceAccount" in script
    assert "-MultipleInstances IgnoreNew" in script
    assert "-ExecutionTimeLimit (New-TimeSpan -Hours 3)" in script
    assert 'System32\\WindowsPowerShell\\v1.0\\powershell.exe" `' in script
    assert "-File $SupervisorPath -MaximumIterations 1" in script
    assert "Start-ScheduledTask" not in script
    assert "Run-RdpTelemetryCollector.ps1" in script
    assert "$MaximumCollectorRuntimeMilliseconds = 45000" in script
    assert "$RestartDelaySeconds = 2" in script
    assert "$SupervisorExitCode = 0" in script
    assert "$SupervisorExitCode = 124" in script
    assert 'Phase "collector_failed"' in script
    assert "exit $SupervisorExitCode" in script
    assert "[int]$MaximumIterations = 0" in script
    assert "-MaximumIterations 1" in script
    assert script.index("-MaximumIterations 1") < script.index("$TaskAction =")
    assert (
        "$CollectorProcess.WaitForExit($MaximumCollectorRuntimeMilliseconds)" in script
    )
    assert "$CollectorProcess.Kill()" not in script
    assert "-WindowStyle Hidden" not in script
    assert 'Phase "supervisor_started"' in script
    assert 'phase = "task_registered"' in script
    assert "next_run_time" in script
    assert "$TaskRegistrationCheckedAt = Get-Date" in script
    assert "$CollectorTaskInfo.NextRunTime -gt $TaskRegistrationCheckedAt" in script
    assert 'Phase "collector_launch_failed"' in script
    assert "qwinsta.exe" not in collector
    assert "capabilities.json" in collector
    assert "Get-Counter -ListSet" not in collector
    assert "$MaximumCounterProbeMilliseconds = 2500" in collector
    assert (
        "$CounterProbeProcess.WaitForExit($MaximumCounterProbeMilliseconds)"
        in collector
    )
    assert '"-ResultToken", $PID' in collector
    assert "Measure-RdpUserInputDelay.ps1" in script
    assert "qwinsta.exe" in counter_probe
    assert "Get-Counter -ListSet *" not in counter_probe
    assert script.count("Get-Counter -ListSet *") == 1
    assert "user_input_delay_counter_paths" in counter_probe
    assert 'SessionName -match "^rdp-tcp' in counter_probe
    assert "$ActiveRdpSessionIds -contains [string]$_.InstanceName" in counter_probe
    assert '$ResultToken -notmatch "^\\d+$"' in counter_probe
    assert "Join-Path $ServiceDeskRoot" in counter_probe
    assert "session_count = $ActiveRdpSessionIds.Count" in counter_probe
    assert "counter_value = $null" in counter_probe
    assert "username" not in counter_probe.casefold()
    assert "session_id =" not in counter_probe.casefold()
    assert "taskkill.exe" in script
    assert "/PID $CollectorProcess.Id" in script
    assert "/T `" in script


def test_windows_scheduled_collector_has_bounded_non_sensitive_execution_audit():
    script = Path("scripts/configure_gcp_vdi_windows.ps1").read_text(encoding="utf-8")
    task_runner = script.split("$TaskRunnerScript = @'", 1)[1].split("'@", 1)[0]

    assert "rdp_collector_audit.jsonl" in script
    assert "servicedesk_rdp_collector_audit" in script
    assert "$MaximumAuditFiles = 720" in task_runner
    assert 'Write-CollectorAudit -Phase "started"' in task_runner
    assert 'Write-CollectorAudit -Phase "completed"' in task_runner
    assert "rdp_collector_audit_{0}.tmp" in task_runner
    assert "rdp_collector_audit_{0}.jsonl" in task_runner
    assert "Move-Item -Path $AuditTempPath -Destination $AuditPath" in task_runner
    assert "System.Text.UTF8Encoding($false)" in task_runner
    assert "[System.IO.File]::WriteAllText($AuditTempPath" in task_runner
    assert "-Source $ServiceDeskEventSource -EventId $AuditEventId" in task_runner
    assert "username" not in task_runner.casefold()
    assert "credential" not in task_runner.casefold()


def test_windows_collector_atomically_publishes_bounded_telemetry_files():
    script = Path("scripts/configure_gcp_vdi_windows.ps1").read_text(encoding="utf-8")
    collector = script.split("$CollectorScript = @'", 1)[1].split("'@", 1)[0]

    assert "$MaximumTelemetryFiles = 360" in collector
    assert "rdp_telemetry_{0}.tmp" in collector
    assert "rdp_telemetry_{0}.jsonl" in collector
    assert "Move-Item -Path $TelemetryTempPath -Destination $TelemetryPath" in collector
    assert "System.Text.UTF8Encoding($false)" in collector
    assert "[System.IO.File]::WriteAllText($TelemetryTempPath" in collector
    assert "-Source $ServiceDeskEventSource -EventId $TelemetryEventId" in collector
    assert 'Filter "rdp_telemetry_*.jsonl"' in collector
    assert "Select-Object -Skip $MaximumTelemetryFiles" in collector
    assert "rdp_telemetry_*.jsonl" in script
    assert "rdp_collector_audit_*.jsonl" in script
    assert script.count("wildcard_refresh_interval: 10s") == 2


def test_windows_bootstrap_does_not_modify_sccm_domain_or_network_configuration():
    script = (
        Path("scripts/configure_gcp_vdi_windows.ps1")
        .read_text(encoding="utf-8")
        .casefold()
    )

    for forbidden in (
        "add-computer",
        "remove-computer",
        "ccmsetup",
        "ccmexec",
        "root\\ccm",
        "set-dnsclientserveraddress",
        "new-netfirewallrule",
        "set-netfirewallrule",
        "netsh advfirewall",
    ):
        assert forbidden not in script
