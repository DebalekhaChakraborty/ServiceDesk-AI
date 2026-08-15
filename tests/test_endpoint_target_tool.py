import inspect
import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

os.environ.setdefault("WINRM_PORT", "5986")

from sd_chat.agent import root_agent, sd_chat
from sd_chat.tools import endpoint_target_tool as targets
from sd_chat.tools import gcp_virtual_desktop_cleanup as cleanup


CALLER_UPN = "caller@example.test"
SHARED_MAPPING = {
    "project_id": "fake-project",
    "zone": "us-central1-b",
    "instance_name": "fake-shared-workstation",
    "windows_username": "fakeuser",
}


def _context():
    persona = {
        "displayName": "Caller",
        "userPrincipalName": CALLER_UPN,
        "id": "caller-id",
    }
    return SimpleNamespace(
        state={"persona": persona, "user:persona": persona},
        invocation_id="target-test",
    )


def _install_candidates(monkeypatch, devices, shared=SHARED_MAPPING):
    registered = Mock(
        return_value={
            "ok": True,
            "allowed_hosts": list(devices),
            "source": "graph.registeredDevices",
            "error": None,
        }
    )
    monkeypatch.setattr(targets.aad_tool.aad_get_my_devices, "func", registered)
    shared_lookup = Mock(return_value=(shared, None))
    monkeypatch.setattr(targets, "_shared_workstation", shared_lookup)
    return registered, shared_lookup


def test_one_registered_device_and_shared_workstation_asks_one_exact_question(
    monkeypatch,
):
    _install_candidates(monkeypatch, ["TEJA-LAPTOP"])
    context = _context()

    result = targets.resolve_endpoint_targets.func(context)

    assert result == {
        "status": "needs_input",
        "kind": "endpoint_target_scope",
        "question": (
            "I found your registered device 'TEJA-LAPTOP'. Is this for that "
            "device, or for the shared virtual workstation?"
        ),
        "registered_devices": ["TEJA-LAPTOP"],
        "shared_virtual_workstation_available": True,
    }
    assert context.state[targets.ENDPOINT_TARGET_BINDING_STATE_KEY] is None


def test_registered_device_selection_binds_only_fresh_entra_candidates(monkeypatch):
    registered, shared = _install_candidates(
        monkeypatch, ["TEJA-LAPTOP"], shared=SHARED_MAPPING
    )
    context = _context()

    result = targets.bind_endpoint_target_scope.func(
        targets.REGISTERED_DEVICE_SCOPE, context
    )

    assert result["status"] == "ok"
    assert result["binding"] == {
        "target_scope": "registered_device",
        "persisted": True,
        "source": "entra",
        "registered_device_name": "TEJA-LAPTOP",
    }
    binding = context.state[targets.ENDPOINT_TARGET_BINDING_STATE_KEY]
    assert binding["target_scope"] == "registered_device"
    assert binding["target_host"] == "TEJA-LAPTOP"
    registered.assert_called_once_with(context)
    shared.assert_not_called()


def test_shared_workstation_selection_returns_trusted_name_without_sensitive_infrastructure(
    monkeypatch,
):
    registered, shared = _install_candidates(monkeypatch, ["TEJA-LAPTOP"])
    context = _context()

    result = targets.bind_endpoint_target_scope.func(
        targets.SHARED_WORKSTATION_SCOPE, context
    )

    assert result == {
        "status": "ok",
        "resolution": "scope_bound",
        "binding": {
            "target_scope": "shared_virtual_workstation",
            "persisted": True,
            "source": "trusted_shared_workstation_mapping",
            "shared_virtual_workstation_available": True,
            "display_name": "Shared Virtual Workstation",
        },
    }
    assert "project_id" not in str(result)
    assert "zone" not in str(result)
    assert "windows_username" not in str(result)
    binding = context.state[targets.ENDPOINT_TARGET_BINDING_STATE_KEY]
    assert binding["target_scope"] == "shared_virtual_workstation"
    assert binding["display_name"] == "Shared Virtual Workstation"
    assert binding.get("mapping_fingerprint")
    registered.assert_not_called()
    shared.assert_called_once_with(CALLER_UPN)


def test_bound_scope_is_retained_without_asking_again(monkeypatch):
    _install_candidates(monkeypatch, ["TEJA-LAPTOP"])
    context = _context()
    targets.bind_endpoint_target_scope.func(
        targets.SHARED_WORKSTATION_SCOPE, context
    )

    result = targets.resolve_endpoint_targets.func(context)

    assert result["status"] == "ok"
    assert result["resolution"] == "retained_binding"
    assert result["binding"]["target_scope"] == "shared_virtual_workstation"
    assert (
        result["binding"]["display_name"] == "Shared Virtual Workstation"
    )
    assert "question" not in result


def test_explicit_switch_freshly_rebinds_from_requested_trusted_source(monkeypatch):
    registered, shared = _install_candidates(monkeypatch, ["TEJA-LAPTOP"])
    context = _context()
    targets.bind_endpoint_target_scope.func(
        targets.SHARED_WORKSTATION_SCOPE, context
    )

    result = targets.bind_endpoint_target_scope.func(
        targets.REGISTERED_DEVICE_SCOPE, context
    )

    assert result["binding"]["target_scope"] == "registered_device"
    assert context.state[targets.ENDPOINT_TARGET_BINDING_STATE_KEY][
        "target_host"
    ] == "TEJA-LAPTOP"
    registered.assert_called_once_with(context)
    shared.assert_called_once_with(CALLER_UPN)


@pytest.mark.parametrize("scope", ["gcp", "10.0.0.8", "some-host", ""])
def test_model_cannot_bind_arbitrary_target_values(scope):
    result = targets.bind_endpoint_target_scope.func(scope, _context())

    assert result["code"] == "ENDPOINT_TARGET_SCOPE_INVALID"


def test_agent_registers_target_tools_and_keeps_root_agent():
    assert root_agent is sd_chat
    names = {
        getattr(tool, "name", None) or getattr(tool, "__name__", None)
        for tool in sd_chat.tools
    }
    assert "resolve_endpoint_targets" in names
    assert "bind_endpoint_target_scope" in names
    instruction = " ".join(sd_chat.instruction.split())
    assert "Cloud provider is NOT the target-class discriminator" in instruction
    assert "Do not resolve or ask again on every turn" in instruction
    assert "never request or accept its infrastructure values" in instruction
    assert '"which one is my shared virtual workstation?"' in instruction
    assert "is explicit, NOT ambiguous" in instruction
    assert "<display_name>" in instruction
    assert "install_software_on_bound_endpoint" in names


def test_multiple_registered_devices_require_and_bind_exact_verified_candidate(
    monkeypatch,
):
    _install_candidates(monkeypatch, ["DEVICE-A", "DEVICE-B"])
    context = _context()

    missing = targets.bind_endpoint_target_scope.func(
        targets.REGISTERED_DEVICE_SCOPE, context
    )
    assert missing["status"] == "needs_input"
    assert missing["registered_devices"] == ["DEVICE-A", "DEVICE-B"]

    rejected = targets.bind_endpoint_target_scope.func(
        targets.REGISTERED_DEVICE_SCOPE, context, "DEVICE-C"
    )
    assert rejected["code"] == "REGISTERED_DEVICE_NOT_VERIFIED"

    selected = targets.bind_endpoint_target_scope.func(
        targets.REGISTERED_DEVICE_SCOPE, context, "device-b"
    )
    assert selected["binding"]["registered_device_name"] == "DEVICE-B"
    binding = context.state[targets.ENDPOINT_TARGET_BINDING_STATE_KEY]
    assert binding["target_host"] == "DEVICE-B"
    assert binding["trusted_device_id"] == "device-b"


def _install_plan():
    return {
        "status": "ok",
        "plan": {
            "required_inputs": [],
            "preconditions": [
                "host_is_authorized",
                "endpoint_reachable",
                "endpoint_is_windows",
                "software_is_approved",
            ],
            "tool_sequence": [
                {
                    "tool": "win_tool",
                    "action": "install_software",
                    "action_id": "win.install_software",
                }
            ],
            "unmapped": [],
            "can_execute_fully": True,
            "low_confidence": False,
        },
    }


@pytest.mark.parametrize("scope", ["registered_device", "shared_virtual_workstation"])
def test_bound_software_adapter_reuses_existing_installer_without_model_host(
    monkeypatch, scope
):
    _install_candidates(monkeypatch, ["DEVICE-A"])
    context = _context()
    targets.bind_endpoint_target_scope.func(scope, context)
    monkeypatch.setattr(
        targets,
        "_sop_retriever",
        Mock(return_value={"status": "ok", "snippets": ["approved software SOP"]}),
    )
    monkeypatch.setattr(targets, "_propose_plan", Mock(return_value=_install_plan()))
    policy = Mock(return_value={"status": "ok"})
    installer = Mock(return_value={"status": "ok", "message": "installed"})
    monkeypatch.setattr(targets, "_check_list", policy)
    monkeypatch.setattr(targets.win_tool, "install_software", installer)
    monkeypatch.setattr(cleanup, "_resolve_private_target", lambda _: "10.0.0.8")

    result = targets.install_software_on_bound_endpoint.func("7-Zip", context)

    assert result["status"] == "ok"
    expected_host = "DEVICE-A" if scope == "registered_device" else "10.0.0.8"
    installer.assert_called_once_with(expected_host, "7-Zip")
    assert policy.call_count == 1
    assert policy.call_args.kwargs["target_host"] == expected_host
    assert list(inspect.signature(targets.install_software_on_bound_endpoint.func).parameters) == [
        "software_name",
        "tool_context",
    ]
