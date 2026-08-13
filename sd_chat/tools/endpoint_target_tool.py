"""Trusted endpoint-class disambiguation for ServiceDesk conversations.

The language model may select only a target *scope*. It can never provide a
hostname, IP address, project, zone, or instance as target input. Registered
devices are read from Microsoft Graph; the shared workstation is read from the
existing private UPN mapping. The selected scope is retained in ADK session
state. A controller-resolved workstation name may be returned for display.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

from google.adk.tools import FunctionTool, ToolContext

from ..planner.reasoning_composer import propose_plan as _propose_plan
from . import aad_tool, win_tool
from .identity_context_tool import ensure_identity_context_in_state
from .policy_tool import check_list as _check_list
from .sop_retriever import sop_retriever as _sop_retriever


ENDPOINT_TARGET_BINDING_STATE_KEY = "endpoint_target_binding"
ENDPOINT_TARGET_CANDIDATES_STATE_KEY = "endpoint_target_candidates"
REGISTERED_DEVICE_SCOPE = "registered_device"
SHARED_WORKSTATION_SCOPE = "shared_virtual_workstation"
_VALID_SCOPES = {REGISTERED_DEVICE_SCOPE, SHARED_WORKSTATION_SCOPE}
_INSTALL_ACTION_ID = "win.install_software"
_INSTALL_ACTION_TITLE = (
    "Install a software application on a user's device (approved catalog only)"
)


def _state(tool_context: ToolContext) -> Dict[str, Any]:
    state = tool_context.state
    if state is None:
        state = {}
        tool_context.state = state
    return state


def _error(code: str, message: str) -> Dict[str, Any]:
    return {"status": "error", "code": code, "message": message}


def _caller_upn(tool_context: ToolContext) -> Tuple[str, Optional[Dict[str, Any]]]:
    state = _state(tool_context)
    resolved = ensure_identity_context_in_state(state)
    identity = state.get("identity_context")
    if not resolved.get("ok") or not isinstance(identity, Mapping):
        return "", _error(
            "ENDPOINT_TARGET_CALLER_UNKNOWN",
            "The authenticated caller identity is unavailable.",
        )
    upn = str(identity.get("upn") or identity.get("primary_email") or "").strip().lower()
    if not upn:
        return "", _error(
            "ENDPOINT_TARGET_CALLER_UNKNOWN",
            "The authenticated caller UPN is unavailable.",
        )
    return upn, None


def _registered_devices(tool_context: ToolContext) -> Tuple[Optional[List[str]], Optional[Dict[str, Any]]]:
    result = aad_tool.aad_get_my_devices.func(tool_context)
    if not isinstance(result, Mapping) or result.get("ok") is not True:
        return None, _error(
            "REGISTERED_DEVICE_LOOKUP_FAILED",
            "Registered devices could not be resolved from Microsoft Entra ID.",
        )
    raw_hosts = result.get("allowed_hosts")
    if not isinstance(raw_hosts, list):
        return None, _error(
            "REGISTERED_DEVICE_LOOKUP_FAILED",
            "Microsoft Entra ID returned an invalid registered-device list.",
        )
    hosts: List[str] = []
    seen = set()
    for value in raw_hosts:
        host = str(value or "").strip()
        normalized = host.casefold()
        if host and normalized not in seen:
            seen.add(normalized)
            hosts.append(host)
    return hosts, None


def _shared_workstation(upn: str) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
    # Local import keeps the generic target controller independent from GCP
    # implementation initialization while reusing its strict mapping validator.
    from .gcp_virtual_desktop_tool import _MappingError, _mapping_for

    try:
        mapping = _mapping_for(upn)
    except KeyError:
        return None, None
    except _MappingError:
        return None, _error(
            "SHARED_WORKSTATION_MAPPING_INVALID",
            "The trusted shared-workstation mapping is missing or invalid.",
        )
    return mapping, None


def _mapping_fingerprint(mapping: Mapping[str, str]) -> str:
    stable = json.dumps(dict(mapping), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def _bind(
    state: Dict[str, Any],
    caller_upn: str,
    scope: str,
    registered_devices: Optional[List[str]] = None,
    selected_registered_device: Optional[str] = None,
    shared_mapping: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    binding: Dict[str, Any] = {
        "target_scope": scope,
        "caller_upn": caller_upn,
        "bound_at": int(time.time()),
    }
    public: Dict[str, Any] = {
        "target_scope": scope,
        "persisted": True,
    }
    if scope == REGISTERED_DEVICE_SCOPE:
        hosts = list(registered_devices or [])
        selected = str(selected_registered_device or "").strip()
        if not selected and len(hosts) == 1:
            selected = hosts[0]
        if not selected or selected.casefold() not in {
            host.casefold() for host in hosts
        }:
            raise ValueError("registered_device_not_verified")
        selected = next(host for host in hosts if host.casefold() == selected.casefold())
        binding.update(
            {
                "source": "entra",
                "trusted_device_id": selected.casefold(),
                "target_host": selected,
            }
        )
        public.update(
            {
                "source": "entra",
                "registered_device_name": selected,
            }
        )
    else:
        assert shared_mapping is not None
        workstation_name = str(
            shared_mapping.get("display_name") or "Shared Virtual Workstation"
        )
        binding.update(
            {
                "source": "trusted_shared_workstation_mapping",
                "mapping_fingerprint": _mapping_fingerprint(shared_mapping),
                "display_name": workstation_name,
            }
        )
        public.update(
            {
                "source": "trusted_shared_workstation_mapping",
                "shared_virtual_workstation_available": True,
                "display_name": workstation_name,
            }
        )
    state[ENDPOINT_TARGET_BINDING_STATE_KEY] = binding
    return public


def resolve_endpoint_targets(tool_context: ToolContext) -> Dict[str, Any]:
    """Resolve both trusted target classes and bind or ask one scope question."""
    state = _state(tool_context)
    caller_upn, caller_error = _caller_upn(tool_context)
    if caller_error is not None:
        return caller_error

    devices, device_error = _registered_devices(tool_context)
    if device_error is not None or devices is None:
        return device_error or _error(
            "REGISTERED_DEVICE_LOOKUP_FAILED",
            "Registered devices could not be resolved from Microsoft Entra ID.",
        )
    shared, shared_error = _shared_workstation(caller_upn)
    if shared_error is not None:
        return shared_error

    candidates = {
        "caller_upn": caller_upn,
        "registered_devices": devices,
        "shared_virtual_workstation_available": shared is not None,
        "resolved_at": int(time.time()),
    }
    state[ENDPOINT_TARGET_CANDIDATES_STATE_KEY] = candidates

    existing = state.get(ENDPOINT_TARGET_BINDING_STATE_KEY)
    if (
        isinstance(existing, Mapping)
        and str(existing.get("caller_upn") or "").strip().lower() == caller_upn
    ):
        existing_scope = existing.get("target_scope")
        if existing_scope == REGISTERED_DEVICE_SCOPE and devices:
            retained = str(existing.get("trusted_device_id") or "").casefold()
            selected = next(
                (device for device in devices if device.casefold() == retained), None
            )
            if selected is not None:
                return {
                    "status": "ok",
                    "resolution": "retained_binding",
                    "binding": _bind(
                        state,
                        caller_upn,
                        REGISTERED_DEVICE_SCOPE,
                        registered_devices=devices,
                        selected_registered_device=selected,
                    ),
                }
        if existing_scope == SHARED_WORKSTATION_SCOPE and shared is not None:
            return {
                "status": "ok",
                "resolution": "retained_binding",
                "binding": _bind(
                    state,
                    caller_upn,
                    SHARED_WORKSTATION_SCOPE,
                    shared_mapping=shared,
                ),
            }

    if devices and shared is not None:
        state[ENDPOINT_TARGET_BINDING_STATE_KEY] = None
        if len(devices) == 1:
            question = (
                f"I found your registered device '{devices[0]}'. Is this for that "
                "device, or for the shared virtual workstation?"
            )
        else:
            question = (
                "I found these registered devices: "
                + ", ".join(f"'{device}'" for device in devices)
                + ". Is this for one of those devices, or for the shared virtual workstation?"
            )
        return {
            "status": "needs_input",
            "kind": "endpoint_target_scope",
            "question": question,
            "registered_devices": devices,
            "shared_virtual_workstation_available": True,
        }
    if devices:
        if len(devices) > 1:
            state[ENDPOINT_TARGET_BINDING_STATE_KEY] = None
            return {
                "status": "needs_input",
                "kind": "registered_device_selection",
                "question": (
                    "Which registered device should I use: "
                    + ", ".join(f"'{device}'" for device in devices)
                    + "?"
                ),
                "registered_devices": devices,
                "shared_virtual_workstation_available": False,
            }
        return {
            "status": "ok",
            "resolution": "bound_only_available_scope",
            "binding": _bind(
                state,
                caller_upn,
                REGISTERED_DEVICE_SCOPE,
                registered_devices=devices,
            ),
        }
    if shared is not None:
        return {
            "status": "ok",
            "resolution": "bound_only_available_scope",
            "binding": _bind(
                state,
                caller_upn,
                SHARED_WORKSTATION_SCOPE,
                shared_mapping=shared,
            ),
        }
    state[ENDPOINT_TARGET_BINDING_STATE_KEY] = None
    return _error(
        "ENDPOINT_TARGET_NOT_FOUND",
        "No registered device or shared virtual workstation is available for the authenticated caller.",
    )


def bind_endpoint_target_scope(
    target_scope: str,
    tool_context: ToolContext,
    registered_device_name: str = "",
) -> Dict[str, Any]:
    """Resolve and persist an explicitly selected trusted target class.

    Use this tool when the user selects or asks to identify their registered
    device or shared virtual workstation. For the shared scope, the result
    includes the trusted controller-resolved workstation name for display.
    """
    requested = str(target_scope or "").strip().lower()
    if requested not in _VALID_SCOPES:
        return _error(
            "ENDPOINT_TARGET_SCOPE_INVALID",
            "The endpoint target scope must be registered_device or shared_virtual_workstation.",
        )
    state = _state(tool_context)
    caller_upn, caller_error = _caller_upn(tool_context)
    if caller_error is not None:
        return caller_error

    if requested == REGISTERED_DEVICE_SCOPE:
        devices, device_error = _registered_devices(tool_context)
        if device_error is not None or devices is None:
            return device_error or _error(
                "REGISTERED_DEVICE_LOOKUP_FAILED",
                "Registered devices could not be resolved from Microsoft Entra ID.",
            )
        if not devices:
            return _error(
                "REGISTERED_DEVICE_NOT_FOUND",
                "No registered device is available for the authenticated caller.",
            )
        requested_device = str(registered_device_name or "").strip()
        if len(devices) > 1 and not requested_device:
            return {
                "status": "needs_input",
                "kind": "registered_device_selection",
                "question": (
                    "Which registered device should I use: "
                    + ", ".join(f"'{device}'" for device in devices)
                    + "?"
                ),
                "registered_devices": devices,
            }
        selected = requested_device or devices[0]
        verified = next(
            (device for device in devices if device.casefold() == selected.casefold()),
            None,
        )
        if verified is None:
            return _error(
                "REGISTERED_DEVICE_NOT_VERIFIED",
                "That device is not in the authenticated caller's verified Entra device list.",
            )
        binding = _bind(
            state,
            caller_upn,
            REGISTERED_DEVICE_SCOPE,
            registered_devices=devices,
            selected_registered_device=verified,
        )
    else:
        shared, shared_error = _shared_workstation(caller_upn)
        if shared_error is not None:
            return shared_error
        if shared is None:
            return _error(
                "SHARED_WORKSTATION_NOT_FOUND",
                "No shared virtual workstation is mapped to the authenticated caller.",
            )
        binding = _bind(
            state,
            caller_upn,
            SHARED_WORKSTATION_SCOPE,
            shared_mapping=shared,
        )
    return {"status": "ok", "resolution": "scope_bound", "binding": binding}


def _resolve_bound_target(
    tool_context: ToolContext,
) -> Tuple[Optional[str], Optional[List[str]], Optional[Dict[str, Any]]]:
    """Re-resolve a retained binding and return only a controller-owned target."""
    state = _state(tool_context)
    caller_upn, caller_error = _caller_upn(tool_context)
    if caller_error is not None:
        return None, None, caller_error
    binding = state.get(ENDPOINT_TARGET_BINDING_STATE_KEY)
    if not isinstance(binding, Mapping) or _norm(binding.get("caller_upn")) != caller_upn:
        return None, None, _error(
            "ENDPOINT_TARGET_BINDING_REQUIRED",
            "Select the registered device or shared virtual workstation first.",
        )
    scope = binding.get("target_scope")
    if scope == REGISTERED_DEVICE_SCOPE:
        devices, lookup_error = _registered_devices(tool_context)
        if lookup_error is not None or devices is None:
            return None, None, lookup_error
        trusted_id = _norm(binding.get("trusted_device_id"))
        selected = next(
            (device for device in devices if device.casefold() == trusted_id), None
        )
        if selected is None:
            return None, None, _error(
                "REGISTERED_DEVICE_BINDING_STALE",
                "The selected registered device is no longer verified in Entra ID.",
            )
        return selected, devices, None
    if scope == SHARED_WORKSTATION_SCOPE:
        shared, lookup_error = _shared_workstation(caller_upn)
        if lookup_error is not None or shared is None:
            return None, None, lookup_error or _error(
                "SHARED_WORKSTATION_BINDING_STALE",
                "The shared-workstation assignment is no longer available.",
            )
        if (
            binding.get("source") != "trusted_shared_workstation_mapping"
            or binding.get("mapping_fingerprint") != _mapping_fingerprint(shared)
        ):
            return None, None, _error(
                "SHARED_WORKSTATION_BINDING_STALE",
                "The shared-workstation assignment changed; select it again.",
            )
        from .gcp_virtual_desktop_cleanup import _resolve_private_target

        try:
            private_target = _resolve_private_target(shared)
        except Exception:
            return None, None, _error(
                "SHARED_WORKSTATION_PRIVATE_TARGET_UNAVAILABLE",
                "The shared virtual workstation's private endpoint is unavailable.",
            )
        return private_target, [private_target], None
    return None, None, _error(
        "ENDPOINT_TARGET_BINDING_INVALID",
        "The retained endpoint target is invalid; select the endpoint again.",
    )


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def install_software_on_bound_endpoint(
    software_name: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """Run the existing governed installer against the retained trusted target."""
    target_host, allowed_hosts, target_error = _resolve_bound_target(tool_context)
    if target_error is not None or target_host is None or allowed_hosts is None:
        return target_error or _error(
            "ENDPOINT_TARGET_BINDING_INVALID", "The endpoint target could not be verified."
        )
    try:
        retrieved = _sop_retriever(
            query=f"approved software installation {software_name}",
            tool_context=tool_context,
        )
    except Exception:
        retrieved = {"status": "error"}
    snippets = retrieved.get("snippets") if isinstance(retrieved, Mapping) else None
    if (
        not isinstance(retrieved, Mapping)
        or retrieved.get("status") != "ok"
        or not isinstance(snippets, list)
        or not snippets
    ):
        return _error(
            "SOFTWARE_INSTALL_SOP_NOT_FOUND",
            "No approved software-installation SOP was found; installation was not run.",
        )
    grounded_sop = _INSTALL_ACTION_TITLE + "\n\n" + "\n\n".join(
        str(snippet) for snippet in snippets
    )
    try:
        planned = _propose_plan(
            user_text=_INSTALL_ACTION_TITLE,
            ctx_vars=["target_host", "package_id"],
            sop_texts=[grounded_sop],
        )
    except Exception:
        planned = {"status": "error"}
    plan = planned.get("plan") if isinstance(planned, Mapping) else None
    sequence = plan.get("tool_sequence") if isinstance(plan, Mapping) else None
    step = sequence[0] if isinstance(sequence, list) and len(sequence) == 1 else None
    if not (
        planned.get("status") == "ok"
        and isinstance(plan, Mapping)
        and plan.get("can_execute_fully") is True
        and plan.get("low_confidence") is False
        and plan.get("required_inputs") == []
        and plan.get("unmapped") == []
        and isinstance(step, Mapping)
        and step.get("action_id") == _INSTALL_ACTION_ID
        and step.get("tool") == "win_tool"
        and step.get("action") == "install_software"
    ):
        return _error(
            "SOFTWARE_INSTALL_PLAN_NOT_EXECUTABLE",
            "The approved software request did not produce one exact safe installation action.",
        )
    preconditions = plan.get("preconditions")
    if not isinstance(preconditions, list):
        return _error(
            "SOFTWARE_INSTALL_PLAN_NOT_EXECUTABLE",
            "The approved software-installation preconditions were invalid.",
        )
    policy = _check_list(
        preconditions=preconditions,
        target_host=target_host,
        caller_upn=_caller_upn(tool_context)[0],
        allowed_hosts_csv=",".join(allowed_hosts),
        software_name=software_name,
        tool_context=tool_context,
    )
    if not isinstance(policy, Mapping) or policy.get("status") != "ok":
        return _error(
            "SOFTWARE_INSTALL_POLICY_DENIED",
            "Software installation policy did not pass; installation was not run.",
        )
    result = win_tool.install_software(target_host, software_name)
    if not isinstance(result, Mapping):
        return _error(
            "SOFTWARE_INSTALL_FAILED", "The existing software installer returned no result."
        )
    return dict(result)


resolve_endpoint_targets = FunctionTool(func=resolve_endpoint_targets)
bind_endpoint_target_scope = FunctionTool(func=bind_endpoint_target_scope)
install_software_on_bound_endpoint = FunctionTool(
    func=install_software_on_bound_endpoint
)

endpoint_target_tools = [
    resolve_endpoint_targets,
    bind_endpoint_target_scope,
    install_software_on_bound_endpoint,
]
