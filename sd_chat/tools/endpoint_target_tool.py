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

from . import aad_tool
from .identity_context_tool import ensure_identity_context_in_state


ENDPOINT_TARGET_BINDING_STATE_KEY = "endpoint_target_binding"
ENDPOINT_TARGET_CANDIDATES_STATE_KEY = "endpoint_target_candidates"
REGISTERED_DEVICE_SCOPE = "registered_device"
SHARED_WORKSTATION_SCOPE = "shared_virtual_workstation"
_VALID_SCOPES = {REGISTERED_DEVICE_SCOPE, SHARED_WORKSTATION_SCOPE}


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
        binding.update(
            {
                "source": "graph.registeredDevices",
                "allowed_hosts": hosts,
                "target_host": hosts[0] if len(hosts) == 1 else None,
            }
        )
        public.update(
            {
                "source": "graph.registeredDevices",
                "registered_devices": hosts,
                "requires_device_selection": len(hosts) > 1,
            }
        )
    else:
        assert shared_mapping is not None
        workstation_name = str(shared_mapping["instance_name"])
        binding.update(
            {
                "source": "trusted_shared_workstation_mapping",
                "mapping_fingerprint": _mapping_fingerprint(shared_mapping),
                "shared_virtual_workstation_name": workstation_name,
            }
        )
        public.update(
            {
                "source": "trusted_shared_workstation_mapping",
                "shared_virtual_workstation_available": True,
                "shared_virtual_workstation_name": workstation_name,
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
            return {
                "status": "ok",
                "resolution": "retained_binding",
                "binding": _bind(
                    state,
                    caller_upn,
                    REGISTERED_DEVICE_SCOPE,
                    registered_devices=devices,
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
                "I found your registered devices and a shared virtual workstation. "
                "Is this for a registered device, or for the shared virtual workstation?"
            )
        return {
            "status": "needs_input",
            "kind": "endpoint_target_scope",
            "question": question,
            "registered_devices": devices,
            "shared_virtual_workstation_available": True,
        }
    if devices:
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
        binding = _bind(
            state,
            caller_upn,
            REGISTERED_DEVICE_SCOPE,
            registered_devices=devices,
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


resolve_endpoint_targets = FunctionTool(func=resolve_endpoint_targets)
bind_endpoint_target_scope = FunctionTool(func=bind_endpoint_target_scope)

endpoint_target_tools = [resolve_endpoint_targets, bind_endpoint_target_scope]
