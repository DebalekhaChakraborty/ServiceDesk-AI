"""Protected Active Directory account-status and remediation tools.

The current backend is an in-process deterministic demo fixture. Caller identity,
target lookup, manager lookup, and authorization remain the responsibility of the
existing root orchestrator and policy gate. Lock and disabled state are modeled
independently so unlock, enable, and password reset remain separate actions.
"""

import os
import threading
from typing import Any, Dict, Set

from google.adk.tools import FunctionTool, ToolContext

from .policy_tool import (
    ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY,
    ACCOUNT_DIAGNOSIS_ACTION_ID,
)


DEMO_BACKEND = "demo_ad_ds"


def _configured_account_mode() -> str:
    return (os.getenv("AD_ACCOUNT_MODE") or "off").strip().lower()


AD_ACCOUNT_MODE = _configured_account_mode()


def _normalize_upn(value: str) -> str:
    return (value or "").strip().lower()


def _configured_demo_upns(variable_name: str) -> Set[str]:
    configured = os.getenv(variable_name, "")
    return {
        normalized
        for item in configured.split(",")
        if (normalized := _normalize_upn(item))
    }


def _configured_demo_locked_upns() -> Set[str]:
    return _configured_demo_upns("AD_DEMO_LOCKED_UPNS")


def _configured_demo_disabled_upns() -> Set[str]:
    return _configured_demo_upns("AD_DEMO_DISABLED_UPNS")


# Initialized once when the application imports this module. Restarting the
# backend deliberately restores both environment-configured demo fixtures.
_demo_locked_upns = _configured_demo_locked_upns()
_demo_disabled_upns = _configured_demo_disabled_upns()
_demo_state_lock = threading.Lock()


def _detail_key(operation: str) -> str:
    return "account" if operation == "status" else operation


def _backend_error(operation: str, target_upn: str) -> Dict[str, Any]:
    backend = AD_ACCOUNT_MODE or "unconfigured"
    if backend == "off":
        code = "AD_ACCOUNT_BACKEND_OFF"
        message = (
            "Active Directory account-status automation is off. "
            "Configure AD_ACCOUNT_MODE=demo explicitly to use the demo backend."
        )
    elif backend == "ad_ds":
        code = "AD_DS_BACKEND_NOT_CONFIGURED"
        message = "The Active Directory Domain Services backend is not configured."
    else:
        code = "AD_ACCOUNT_MODE_INVALID"
        message = (
            f"Unsupported AD account mode '{backend}'. "
            "Configure AD_ACCOUNT_MODE=demo."
        )

    result: Dict[str, Any] = {
        "status": "error",
        "code": code,
        "message": message,
        "stdout": "",
        "stderr": message,
    }
    result[_detail_key(operation)] = {
        "status": "error",
        "target_upn": target_upn,
        "backend": backend,
        "message": message,
        "error": code,
    }
    return result


def _invalid_target(operation: str) -> Dict[str, Any]:
    message = "A resolved target UPN is required for the account operation."
    result: Dict[str, Any] = {
        "status": "error",
        "code": "TARGET_UPN_REQUIRED",
        "message": message,
        "stdout": "",
        "stderr": message,
    }
    result[_detail_key(operation)] = {
        "status": "error",
        "target_upn": "",
        "backend": DEMO_BACKEND if AD_ACCOUNT_MODE == "demo" else AD_ACCOUNT_MODE,
        "message": message,
        "error": "TARGET_UPN_REQUIRED",
    }
    return result


def _authorization_error(operation: str, target_upn: str) -> Dict[str, Any]:
    message = (
        "A successful action-bound caller_is_self_or_manager policy check for "
        "this exact target and operation is required before accessing Active "
        "Directory account state."
    )
    result: Dict[str, Any] = {
        "status": "error",
        "code": "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED",
        "message": message,
        "stdout": "",
        "stderr": message,
    }
    result[_detail_key(operation)] = {
        "status": "error",
        "target_upn": target_upn,
        "backend": DEMO_BACKEND,
        "message": message,
        "error": "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED",
    }
    return result


def _is_authorized_target(
    tool_context: ToolContext,
    target_upn: str,
    action_id: str,
) -> bool:
    state = tool_context.state if tool_context is not None else None
    if state is None:
        return False
    grant = state.get(ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY)
    return bool(
        isinstance(grant, dict)
        and grant.get("authorized") is True
        and grant.get("policy") == "caller_is_self_or_manager"
        and _normalize_upn(str(grant.get("target_upn") or "")) == target_upn
        and grant.get("action_id") == action_id
    )


def _recommended_action(enabled: bool, locked: bool) -> str:
    if not enabled:
        return "enable"
    if locked:
        return "unlock"
    return "password_reset"


def _account_snapshot(target_upn: str) -> Dict[str, Any]:
    locked = target_upn in _demo_locked_upns
    enabled = target_upn not in _demo_disabled_upns
    return {
        "target_upn": target_upn,
        "locked": locked,
        "enabled": enabled,
        "backend": DEMO_BACKEND,
        "recommended_action": _recommended_action(enabled, locked),
    }


def _get_account_status(
    tool_context: ToolContext,
    target_upn: str,
) -> Dict[str, Any]:
    normalized_upn = _normalize_upn(target_upn)
    if not normalized_upn:
        return _invalid_target("status")
    if AD_ACCOUNT_MODE != "demo":
        return _backend_error("status", normalized_upn)
    if not _is_authorized_target(
        tool_context,
        normalized_upn,
        ACCOUNT_DIAGNOSIS_ACTION_ID,
    ):
        return _authorization_error("status", normalized_upn)

    with _demo_state_lock:
        account = _account_snapshot(normalized_upn)

    state = tool_context.state
    if state is None:
        state = {}
        tool_context.state = state
    state["account_access_diagnosis"] = dict(account)

    return {
        "status": "ok",
        "account": account,
    }


def ad_get_account_status(
    tool_context: ToolContext,
    target_upn: str,
) -> Dict[str, Any]:
    """Return enabled and locked state for one authorized account target."""
    return _get_account_status(tool_context, target_upn)


def ad_check_account_lock_status(
    tool_context: ToolContext,
    target_upn: str,
) -> Dict[str, Any]:
    """Compatibility wrapper; new orchestration should use ad_get_account_status."""
    return _get_account_status(tool_context, target_upn)


def ad_unlock_account(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """Clear lockout only; disabled state and password remain unchanged."""
    normalized_upn = _normalize_upn(target_upn)
    if not normalized_upn:
        return _invalid_target("unlock")
    if AD_ACCOUNT_MODE != "demo":
        return _backend_error("unlock", normalized_upn)
    if not _is_authorized_target(
        tool_context,
        normalized_upn,
        "ad.unlock_account",
    ):
        return _authorization_error("unlock", normalized_upn)

    with _demo_state_lock:
        was_locked = normalized_upn in _demo_locked_upns
        _demo_locked_upns.discard(normalized_upn)
        is_locked = normalized_upn in _demo_locked_upns

    if was_locked:
        message = f"Account {normalized_upn} was unlocked successfully."
    else:
        message = f"Account {normalized_upn} is already unlocked; no change was needed."

    return {
        "status": "ok",
        "unlock": {
            "status": "ok",
            "target_upn": normalized_upn,
            "was_locked": was_locked,
            "is_locked": is_locked,
            "backend": DEMO_BACKEND,
            "message": message,
        },
    }


def ad_enable_account(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """Enable an account only; lock state and password remain unchanged."""
    normalized_upn = _normalize_upn(target_upn)
    if not normalized_upn:
        return _invalid_target("enable")
    if AD_ACCOUNT_MODE != "demo":
        return _backend_error("enable", normalized_upn)
    if not _is_authorized_target(
        tool_context,
        normalized_upn,
        "ad.enable_account",
    ):
        return _authorization_error("enable", normalized_upn)

    with _demo_state_lock:
        was_enabled = normalized_upn not in _demo_disabled_upns
        _demo_disabled_upns.discard(normalized_upn)
        is_enabled = normalized_upn not in _demo_disabled_upns

    if was_enabled:
        message = f"Account {normalized_upn} is already enabled; no change was needed."
    else:
        message = f"Account {normalized_upn} was enabled successfully."

    return {
        "status": "ok",
        "enable": {
            "status": "ok",
            "target_upn": normalized_upn,
            "was_enabled": was_enabled,
            "is_enabled": is_enabled,
            "backend": DEMO_BACKEND,
            "message": message,
        },
    }


ad_get_account_status = FunctionTool(func=ad_get_account_status)
ad_check_account_lock_status = FunctionTool(func=ad_check_account_lock_status)
ad_unlock_account = FunctionTool(func=ad_unlock_account)
ad_enable_account = FunctionTool(func=ad_enable_account)

ad_account_tools = [
    ad_get_account_status,
    ad_unlock_account,
    ad_enable_account,
]
