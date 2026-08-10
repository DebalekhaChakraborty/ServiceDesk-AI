"""Active Directory account lock-state tools.

The current backend is an in-process demo fixture. Caller identity, target lookup,
manager lookup, and authorization remain the responsibility of the existing
orchestrator and policy gate; only the AD DS lock operation is simulated here.
"""

import os
import threading
from typing import Any, Dict, Set

from google.adk.tools import FunctionTool, ToolContext


AD_UNLOCK_MODE = (os.getenv("AD_UNLOCK_MODE", "demo") or "demo").strip().lower()
DEMO_BACKEND = "demo_ad_ds"


def _normalize_upn(value: str) -> str:
    return (value or "").strip().lower()


def _configured_demo_locked_upns() -> Set[str]:
    configured = os.getenv("AD_UNLOCK_DEMO_LOCKED_UPNS", "")
    return {
        normalized
        for item in configured.split(",")
        if (normalized := _normalize_upn(item))
    }


# Initialized once when the application imports this module. Restarting the
# backend deliberately restores the environment-configured demo fixture.
_demo_locked_upns = _configured_demo_locked_upns()
_demo_state_lock = threading.Lock()


def _backend_error(operation: str, target_upn: str) -> Dict[str, Any]:
    backend = AD_UNLOCK_MODE or "unconfigured"
    if backend == "ad_ds":
        code = "AD_DS_BACKEND_NOT_CONFIGURED"
        message = (
            "The Active Directory Domain Services unlock backend is not configured."
        )
    else:
        code = "AD_UNLOCK_MODE_INVALID"
        message = (
            f"Unsupported AD account unlock mode '{backend}'. "
            "Configure AD_UNLOCK_MODE=demo."
        )

    result: Dict[str, Any] = {
        "status": "error",
        "code": code,
        "message": message,
        "stdout": "",
        "stderr": message,
    }
    detail_key = "account" if operation == "check" else "unlock"
    result[detail_key] = {
        "status": "error",
        "target_upn": target_upn,
        "backend": backend,
        "message": message,
        "error": code,
    }
    return result


def _invalid_target(operation: str) -> Dict[str, Any]:
    message = "A resolved target UPN is required for the account unlock operation."
    result: Dict[str, Any] = {
        "status": "error",
        "code": "TARGET_UPN_REQUIRED",
        "message": message,
        "stdout": "",
        "stderr": message,
    }
    detail_key = "account" if operation == "check" else "unlock"
    result[detail_key] = {
        "status": "error",
        "target_upn": "",
        "backend": DEMO_BACKEND if AD_UNLOCK_MODE == "demo" else AD_UNLOCK_MODE,
        "message": message,
        "error": "TARGET_UPN_REQUIRED",
    }
    return result


def ad_check_account_lock_status(
    tool_context: ToolContext,
    target_upn: str,
) -> Dict[str, Any]:
    """Check whether a resolved Active Directory account is locked.

    Authorization must be completed by ``check_list`` before this tool is called.
    In demo mode, the state comes from the process-local deterministic fixture.
    """
    normalized_upn = _normalize_upn(target_upn)
    if not normalized_upn:
        return _invalid_target("check")
    if AD_UNLOCK_MODE != "demo":
        return _backend_error("check", normalized_upn)

    with _demo_state_lock:
        locked = normalized_upn in _demo_locked_upns

    account = {
        "target_upn": normalized_upn,
        "locked": locked,
        "backend": DEMO_BACKEND,
    }

    # The root orchestrator uses this only after authorizing a diagnostic. It
    # lets a later confirmation refer to the same resolved account rather than
    # asking the user to repeat a UPN or attempting a fresh lookup.
    state = tool_context.state
    if state is None:
        state = {}
        tool_context.state = state
    state["account_access_diagnosis"] = dict(account)

    return {
        "status": "ok",
        "account": account,
    }


def ad_unlock_account(target_upn: str) -> Dict[str, Any]:
    """Unlock a resolved Active Directory account.

    This tool never enables an account or resets a password. The existing
    orchestrator must run the self-or-manager policy gate exactly once before
    invoking it.
    """
    normalized_upn = _normalize_upn(target_upn)
    if not normalized_upn:
        return _invalid_target("unlock")
    if AD_UNLOCK_MODE != "demo":
        return _backend_error("unlock", normalized_upn)

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


ad_check_account_lock_status = FunctionTool(func=ad_check_account_lock_status)
ad_unlock_account = FunctionTool(func=ad_unlock_account)

ad_account_tools = [
    ad_check_account_lock_status,
    ad_unlock_account,
]
