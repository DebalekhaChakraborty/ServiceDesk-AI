"""Protected Microsoft Entra / Active Directory account tools.

Runtime account status and enablement can use the repository's existing Microsoft
Graph application credentials. The deterministic demo backend remains available
only when explicitly selected for isolated development and unit tests. Caller
identity, target lookup, manager lookup, and authorization remain the
responsibility of the existing root orchestrator and policy gate.

Microsoft Graph exposes the authoritative ``accountEnabled`` property, but it does
not expose a current AD DS lockout boolean on the user resource. Graph-backed
responses therefore report lock state as unknown instead of claiming that the
account is unlocked. A separately configured AD DS connector is required for a
real lock check or unlock operation.
"""

import os
import threading
import time
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import quote

from google.adk.tools import FunctionTool, ToolContext

from . import aad_tool
from .policy_tool import (
    ACCOUNT_DIAGNOSIS_ACTION_ID,
    consume_account_access_authorization,
)


DEMO_BACKEND = "demo_ad_ds"
GRAPH_BACKEND = "microsoft_graph"

# Microsoft Graph can briefly return the pre-update accountEnabled value after a
# successful PATCH. Verify the accepted mutation for one minute without issuing
# the mutation a second time.
GRAPH_ENABLE_VERIFICATION_WINDOW_SECONDS = 60
GRAPH_ENABLE_VERIFICATION_INTERVAL_SECONDS = 5

GRAPH_ACCOUNT_SELECT_FIELDS = (
    "id",
    "displayName",
    "userPrincipalName",
    "mail",
    "accountEnabled",
    "userType",
    "createdDateTime",
    "lastPasswordChangeDateTime",
    "passwordPolicies",
    "onPremisesSyncEnabled",
    "onPremisesLastSyncDateTime",
    "onPremisesDistinguishedName",
    "creationType",
    "externalUserState",
    "externalUserStateChangeDateTime",
    "usageLocation",
    "employeeId",
    "employeeType",
    "jobTitle",
    "department",
    "companyName",
    "officeLocation",
)


def _configured_account_mode() -> str:
    return (os.getenv("AD_ACCOUNT_MODE") or "off").strip().lower()


AD_ACCOUNT_MODE = _configured_account_mode()


def _normalize_upn(value: str) -> str:
    return (value or "").strip().lower()


# Demo state is deliberately process-local and has no environment-driven user
# fixtures. Unit tests inject state directly; runtime account state comes from Graph.
_demo_locked_upns: Set[str] = set()
_demo_disabled_upns: Set[str] = set()
_demo_state_lock = threading.Lock()


def _detail_key(operation: str) -> str:
    return "account" if operation == "status" else operation


def _backend_error(operation: str, target_upn: str) -> Dict[str, Any]:
    backend = AD_ACCOUNT_MODE or "unconfigured"
    if backend == "off":
        code = "AD_ACCOUNT_BACKEND_OFF"
        message = (
            "Active Directory account-status automation is off. "
            "Configure AD_ACCOUNT_MODE=graph to use the real Microsoft Graph backend."
        )
    elif backend == "ad_ds":
        code = "AD_DS_BACKEND_NOT_CONFIGURED"
        message = "The Active Directory Domain Services backend is not configured."
    else:
        code = "AD_ACCOUNT_MODE_INVALID"
        message = (
            f"Unsupported AD account mode '{backend}'. "
            "Configure AD_ACCOUNT_MODE=graph for real directory state."
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


def _graph_error_message(response: Any) -> str:
    """Extract a useful Graph error without exposing request credentials."""
    try:
        payload = response.json()
    except Exception:
        payload = None

    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            code = str(error.get("code") or "").strip()
            message = str(error.get("message") or "").strip()
            if code and message:
                return f"{code}: {message}"
            if message:
                return message

    text = str(getattr(response, "text", "") or "").strip()
    return text or "Microsoft Graph returned an unspecified error."


def _graph_operation_error(
    operation: str,
    target_upn: str,
    code: str,
    message: str,
    http_status: Optional[int] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "status": "error",
        "code": code,
        "message": message,
        "stdout": "",
        "stderr": message,
    }
    if http_status is not None:
        result["http_status"] = http_status
    result[_detail_key(operation)] = {
        "status": "error",
        "target_upn": target_upn,
        "backend": GRAPH_BACKEND,
        "message": message,
        "error": code,
    }
    return result


def _normalize_graph_profile(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return relevant account metadata with stable, model-friendly names."""
    return {
        "aad_object_id": data.get("id"),
        "display_name": data.get("displayName"),
        "user_principal_name": data.get("userPrincipalName"),
        "mail": data.get("mail"),
        "account_enabled": data.get("accountEnabled"),
        "user_type": data.get("userType"),
        "created_date_time": data.get("createdDateTime"),
        "last_password_change_date_time": data.get("lastPasswordChangeDateTime"),
        "password_policies": data.get("passwordPolicies"),
        "on_premises_sync_enabled": data.get("onPremisesSyncEnabled"),
        "on_premises_last_sync_date_time": data.get("onPremisesLastSyncDateTime"),
        "on_premises_distinguished_name": data.get("onPremisesDistinguishedName"),
        "creation_type": data.get("creationType"),
        "external_user_state": data.get("externalUserState"),
        "external_user_state_change_date_time": data.get(
            "externalUserStateChangeDateTime"
        ),
        "usage_location": data.get("usageLocation"),
        "employee_id": data.get("employeeId"),
        "employee_type": data.get("employeeType"),
        "job_title": data.get("jobTitle"),
        "department": data.get("department"),
        "company_name": data.get("companyName"),
        "office_location": data.get("officeLocation"),
    }


def _read_graph_account(
    target_upn: str,
    operation: str = "status",
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Read one real Entra account from Microsoft Graph."""
    path = f"users/{quote(target_upn, safe='')}"
    params = {"$select": ",".join(GRAPH_ACCOUNT_SELECT_FIELDS)}
    try:
        response = aad_tool._graph_get(path, params=params)
    except Exception as exc:
        message = f"Microsoft Graph account lookup failed: {exc}"
        return None, _graph_operation_error(
            operation,
            target_upn,
            "GRAPH_ACCOUNT_LOOKUP_FAILED",
            message,
        )

    if response.status_code != 200:
        message = (
            f"Microsoft Graph account lookup returned {response.status_code}: "
            f"{_graph_error_message(response)}"
        )
        return None, _graph_operation_error(
            operation,
            target_upn,
            "GRAPH_ACCOUNT_LOOKUP_FAILED",
            message,
            response.status_code,
        )

    try:
        data = response.json()
    except Exception as exc:
        message = f"Microsoft Graph returned invalid account JSON: {exc}"
        return None, _graph_operation_error(
            operation,
            target_upn,
            "GRAPH_ACCOUNT_RESPONSE_INVALID",
            message,
            response.status_code,
        )

    if not isinstance(data, dict) or not isinstance(data.get("accountEnabled"), bool):
        message = (
            "Microsoft Graph did not return the required boolean accountEnabled "
            "property; account state was not inferred."
        )
        return None, _graph_operation_error(
            operation,
            target_upn,
            "GRAPH_ACCOUNT_ENABLED_MISSING",
            message,
            response.status_code,
        )

    return _normalize_graph_profile(data), None


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
        "backend": (
            GRAPH_BACKEND if AD_ACCOUNT_MODE == "graph" else DEMO_BACKEND
        ),
        "message": message,
        "error": "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED",
    }
    return result


def _is_authorized_target(
    tool_context: ToolContext,
    target_upn: str,
    action_id: str,
) -> bool:
    return consume_account_access_authorization(
        tool_context,
        target_upn,
        action_id,
        require_identity_verification=AD_ACCOUNT_MODE == "graph",
    )


def _recommended_action(enabled: bool, locked: Optional[bool]) -> str:
    if not enabled:
        return "enable"
    if locked is True:
        return "unlock"
    if locked is False:
        return "password_reset"
    return "investigate_sign_in"


def _demo_account_snapshot(target_upn: str) -> Dict[str, Any]:
    locked = target_upn in _demo_locked_upns
    enabled = target_upn not in _demo_disabled_upns
    return {
        "target_upn": target_upn,
        "locked": locked,
        "enabled": enabled,
        "backend": DEMO_BACKEND,
        "recommended_action": _recommended_action(enabled, locked),
    }


def _graph_account_snapshot(
    target_upn: str,
    profile: Dict[str, Any],
) -> Dict[str, Any]:
    enabled = profile["account_enabled"]
    locked = None
    return {
        "target_upn": target_upn,
        "locked": locked,
        "lock_state_available": False,
        "lock_state_message": (
            "Current AD DS or Microsoft Entra smart-lockout state is not exposed "
            "by the Microsoft Graph user resource and was not inferred."
        ),
        "enabled": enabled,
        "backend": GRAPH_BACKEND,
        "recommended_action": _recommended_action(enabled, locked),
        "directory_profile": profile,
    }


def _get_account_status(
    tool_context: ToolContext,
    target_upn: str,
) -> Dict[str, Any]:
    normalized_upn = _normalize_upn(target_upn)
    if not normalized_upn:
        return _invalid_target("status")
    if not _is_authorized_target(
        tool_context,
        normalized_upn,
        ACCOUNT_DIAGNOSIS_ACTION_ID,
    ):
        return _authorization_error("status", normalized_upn)

    if AD_ACCOUNT_MODE == "demo":
        with _demo_state_lock:
            account = _demo_account_snapshot(normalized_upn)
    elif AD_ACCOUNT_MODE == "graph":
        profile, error = _read_graph_account(normalized_upn)
        if error is not None:
            return error
        if profile is None:
            return _graph_operation_error(
                "status",
                normalized_upn,
                "GRAPH_ACCOUNT_RESPONSE_INVALID",
                "Microsoft Graph account lookup returned no profile.",
            )
        account = _graph_account_snapshot(normalized_upn, profile)
    else:
        return _backend_error("status", normalized_upn)

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
    """Return real Entra account metadata and any available lock state."""
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
    if not _is_authorized_target(
        tool_context,
        normalized_upn,
        "ad.unlock_account",
    ):
        return _authorization_error("unlock", normalized_upn)

    if AD_ACCOUNT_MODE == "graph":
        message = (
            "Microsoft Graph does not expose a current AD DS lockout boolean or "
            "an administrative unlock operation for this account. Configure a "
            "real AD DS connector before attempting unlock; no change was made."
        )
        return _graph_operation_error(
            "unlock",
            normalized_upn,
            "GRAPH_ACCOUNT_UNLOCK_UNAVAILABLE",
            message,
        )
    if AD_ACCOUNT_MODE != "demo":
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


def _enable_graph_account(target_upn: str) -> Dict[str, Any]:
    """Enable one real Entra account and verify the persisted Graph value."""
    current, error = _read_graph_account(target_upn, operation="enable")
    if error is not None:
        return error
    if current is None:
        return _graph_operation_error(
            "enable",
            target_upn,
            "GRAPH_ACCOUNT_RESPONSE_INVALID",
            "Microsoft Graph account lookup returned no profile.",
        )

    was_enabled = current["account_enabled"]
    if not was_enabled:
        path = f"users/{quote(target_upn, safe='')}"
        try:
            response = aad_tool._graph_patch(path, {"accountEnabled": True})
        except Exception as exc:
            message = f"Microsoft Graph account enable failed: {exc}"
            return _graph_operation_error(
                "enable",
                target_upn,
                "GRAPH_ACCOUNT_ENABLE_FAILED",
                message,
            )

        if response.status_code not in {200, 204}:
            message = (
                f"Microsoft Graph account enable returned {response.status_code}: "
                f"{_graph_error_message(response)}"
            )
            return _graph_operation_error(
                "enable",
                target_upn,
                "GRAPH_ACCOUNT_ENABLE_FAILED",
                message,
                response.status_code,
            )

    verification_attempts = 0
    max_verification_attempts = (
        GRAPH_ENABLE_VERIFICATION_WINDOW_SECONDS
        // GRAPH_ENABLE_VERIFICATION_INTERVAL_SECONDS
    ) + 1
    verified = None
    verify_error = None
    for verification_attempts in range(1, max_verification_attempts + 1):
        verified, verify_error = _read_graph_account(target_upn, operation="enable")
        if verify_error is not None or (
            verified is not None and verified["account_enabled"] is True
        ):
            break
        if verification_attempts < max_verification_attempts:
            time.sleep(GRAPH_ENABLE_VERIFICATION_INTERVAL_SECONDS)

    if verify_error is not None:
        return verify_error
    if verified is None or verified["account_enabled"] is not True:
        message = (
            "Microsoft Graph accepted the enable operation but did not verify "
            f"accountEnabled=true within {GRAPH_ENABLE_VERIFICATION_WINDOW_SECONDS} "
            "seconds; success was not claimed."
        )
        result = _graph_operation_error(
            "enable",
            target_upn,
            "GRAPH_ACCOUNT_ENABLE_VERIFICATION_FAILED",
            message,
        )
        result["enable"].update(
            {
                "verification_attempts": verification_attempts,
                "verification_window_seconds": (
                    GRAPH_ENABLE_VERIFICATION_WINDOW_SECONDS
                ),
                "verification_interval_seconds": (
                    GRAPH_ENABLE_VERIFICATION_INTERVAL_SECONDS
                ),
            }
        )
        return result

    if was_enabled:
        message = f"Account {target_upn} is already enabled; no change was needed."
    else:
        message = f"Account {target_upn} was enabled successfully."

    return {
        "status": "ok",
        "enable": {
            "status": "ok",
            "target_upn": target_upn,
            "was_enabled": was_enabled,
            "is_enabled": True,
            "backend": GRAPH_BACKEND,
            "message": message,
            "directory_profile": verified,
            "verification_attempts": verification_attempts,
            "verification_window_seconds": GRAPH_ENABLE_VERIFICATION_WINDOW_SECONDS,
            "verification_interval_seconds": (
                GRAPH_ENABLE_VERIFICATION_INTERVAL_SECONDS
            ),
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
    if not _is_authorized_target(
        tool_context,
        normalized_upn,
        "ad.enable_account",
    ):
        return _authorization_error("enable", normalized_upn)

    if AD_ACCOUNT_MODE == "graph":
        return _enable_graph_account(normalized_upn)
    if AD_ACCOUNT_MODE != "demo":
        return _backend_error("enable", normalized_upn)

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
