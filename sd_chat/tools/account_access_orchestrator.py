"""Deterministic orchestration for protected account-access operations.

Gemini may decide that an account-access flow is relevant, but it does not own
the privileged sequence.  These tools bind the current session requester, exact
target, fresh Microsoft Graph manager relationship, registered-device evidence,
planner output, policy grant, and one atomic action in Python.

Registered devices are collected as security context.  They do not replace
self/manager authorization and do not grant permission to remediate an endpoint.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit

from google.adk.tools import FunctionTool, ToolContext

from sd_chat.planner.reasoning_composer import propose_plan

from . import aad_tool, ad_account_tool
from .identity_context_tool import ensure_identity_context_in_state
from .policy_tool import (
    AAD_MANAGER_LOOKUP_STATE_KEY,
    ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY,
    ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY,
    check_list,
)
from .sop_retriever import sop_retriever


IDENTITY_VERIFICATION_STATE_KEY = ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY
ACCOUNT_ACCESS_OFFER_STATE_KEY = "account_access_offer"
OFFER_TTL_SECONDS = 10 * 60

_USER_SELECT = "id,displayName,userPrincipalName,mail"
_DEVICE_SELECT = "id,displayName,deviceId,operatingSystem"

_ACTION_SPECS: Dict[str, Dict[str, str]] = {
    "ad.unlock_account": {
        "recommendation": "unlock",
        "query": "Active Directory account unlock remediation procedure",
        "label": "Unlock the target Active Directory account",
    },
    "ad.enable_account": {
        "recommendation": "enable",
        "query": "Active Directory disabled account enable remediation procedure",
        "label": "Enable the target Active Directory account",
    },
    "aad.reset_password": {
        "recommendation": "password_reset",
        "query": "Azure Active Directory password reset remediation procedure",
        "label": "Reset Azure AD password for a user",
    },
}

_RECOMMENDATION_TO_ACTION = {
    spec["recommendation"]: action_id for action_id, spec in _ACTION_SPECS.items()
}

_SIGN_IN_INVESTIGATION_NEXT_STEP = {
    "kind": "sign_in_intake",
    "question": (
        "Which application or system is affected, and what exact error is shown?"
    ),
}


def _norm_upn(value: Any) -> str:
    return str(value or "").strip().lower()


def _state(tool_context: ToolContext) -> Dict[str, Any]:
    state = tool_context.state
    if state is None:
        state = {}
        tool_context.state = state
    return state


def _error(code: str, message: str, **details: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "status": "error",
        "code": code,
        "message": message,
    }
    if details:
        result["details"] = details
    return result


def _graph_error(response: Any) -> str:
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
    return f"Microsoft Graph returned HTTP {getattr(response, 'status_code', 'unknown')}."


def _read_directory_user(user_upn: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Resolve one exact Graph user without exposing its state before policy."""
    try:
        response = aad_tool._graph_get(
            f"users/{quote(user_upn, safe='')}",
            params={"$select": _USER_SELECT},
        )
    except Exception as exc:
        return None, _error(
            "DIRECTORY_USER_LOOKUP_FAILED",
            f"Microsoft Graph user lookup failed: {exc}",
        )
    if response.status_code != 200:
        return None, _error(
            "DIRECTORY_USER_LOOKUP_FAILED",
            _graph_error(response),
            http_status=response.status_code,
        )
    try:
        raw = response.json()
    except Exception as exc:
        return None, _error(
            "DIRECTORY_USER_RESPONSE_INVALID",
            f"Microsoft Graph returned invalid user JSON: {exc}",
        )
    if not isinstance(raw, dict):
        return None, _error(
            "DIRECTORY_USER_RESPONSE_INVALID",
            "Microsoft Graph returned an invalid user record.",
        )
    resolved_upn = _norm_upn(raw.get("userPrincipalName") or raw.get("mail"))
    object_id = str(raw.get("id") or "").strip()
    if not resolved_upn or not object_id or resolved_upn != user_upn:
        return None, _error(
            "DIRECTORY_IDENTITY_MISMATCH",
            "The exact requested directory identity could not be verified.",
        )
    return {
        "upn": resolved_upn,
        "aad_object_id": object_id,
        "display_name": raw.get("displayName"),
        "mail": raw.get("mail"),
    }, None


def _read_manager(target_upn: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        response = aad_tool._graph_get(
            f"users/{quote(target_upn, safe='')}/manager",
            params={"$select": _USER_SELECT},
        )
    except Exception as exc:
        return None, _error(
            "DIRECTORY_MANAGER_LOOKUP_FAILED",
            f"Microsoft Graph manager lookup failed: {exc}",
        )
    if response.status_code == 404:
        return None, None
    if response.status_code != 200:
        return None, _error(
            "DIRECTORY_MANAGER_LOOKUP_FAILED",
            _graph_error(response),
            http_status=response.status_code,
        )
    try:
        raw = response.json()
    except Exception as exc:
        return None, _error(
            "DIRECTORY_MANAGER_RESPONSE_INVALID",
            f"Microsoft Graph returned invalid manager JSON: {exc}",
        )
    if not isinstance(raw, dict):
        return None, _error(
            "DIRECTORY_MANAGER_RESPONSE_INVALID",
            "Microsoft Graph returned an invalid manager record.",
        )
    manager_upn = _norm_upn(raw.get("userPrincipalName") or raw.get("mail"))
    manager_id = str(raw.get("id") or "").strip()
    if not manager_upn or not manager_id:
        return None, _error(
            "DIRECTORY_MANAGER_RESPONSE_INVALID",
            "Microsoft Graph did not return a usable manager identity.",
        )
    return {
        "upn": manager_upn,
        "aad_object_id": manager_id,
        "display_name": raw.get("displayName"),
    }, None


def _next_graph_path(next_link: str) -> Optional[str]:
    parsed = urlsplit(next_link)
    marker = "/v1.0/"
    if marker not in parsed.path:
        return None
    path = parsed.path.split(marker, 1)[1]
    return f"{path}?{parsed.query}" if parsed.query else path


def _read_registered_devices(
    user_upn: str,
) -> Tuple[Optional[List[Dict[str, Any]]], Optional[Dict[str, Any]]]:
    """Read all pages of a user's registered Graph devices."""
    path = f"users/{quote(user_upn, safe='')}/registeredDevices"
    params: Optional[Dict[str, str]] = {"$select": _DEVICE_SELECT}
    devices: List[Dict[str, Any]] = []

    for _ in range(20):
        try:
            response = aad_tool._graph_get(path, params=params)
        except Exception as exc:
            return None, _error(
                "DIRECTORY_DEVICE_LOOKUP_FAILED",
                f"Microsoft Graph registered-device lookup failed: {exc}",
            )
        if response.status_code != 200:
            return None, _error(
                "DIRECTORY_DEVICE_LOOKUP_FAILED",
                _graph_error(response),
                http_status=response.status_code,
            )
        try:
            payload = response.json()
        except Exception as exc:
            return None, _error(
                "DIRECTORY_DEVICE_RESPONSE_INVALID",
                f"Microsoft Graph returned invalid device JSON: {exc}",
            )
        values = payload.get("value") if isinstance(payload, dict) else None
        if not isinstance(values, list):
            return None, _error(
                "DIRECTORY_DEVICE_RESPONSE_INVALID",
                "Microsoft Graph returned an invalid registered-device list.",
            )
        for raw in values:
            if not isinstance(raw, dict):
                continue
            devices.append(
                {
                    "directory_object_id": raw.get("id"),
                    "device_id": raw.get("deviceId"),
                    "display_name": raw.get("displayName"),
                    "operating_system": raw.get("operatingSystem"),
                }
            )
        next_link = payload.get("@odata.nextLink")
        if not next_link:
            return devices, None
        path = _next_graph_path(str(next_link)) or ""
        params = None
        if not path:
            return None, _error(
                "DIRECTORY_DEVICE_PAGINATION_INVALID",
                "Microsoft Graph returned an invalid device pagination link.",
            )

    return None, _error(
        "DIRECTORY_DEVICE_PAGINATION_LIMIT",
        "Registered-device lookup exceeded the safe pagination limit.",
    )


def _device_fingerprint(devices: List[Dict[str, Any]]) -> str:
    stable = json.dumps(devices, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def _public_devices(devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "display_name": device.get("display_name"),
            "operating_system": device.get("operating_system"),
        }
        for device in devices
    ]


def _invalidate_security_state(state: Dict[str, Any]) -> None:
    state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] = None
    state[AAD_MANAGER_LOOKUP_STATE_KEY] = None
    state[IDENTITY_VERIFICATION_STATE_KEY] = None


def _verify_identity(
    tool_context: ToolContext,
    target_upn: str,
    plan: Optional[Dict[str, Any]] = None,
    expected_action_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build fresh, target-bound Graph evidence and run the canonical policy."""
    state = _state(tool_context)
    _invalidate_security_state(state)

    normalized_target = _norm_upn(target_upn)
    if not normalized_target or "@" not in normalized_target:
        return _error(
            "TARGET_UPN_REQUIRED",
            "An exact directory UPN is required for identity verification.",
        )

    identity_result = ensure_identity_context_in_state(state)
    identity = state.get("identity_context")
    if not identity_result.get("ok") or not isinstance(identity, dict):
        return _error(
            "REQUESTER_IDENTITY_MISSING",
            "The requesting user's session identity is unavailable.",
        )
    caller_upn = _norm_upn(identity.get("upn") or identity.get("primary_email"))
    if not caller_upn:
        return _error(
            "REQUESTER_IDENTITY_MISSING",
            "The requesting user's session identity has no usable UPN.",
        )

    caller, caller_error = _read_directory_user(caller_upn)
    if caller_error is not None or caller is None:
        return caller_error or _error(
            "REQUESTER_DIRECTORY_VERIFICATION_FAILED",
            "The requesting user could not be verified in Microsoft Graph.",
        )
    claimed_object_id = str(identity.get("aad_object_id") or "").strip().lower()
    if claimed_object_id and claimed_object_id != caller["aad_object_id"].lower():
        return _error(
            "REQUESTER_DIRECTORY_ID_MISMATCH",
            "The session requester does not match the Microsoft Graph object.",
        )

    target, target_error = _read_directory_user(normalized_target)
    if target_error is not None or target is None:
        return target_error or _error(
            "TARGET_DIRECTORY_VERIFICATION_FAILED",
            "The target user could not be verified in Microsoft Graph.",
        )

    manager, manager_error = _read_manager(normalized_target)
    caller_is_self = caller_upn == normalized_target
    if manager_error is not None:
        return manager_error
    manager_upn = _norm_upn(manager.get("upn") if manager else "")
    if not caller_is_self and (not manager_upn or manager_upn != caller_upn):
        return _error(
            "REQUESTER_NOT_TARGET_MANAGER",
            "The requester is neither the target account owner nor its current Microsoft Graph manager.",
        )

    if manager_upn:
        state[AAD_MANAGER_LOOKUP_STATE_KEY] = {
            "target_upn": normalized_target,
            "manager_upn": manager_upn,
            "source": "microsoft_graph",
        }

    policy_kwargs: Dict[str, Any] = {}
    if expected_action_id:
        policy_kwargs = {
            "account_action_id": expected_action_id,
            "plan_can_execute_fully": plan.get("can_execute_fully") if plan else None,
            "plan_low_confidence": plan.get("low_confidence") if plan else None,
            "plan_unmapped_count": len(plan.get("unmapped") or []) if plan else None,
            "plan_action_count": len(plan.get("tool_sequence") or []) if plan else None,
        }
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=caller_upn,
        target_upn=normalized_target,
        manager_upn=manager_upn,
        tool_context=tool_context,
        **policy_kwargs,
    )
    if policy.get("status") != "ok":
        _invalidate_security_state(state)
        return _error(
            "ACCOUNT_ACCESS_POLICY_FAILED",
            str(policy.get("message") or "Account-access policy did not pass."),
        )

    requester_devices, requester_device_error = _read_registered_devices(caller_upn)
    if requester_device_error is not None or requester_devices is None:
        _invalidate_security_state(state)
        return requester_device_error or _error(
            "REQUESTER_DEVICE_VERIFICATION_FAILED",
            "The requester's registered devices could not be verified.",
        )
    if caller_is_self:
        target_devices = list(requester_devices)
    else:
        target_devices, target_device_error = _read_registered_devices(normalized_target)
        if target_device_error is not None or target_devices is None:
            _invalidate_security_state(state)
            return target_device_error or _error(
                "TARGET_DEVICE_VERIFICATION_FAILED",
                "The target user's registered devices could not be verified.",
            )

    allowed_hosts = sorted(
        {
            str(device.get("display_name") or "").strip().lower()
            for device in requester_devices
            if str(device.get("display_name") or "").strip()
        }
    )
    state["allowed_hosts"] = allowed_hosts
    identity["allowed_hosts"] = allowed_hosts

    verified_at = int(time.time())
    verification = {
        "verification_id": str(uuid.uuid4()),
        "verified_at": verified_at,
        "requester": caller,
        "requester_claim_source": identity.get("source"),
        "authentication_assurance": "session_identity_graph_corroborated",
        "target": target,
        "manager": manager,
        "authorization_basis": "self" if caller_is_self else "current_graph_manager",
        "requester_devices": requester_devices,
        "target_devices": target_devices,
        "requester_devices_fingerprint": _device_fingerprint(requester_devices),
        "target_devices_fingerprint": _device_fingerprint(target_devices),
        "policy_action_id": expected_action_id or "ad.get_account_status",
    }
    state[IDENTITY_VERIFICATION_STATE_KEY] = verification
    grant = state.get(ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY)
    if isinstance(grant, dict):
        grant["identity_verification_id"] = verification["verification_id"]
        state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] = grant

    return {
        "status": "ok",
        "verification": verification,
        "public": {
            "requester": {
                "display_name": caller.get("display_name"),
                "upn": caller_upn,
            },
            "target": {
                "display_name": target.get("display_name"),
                "upn": normalized_target,
            },
            "manager": (
                {
                    "display_name": manager.get("display_name"),
                    "upn": manager_upn,
                }
                if manager
                else None
            ),
            "authorization_basis": verification["authorization_basis"],
            "requester_devices": _public_devices(requester_devices),
            "target_devices": _public_devices(target_devices),
        },
    }


def _new_offer(
    state: Dict[str, Any],
    account: Dict[str, Any],
    verification: Dict[str, Any],
    invocation_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    action_id = _RECOMMENDATION_TO_ACTION.get(account.get("recommended_action"))
    if not action_id:
        state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = None
        return None
    now = int(time.time())
    offer = {
        "offer_id": str(uuid.uuid4()),
        "phase": "offered",
        "created_at": now,
        "expires_at": now + OFFER_TTL_SECONDS,
        "caller_upn": verification["requester"]["upn"],
        "target_upn": account["target_upn"],
        "target_aad_object_id": verification["target"]["aad_object_id"],
        "identity_verification_id": verification["verification_id"],
        "action_id": action_id,
        "created_invocation_id": invocation_id,
    }
    state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = offer
    return offer


def _next_step(account: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Return a deterministic non-remediation next step when no action is safe."""
    if account.get("recommended_action") == "investigate_sign_in":
        return dict(_SIGN_IN_INVESTIGATION_NEXT_STEP)
    return None


def _diagnose_verified_target(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    state = _state(tool_context)
    verification_result = _verify_identity(tool_context, target_upn)
    if verification_result.get("status") != "ok":
        state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = None
        return verification_result

    status = ad_account_tool.ad_get_account_status.func(tool_context, target_upn)
    if status.get("status") != "ok":
        state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = None
        return status

    verification = verification_result["verification"]
    offer = _new_offer(
        state,
        status["account"],
        verification,
        getattr(tool_context, "invocation_id", None),
    )
    next_step = _next_step(status["account"])
    return {
        "status": "ok",
        "account": status["account"],
        "identity_verification": verification_result["public"],
        "offer": (
            {
                "available": True,
                "action_id": offer["action_id"],
                "expires_at": offer["expires_at"],
            }
            if offer
            else None
        ),
        "next_step": next_step,
    }


def diagnose_account_access(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """Verify identity, manager and devices, then read protected account state."""
    state = _state(tool_context)
    state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = None
    return _diagnose_verified_target(_norm_upn(target_upn), tool_context)


def recheck_account_access(tool_context: ToolContext) -> Dict[str, Any]:
    """Recheck the exact retained diagnosis target using fresh Graph evidence."""
    state = _state(tool_context)
    diagnosis = state.get("account_access_diagnosis")
    if not isinstance(diagnosis, dict) or not diagnosis.get("target_upn"):
        state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = None
        return _error(
            "ACCOUNT_ACCESS_DIAGNOSIS_MISSING",
            "There is no retained account-access target to recheck.",
        )
    state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = None
    return _diagnose_verified_target(
        _norm_upn(diagnosis.get("target_upn")),
        tool_context,
    )


def _retrieve_and_plan(
    action_id: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    spec = _ACTION_SPECS[action_id]
    retrieval = sop_retriever(query=spec["query"], tool_context=tool_context)
    meta = retrieval.get("meta") if isinstance(retrieval, dict) else None
    results_count = meta.get("results_count") if isinstance(meta, dict) else 0
    if retrieval.get("status") != "ok" or not results_count:
        return _error(
            "ACCOUNT_ACCESS_SOP_UNAVAILABLE",
            "A matching Account Access SOP could not be retrieved; no action was executed.",
        )

    # SOP retrieval is mandatory governance evidence.  Identity, authorization,
    # diagnosis and verification steps are deliberately kept out of the generic
    # planner; it receives the one canonical executable label for this atomic
    # action so realistic SOP prerequisites cannot become unsafe unmapped steps.
    planned = propose_plan(
        user_text=spec["query"],
        ctx_vars=["target_upn"],
        sop_texts=[spec["label"]],
    )
    plan = planned.get("plan") if isinstance(planned, dict) else None
    sequence = plan.get("tool_sequence") if isinstance(plan, dict) else None
    valid = bool(
        planned.get("status") == "ok"
        and isinstance(plan, dict)
        and plan.get("can_execute_fully") is True
        and plan.get("low_confidence") is False
        and not (plan.get("unmapped") or [])
        and not (plan.get("required_inputs") or [])
        and plan.get("preconditions") == ["caller_is_self_or_manager"]
        and isinstance(sequence, list)
        and len(sequence) == 1
        and sequence[0].get("action_id") == action_id
    )
    if not valid:
        return _error(
            "ACCOUNT_ACCESS_PLAN_NOT_EXECUTABLE",
            "The planner did not produce the exact expected single Account Access action; no action was executed.",
        )
    return {
        "status": "ok",
        "plan": plan,
        "sop": {
            "retrieved": True,
            "results_count": results_count,
            "step_extraction_degraded": any(
                "couldn’t extract procedural steps" in str(item)
                for item in (retrieval.get("snippets") or [])
            ),
        },
    }


def _action_succeeded(action_id: str, result: Dict[str, Any]) -> bool:
    if action_id == "aad.reset_password":
        reset = result.get("reset")
        return isinstance(reset, dict) and reset.get("status") == "ok"
    return result.get("status") == "ok"


def _dispatch(action_id: str, target_upn: str, tool_context: ToolContext) -> Dict[str, Any]:
    if action_id == "ad.unlock_account":
        return ad_account_tool.ad_unlock_account.func(target_upn, tool_context)
    if action_id == "ad.enable_account":
        return ad_account_tool.ad_enable_account.func(target_upn, tool_context)
    if action_id == "aad.reset_password":
        return aad_tool.aad_reset_password.func(tool_context, target_upn)
    return _error("ACCOUNT_ACCESS_ACTION_UNSUPPORTED", "Unsupported Account Access action.")


def _execute_exact_action(
    action_id: str,
    target_upn: str,
    tool_context: ToolContext,
    recheck_after: bool,
    expected_caller_upn: Optional[str] = None,
    expected_target_object_id: Optional[str] = None,
) -> Dict[str, Any]:
    planned = _retrieve_and_plan(action_id, tool_context)
    if planned.get("status") != "ok":
        return planned
    plan = planned["plan"]

    verification_result = _verify_identity(
        tool_context,
        target_upn,
        plan=plan,
        expected_action_id=action_id,
    )
    if verification_result.get("status") != "ok":
        return verification_result
    verification = verification_result["verification"]
    if (
        expected_caller_upn
        and _norm_upn(verification["requester"].get("upn"))
        != _norm_upn(expected_caller_upn)
    ) or (
        expected_target_object_id
        and str(verification["target"].get("aad_object_id") or "").lower()
        != str(expected_target_object_id).lower()
    ):
        _invalidate_security_state(_state(tool_context))
        return _error(
            "ACCOUNT_ACCESS_OFFER_IDENTITY_CHANGED",
            "The requester or target directory object changed after the offer; no action was executed.",
        )

    result = _dispatch(action_id, target_upn, tool_context)
    # Protected tools consume valid grants themselves.  Explicitly revoke any
    # residual value as defense in depth for failed/exceptional dispatch paths.
    _state(tool_context)[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] = None
    if not _action_succeeded(action_id, result):
        return {
            "status": "error",
            "code": "ACCOUNT_ACCESS_ACTION_FAILED",
            "message": "The protected Account Access action did not complete successfully.",
            "action": result,
            "identity_verification": verification_result["public"],
            "sop": planned["sop"],
        }

    response: Dict[str, Any] = {
        "status": "ok",
        "action_id": action_id,
        "action": result,
        "identity_verification": verification_result["public"],
        "sop": planned["sop"],
    }
    if recheck_after and action_id in {"ad.enable_account", "ad.unlock_account"}:
        response["post_action_status"] = _diagnose_verified_target(
            target_upn,
            tool_context,
        )
        if response["post_action_status"].get("status") != "ok":
            response["status"] = "error"
            response["code"] = "ACCOUNT_ACCESS_POST_ACTION_VERIFICATION_FAILED"
            response["message"] = (
                "The action returned success, but fresh post-action directory verification failed; "
                "final success was not claimed."
            )
    return response


def confirm_account_access_offer(tool_context: ToolContext) -> Dict[str, Any]:
    """Execute the current retained offer; accepts no model-supplied identity fields."""
    state = _state(tool_context)
    offer = state.get(ACCOUNT_ACCESS_OFFER_STATE_KEY)
    diagnosis = state.get("account_access_diagnosis")
    if not isinstance(offer, dict) or offer.get("phase") != "offered":
        return _error(
            "ACCOUNT_ACCESS_OFFER_MISSING",
            "There is no current Account Access offer to confirm.",
        )
    if int(offer.get("expires_at") or 0) < int(time.time()):
        offer["phase"] = "expired"
        state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = offer
        return _error(
            "ACCOUNT_ACCESS_OFFER_EXPIRED",
            "The Account Access offer expired; run a fresh diagnosis before proceeding.",
        )
    current_invocation_id = getattr(tool_context, "invocation_id", None)
    created_invocation_id = offer.get("created_invocation_id")
    if (
        not current_invocation_id
        or not created_invocation_id
        or current_invocation_id == created_invocation_id
    ):
        return _error(
            "ACCOUNT_ACCESS_NEW_CONFIRMATION_REQUIRED",
            "This action requires confirmation in a new user turn; no action was executed.",
        )
    if not isinstance(diagnosis, dict):
        offer["phase"] = "failed"
        state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = offer
        return _error(
            "ACCOUNT_ACCESS_DIAGNOSIS_MISSING",
            "The diagnosis bound to this offer is missing; no action was executed.",
        )

    identity_result = ensure_identity_context_in_state(state)
    current_identity = state.get("identity_context")
    current_caller_upn = _norm_upn(
        current_identity.get("upn")
        if identity_result.get("ok") and isinstance(current_identity, dict)
        else ""
    )
    if not current_caller_upn or current_caller_upn != _norm_upn(offer.get("caller_upn")):
        offer["phase"] = "failed"
        state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = offer
        return _error(
            "ACCOUNT_ACCESS_REQUESTER_CHANGED",
            "The session requester changed after this offer was created; no action was executed.",
        )

    target_upn = _norm_upn(offer.get("target_upn"))
    action_id = str(offer.get("action_id") or "")
    expected_action = _RECOMMENDATION_TO_ACTION.get(diagnosis.get("recommended_action"))
    if (
        not target_upn
        or _norm_upn(diagnosis.get("target_upn")) != target_upn
        or expected_action != action_id
        or action_id not in _ACTION_SPECS
    ):
        offer["phase"] = "failed"
        state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = offer
        return _error(
            "ACCOUNT_ACCESS_OFFER_MISMATCH",
            "The retained target or action no longer matches the diagnosis; no action was executed.",
        )

    # Single-use transition happens before any external planning or action call.
    offer["phase"] = "confirmed"
    offer["confirmed_at"] = int(time.time())
    state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = offer
    result = _execute_exact_action(
        action_id,
        target_upn,
        tool_context,
        recheck_after=True,
        expected_caller_upn=offer.get("caller_upn"),
        expected_target_object_id=offer.get("target_aad_object_id"),
    )
    offer["phase"] = "executed" if result.get("status") == "ok" else "failed"
    offer["completed_at"] = int(time.time())
    current_offer = state.get(ACCOUNT_ACCESS_OFFER_STATE_KEY)
    if (
        isinstance(current_offer, dict)
        and current_offer.get("offer_id") != offer.get("offer_id")
        and current_offer.get("phase") == "offered"
    ):
        # A verified post-action diagnosis may have created the next distinct
        # offer (for example enable first, then unlock). Preserve it and retain
        # the consumed offer separately for audit/replay protection.
        state["account_access_last_offer"] = offer
    else:
        state[ACCOUNT_ACCESS_OFFER_STATE_KEY] = offer
    result["offer_id"] = offer["offer_id"]
    return result


def execute_explicit_account_unlock(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """Run the exact unlock workflow for an explicit user unlock request."""
    return _execute_exact_action(
        "ad.unlock_account",
        _norm_upn(target_upn),
        tool_context,
        recheck_after=False,
    )


def execute_explicit_account_enable(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """Run the exact enable workflow for an explicit user enable request."""
    return _execute_exact_action(
        "ad.enable_account",
        _norm_upn(target_upn),
        tool_context,
        recheck_after=False,
    )


def execute_explicit_password_reset(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """Run the existing password-reset action behind deterministic verification."""
    return _execute_exact_action(
        "aad.reset_password",
        _norm_upn(target_upn),
        tool_context,
        recheck_after=False,
    )


diagnose_account_access = FunctionTool(func=diagnose_account_access)
recheck_account_access = FunctionTool(func=recheck_account_access)
confirm_account_access_offer = FunctionTool(func=confirm_account_access_offer)
execute_explicit_account_unlock = FunctionTool(func=execute_explicit_account_unlock)
execute_explicit_account_enable = FunctionTool(func=execute_explicit_account_enable)
execute_explicit_password_reset = FunctionTool(func=execute_explicit_password_reset)

account_access_orchestration_tools = [
    diagnose_account_access,
    recheck_account_access,
    confirm_account_access_offer,
    execute_explicit_account_unlock,
    execute_explicit_account_enable,
    execute_explicit_password_reset,
]
