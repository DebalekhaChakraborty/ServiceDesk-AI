import os
import inspect
import time
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest


os.environ.setdefault("WINRM_PORT", "5986")

from sd_chat.agent import root_agent, sd_chat
from sd_chat.planner import reasoning_composer
from sd_chat.tools import aad_tool, ad_account_tool
from sd_chat.tools.aad_tool import aad_reset_password
from sd_chat.tools.identity_context_tool import ensure_identity_context_in_state
from sd_chat.tools.policy_tool import (
    AAD_MANAGER_LOOKUP_STATE_KEY,
    ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY,
    ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY,
    check_list,
)


CALLER_UPN = "caller@example.com"
TARGET_UPN = "target@example.com"


@pytest.fixture(autouse=True)
def isolated_demo_backend(monkeypatch):
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "demo")
    monkeypatch.setattr(ad_account_tool, "_demo_locked_upns", set())
    monkeypatch.setattr(ad_account_tool, "_demo_disabled_upns", set())


def _tool_context():
    return SimpleNamespace(state={})


def _authorize_self(tool_context, target_upn=TARGET_UPN):
    result = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=target_upn,
        target_upn=target_upn,
        tool_context=tool_context,
    )
    _bind_controller_evidence(tool_context, target_upn, "ad.get_account_status")
    return result


def _authorize_action(tool_context, action_id, target_upn=TARGET_UPN):
    result = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=target_upn,
        target_upn=target_upn,
        account_action_id=action_id,
        plan_can_execute_fully=True,
        plan_low_confidence=False,
        plan_unmapped_count=0,
        plan_action_count=1,
        tool_context=tool_context,
    )
    _bind_controller_evidence(tool_context, target_upn, action_id)
    return result


def _bind_controller_evidence(tool_context, target_upn, action_id):
    """Synthetic controller evidence for low-level backend unit tests."""
    verification_id = f"test-verification-{target_upn}-{action_id}"
    tool_context.state[ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY] = {
        "verification_id": verification_id,
        "verified_at": time.time(),
        "requester": {"upn": target_upn},
        "target": {"upn": target_upn},
        "manager": None,
        "authorization_basis": "self",
        "requester_devices": [],
        "target_devices": [],
        "policy_action_id": action_id,
    }
    grant = tool_context.state.get(ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY)
    if isinstance(grant, dict):
        grant["identity_verification_id"] = verification_id
        tool_context.state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] = grant


def _record_manager_lookup(tool_context, target_upn, manager_upn):
    tool_context.state[AAD_MANAGER_LOOKUP_STATE_KEY] = {
        "target_upn": target_upn,
        "manager_upn": manager_upn,
        "source": "microsoft_graph",
    }


def _status(tool_context, target_upn=TARGET_UPN):
    return ad_account_tool.ad_get_account_status.func(tool_context, target_upn)


def _unlock(tool_context, target_upn=TARGET_UPN):
    return ad_account_tool.ad_unlock_account.func(target_upn, tool_context)


def _enable(tool_context, target_upn=TARGET_UPN):
    return ad_account_tool.ad_enable_account.func(target_upn, tool_context)


def _graph_response(status_code, payload, text=""):
    return SimpleNamespace(
        status_code=status_code,
        text=text,
        json=lambda: payload,
    )


def _graph_account_payload(enabled):
    return {
        "id": "target-object-id",
        "displayName": "Target User",
        "userPrincipalName": TARGET_UPN,
        "mail": "target.mail@example.com",
        "accountEnabled": enabled,
        "userType": "Member",
        "createdDateTime": "2025-01-02T03:04:05Z",
        "lastPasswordChangeDateTime": "2026-02-03T04:05:06Z",
        "passwordPolicies": None,
        "onPremisesSyncEnabled": None,
        "onPremisesLastSyncDateTime": None,
        "onPremisesDistinguishedName": None,
        "creationType": None,
        "externalUserState": None,
        "externalUserStateChangeDateTime": None,
        "usageLocation": None,
        "employeeId": "1234",
        "employeeType": None,
        "jobTitle": "Engineer",
        "department": "IT",
        "companyName": "Example",
        "officeLocation": None,
    }


def _graph_sign_in_event(
    created_date_time,
    error_code,
    failure_reason,
    app_display_name="Microsoft 365",
):
    return {
        "id": f"event-{created_date_time}",
        "createdDateTime": created_date_time,
        "appDisplayName": app_display_name,
        "resourceDisplayName": "Microsoft Graph",
        "clientAppUsed": "Browser",
        "isInteractive": True,
        "ipAddress": "192.0.2.10",
        "status": {
            "errorCode": error_code,
            "failureReason": failure_reason,
            "additionalDetails": "Additional diagnostic context",
        },
        "deviceDetail": {
            "displayName": "target-laptop",
            "operatingSystem": "Windows",
            "browser": "Edge",
            "isCompliant": True,
            "isManaged": True,
            "trustType": "Microsoft Entra joined",
        },
    }


@pytest.mark.parametrize(
    ("locked", "enabled", "recommended_action"),
    [
        (False, True, "password_reset"),
        (True, True, "unlock"),
        (False, False, "enable"),
        (True, False, "enable"),
    ],
)
def test_account_status_models_all_independent_states(
    locked,
    enabled,
    recommended_action,
):
    if locked:
        ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    if not enabled:
        ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    _authorize_self(tool_context)

    result = _status(tool_context)

    expected = {
        "target_upn": TARGET_UPN,
        "locked": locked,
        "enabled": enabled,
        "backend": "demo_ad_ds",
        "recommended_action": recommended_action,
    }
    assert result == {"status": "ok", "account": expected}
    assert tool_context.state["account_access_diagnosis"] == expected


def test_unlocking_disabled_locked_account_leaves_it_disabled():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    _authorize_action(tool_context, "ad.unlock_account")

    result = _unlock(tool_context)
    _authorize_self(tool_context)
    status = _status(tool_context)

    assert result["unlock"]["was_locked"] is True
    assert result["unlock"]["is_locked"] is False
    assert status["account"]["locked"] is False
    assert status["account"]["enabled"] is False
    assert status["account"]["recommended_action"] == "enable"


def test_enabling_disabled_locked_account_leaves_it_locked():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    _authorize_action(tool_context, "ad.enable_account")

    result = _enable(tool_context)
    _authorize_self(tool_context)
    status = _status(tool_context)

    assert result["enable"]["was_enabled"] is False
    assert result["enable"]["is_enabled"] is True
    assert status["account"]["enabled"] is True
    assert status["account"]["locked"] is True
    assert status["account"]["recommended_action"] == "unlock"


def test_already_enabled_account_is_clean_noop():
    tool_context = _tool_context()
    _authorize_action(tool_context, "ad.enable_account")

    result = _enable(tool_context)

    assert result["status"] == "ok"
    assert result["enable"]["was_enabled"] is True
    assert result["enable"]["is_enabled"] is True
    assert "already enabled" in result["enable"]["message"]


def test_explicit_enable_maps_to_one_enable_action(monkeypatch):
    monkeypatch.setattr(reasoning_composer, "GENAI_AVAILABLE", False)

    result = reasoning_composer.propose_plan(
        user_text="Enable my Active Directory account.",
        ctx_vars=["target_upn"],
        sop_texts=["Enable the target Active Directory account"],
    )

    assert result["plan"]["can_execute_fully"] is True
    assert result["plan"]["low_confidence"] is False
    assert result["plan"]["unmapped"] == []
    assert result["plan"]["tool_sequence"] == [
        {
            "tool": "ad_account_tool",
            "action": "enable_account",
            "args": {"target_upn": "${target_upn}"},
            "action_id": "ad.enable_account",
        }
    ]


def test_planner_recognizes_serialized_known_variable_name(monkeypatch):
    monkeypatch.setattr(reasoning_composer, "GENAI_AVAILABLE", False)

    result = reasoning_composer.propose_plan(
        user_text="Enable the account.",
        ctx_vars=[f"target_upn:{TARGET_UPN}"],
        sop_texts=["Enable the target Active Directory account"],
    )

    assert result["plan"]["required_inputs"] == []
    assert result["plan"]["can_execute_fully"] is True


def test_planner_never_marks_plan_complete_with_missing_inputs(monkeypatch):
    monkeypatch.setattr(reasoning_composer, "GENAI_AVAILABLE", False)

    result = reasoning_composer.propose_plan(
        user_text="Enable the account.",
        ctx_vars=[],
        sop_texts=["Enable the target Active Directory account"],
    )

    assert result["plan"]["required_inputs"] == ["target_upn"]
    assert result["plan"]["can_execute_fully"] is False


def test_planner_extractor_separates_prerequisites_from_remediation():
    source = inspect.getsource(reasoning_composer._extract_steps_from_llm)

    assert "Include only executable remediation operations" in source
    assert "user/target lookup" in source
    assert "authorization or policy checks" in source
    assert "diagnosis/status inspection" in source
    assert "post-action verification" in source
    assert "return exactly one step" in source


@pytest.mark.parametrize(
    ("can_execute_fully", "low_confidence", "unmapped_count", "action_count"),
    [
        (False, False, 0, 1),
        (True, True, 0, 1),
        (True, False, 1, 1),
        (True, False, 0, 2),
    ],
)
def test_policy_refuses_unsafe_account_remediation_plan(
    can_execute_fully,
    low_confidence,
    unmapped_count,
    action_count,
):
    tool_context = _tool_context()
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=TARGET_UPN,
        target_upn=TARGET_UPN,
        account_action_id="ad.enable_account",
        plan_can_execute_fully=can_execute_fully,
        plan_low_confidence=low_confidence,
        plan_unmapped_count=unmapped_count,
        plan_action_count=action_count,
        tool_context=tool_context,
    )
    enable = _enable(tool_context)

    assert policy["status"] == "error"
    assert policy["code"] == "ACCOUNT_PLAN_NOT_EXECUTABLE"
    assert enable["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert TARGET_UPN in ad_account_tool._demo_disabled_upns


def test_diagnosis_grant_cannot_execute_enable_or_unlock():
    tool_context = _tool_context()
    _authorize_self(tool_context)

    enable = _enable(tool_context)
    unlock = _unlock(tool_context)

    assert enable["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert unlock["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"


def test_remediation_grant_is_bound_to_exact_action():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    policy = _authorize_action(tool_context, "ad.enable_account")

    unlock = _unlock(tool_context)
    enable = _enable(tool_context)

    assert policy["status"] == "ok"
    assert unlock["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert TARGET_UPN in ad_account_tool._demo_locked_upns
    assert enable["status"] == "ok"
    assert TARGET_UPN not in ad_account_tool._demo_disabled_upns


def test_explicit_enable_runs_without_status_unlock_or_password_reset():
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    status = Mock(wraps=ad_account_tool.ad_get_account_status.func)
    unlock = Mock(wraps=ad_account_tool.ad_unlock_account.func)
    password_reset = Mock()
    policy = _authorize_action(tool_context, "ad.enable_account")

    result = _enable(tool_context) if policy["status"] == "ok" else None

    assert result["enable"]["is_enabled"] is True
    status.assert_not_called()
    unlock.assert_not_called()
    password_reset.assert_not_called()


@pytest.mark.parametrize(
    ("locked", "enabled", "recommended_action"),
    [
        (True, True, "unlock"),
        (False, False, "enable"),
        (True, False, "enable"),
        (False, True, "password_reset"),
    ],
)
def test_ambiguous_diagnosis_selects_offer_without_executing(
    locked,
    enabled,
    recommended_action,
):
    if locked:
        ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    if not enabled:
        ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    unlock = Mock(wraps=ad_account_tool.ad_unlock_account.func)
    enable = Mock(wraps=ad_account_tool.ad_enable_account.func)
    password_reset = Mock()
    _authorize_self(tool_context)

    result = _status(tool_context)

    assert result["account"]["recommended_action"] == recommended_action
    unlock.assert_not_called()
    enable.assert_not_called()
    password_reset.assert_not_called()


def test_after_enable_recheck_offers_unlock_without_executing_it():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    _authorize_self(tool_context)
    initial = _status(tool_context)
    unlock = Mock(wraps=ad_account_tool.ad_unlock_account.func)

    assert initial["account"]["recommended_action"] == "enable"
    _authorize_action(tool_context, "ad.enable_account")
    enabled = _enable(tool_context)
    _authorize_self(tool_context)
    rechecked = _status(tool_context)

    assert enabled["status"] == "ok"
    assert rechecked["account"]["enabled"] is True
    assert rechecked["account"]["locked"] is True
    assert rechecked["account"]["recommended_action"] == "unlock"
    unlock.assert_not_called()


def test_self_and_verified_manager_can_read_status():
    self_context = _tool_context()
    manager_context = _tool_context()
    _authorize_self(self_context)
    _record_manager_lookup(manager_context, TARGET_UPN, CALLER_UPN)
    manager_policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=CALLER_UPN,
        tool_context=manager_context,
    )

    assert _status(self_context)["status"] == "ok"
    assert manager_policy["status"] == "ok"
    assert _status(manager_context)["status"] == "ok"


def test_unauthorized_user_cannot_observe_or_change_either_state():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    tool_context = _tool_context()

    status = _status(tool_context)
    unlock = _unlock(tool_context)
    enable = _enable(tool_context)

    assert status["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert unlock["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert enable["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert "account_access_diagnosis" not in tool_context.state
    assert TARGET_UPN in ad_account_tool._demo_locked_upns
    assert TARGET_UPN in ad_account_tool._demo_disabled_upns


def test_enable_confirmation_uses_retained_exact_target():
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    _authorize_self(tool_context)
    diagnosis = _status(tool_context)["account"]
    enable = Mock(wraps=ad_account_tool.ad_enable_account.func)

    _authorize_action(tool_context, "ad.enable_account")
    result = enable(diagnosis["target_upn"], tool_context)

    assert diagnosis["recommended_action"] == "enable"
    enable.assert_called_once_with(TARGET_UPN, tool_context)
    assert result["enable"]["is_enabled"] is True


def test_target_bound_grant_rejects_confirmation_target_drift():
    ad_account_tool._demo_disabled_upns.update({CALLER_UPN, TARGET_UPN})
    tool_context = _tool_context()
    _authorize_self(tool_context, CALLER_UPN)
    diagnosis = _status(tool_context, CALLER_UPN)["account"]
    _authorize_action(tool_context, "ad.enable_account", CALLER_UPN)

    drifted = _enable(tool_context, TARGET_UPN)

    assert diagnosis["target_upn"] == CALLER_UPN
    assert diagnosis["recommended_action"] == "enable"
    assert drifted["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert TARGET_UPN in ad_account_tool._demo_disabled_upns


def test_new_target_lookup_invalidates_stale_diagnosis_and_authorization(monkeypatch):
    tool_context = _tool_context()
    _authorize_self(tool_context, CALLER_UPN)
    tool_context.state["account_access_diagnosis"] = {
        "target_upn": CALLER_UPN,
        "locked": False,
        "enabled": False,
        "recommended_action": "enable",
    }
    tool_context.state["account_access_offer"] = {"phase": "offered"}
    monkeypatch.setattr(aad_tool, "_graph_is_configured", lambda: False)

    aad_tool.aad_user_lookup.func(tool_context, "Another User")

    assert tool_context.state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] is None
    assert tool_context.state[ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY] is None
    assert tool_context.state["account_access_diagnosis"] is None
    assert tool_context.state["account_access_offer"] is None


def test_graph_status_reads_real_account_enabled_and_profile(monkeypatch):
    tool_context = _tool_context()
    _authorize_self(tool_context)
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    graph_get = Mock(
        side_effect=[
            _graph_response(200, _graph_account_payload(False)),
            _graph_response(200, {"value": []}),
        ]
    )
    monkeypatch.setattr(aad_tool, "_graph_get", graph_get)

    result = _status(tool_context)

    account = result["account"]
    assert result["status"] == "ok"
    assert account["target_upn"] == TARGET_UPN
    assert account["enabled"] is False
    assert account["locked"] is None
    assert account["lock_state_available"] is False
    assert account["recommended_action"] == "enable"
    assert account["backend"] == "microsoft_graph"
    assert account["directory_profile"]["account_enabled"] is False
    assert account["directory_profile"]["employee_id"] == "1234"
    assert account["directory_profile"]["last_password_change_date_time"] == (
        "2026-02-03T04:05:06Z"
    )
    assert account["sign_in_investigation"]["status"] == "ok"
    assert account["sign_in_investigation"]["events_examined"] == 0
    assert tool_context.state["account_access_diagnosis"] == account
    assert graph_get.call_args_list[0] == call(
        "users/target%40example.com",
        params={"$select": ",".join(ad_account_tool.GRAPH_ACCOUNT_SELECT_FIELDS)},
    )
    sign_in_path = graph_get.call_args_list[1].args[0]
    sign_in_kwargs = graph_get.call_args_list[1].kwargs
    assert sign_in_path == "auditLogs/signIns"
    assert "userId eq 'target-object-id'" in sign_in_kwargs["params"]["$filter"]
    assert "createdDateTime ge " in sign_in_kwargs["params"]["$filter"]
    assert sign_in_kwargs["params"]["$top"] == "20"


def test_graph_enabled_account_does_not_claim_unlocked(monkeypatch):
    tool_context = _tool_context()
    _authorize_self(tool_context)
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    graph_get = Mock(
        side_effect=[
            _graph_response(200, _graph_account_payload(True)),
            _graph_response(200, {"value": []}),
        ]
    )
    monkeypatch.setattr(aad_tool, "_graph_get", graph_get)

    result = _status(tool_context)

    assert result["account"]["enabled"] is True
    assert result["account"]["locked"] is None
    assert result["account"]["recommended_action"] == "investigate_sign_in"
    assert "not exposed" in result["account"]["lock_state_message"]
    evidence = result["account"]["sign_in_investigation"]
    assert evidence["status"] == "ok"
    assert evidence["current_lock_state"] == "unknown"
    assert evidence["current_lock_state_available"] is False
    assert evidence["possible_lockout_evidence"]["found"] is False
    assert "does not prove" in evidence["possible_lockout_evidence"]["interpretation"]


def test_graph_sign_in_evidence_reports_50053_without_claiming_current_lock(
    monkeypatch,
):
    tool_context = _tool_context()
    _authorize_self(tool_context)
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    graph_patch = Mock()
    graph_get = Mock(
        side_effect=[
            _graph_response(200, _graph_account_payload(True)),
            _graph_response(
                200,
                {
                    "value": [
                        _graph_sign_in_event(
                            "2026-08-11T12:00:00Z",
                            50053,
                            "The account is locked due to repeated sign-in attempts.",
                        ),
                        _graph_sign_in_event(
                            "2026-08-11T12:05:00Z",
                            0,
                            "Sign-in succeeded.",
                        ),
                        _graph_sign_in_event(
                            "2026-08-11T12:10:00Z",
                            50126,
                            "Error validating credentials.",
                            app_display_name="Microsoft Teams",
                        ),
                    ]
                },
            ),
        ]
    )
    monkeypatch.setattr(aad_tool, "_graph_get", graph_get)
    monkeypatch.setattr(aad_tool, "_graph_patch", graph_patch)

    result = _status(tool_context)

    account = result["account"]
    evidence = account["sign_in_investigation"]
    assert result["status"] == "ok"
    assert account["locked"] is None
    assert account["recommended_action"] == "investigate_sign_in"
    assert evidence["current_lock_state"] == "unknown"
    assert evidence["possible_lockout_evidence"]["found"] is True
    assert evidence["possible_lockout_evidence"]["error_code"] == 50053
    assert evidence["possible_lockout_evidence"]["later_success_observed"] is True
    assert evidence["latest_event"]["error_code"] == 50126
    assert evidence["latest_failure"]["error_code"] == 50126
    assert evidence["latest_success"]["error_code"] == 0
    assert len(evidence["recent_events"]) == 3
    assert "192.0.2.10" not in str(evidence)
    graph_patch.assert_not_called()


def test_graph_sign_in_permission_failure_preserves_safe_account_diagnosis(
    monkeypatch,
):
    tool_context = _tool_context()
    _authorize_self(tool_context)
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    graph_get = Mock(
        side_effect=[
            _graph_response(200, _graph_account_payload(True)),
            _graph_response(
                403,
                {
                    "error": {
                        "code": "Authentication_MSGraphPermissionMissing",
                        "message": "Missing permission.",
                    }
                },
            ),
        ]
    )
    monkeypatch.setattr(aad_tool, "_graph_get", graph_get)

    result = _status(tool_context)

    account = result["account"]
    evidence = account["sign_in_investigation"]
    assert result["status"] == "ok"
    assert account["enabled"] is True
    assert account["locked"] is None
    assert account["recommended_action"] == "investigate_sign_in"
    assert evidence["status"] == "unavailable"
    assert evidence["code"] == "GRAPH_SIGN_IN_LOG_PERMISSION_REQUIRED"
    assert evidence["required_application_permission"] == "AuditLog.Read.All"
    assert evidence["current_lock_state_available"] is False


def test_graph_status_failure_never_infers_account_state(monkeypatch):
    tool_context = _tool_context()
    _authorize_self(tool_context)
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    monkeypatch.setattr(
        aad_tool,
        "_graph_get",
        Mock(
            return_value=_graph_response(
                403,
                {"error": {"code": "Authorization_RequestDenied", "message": "Denied"}},
            )
        ),
    )

    result = _status(tool_context)

    assert result["status"] == "error"
    assert result["code"] == "GRAPH_ACCOUNT_LOOKUP_FAILED"
    assert result["http_status"] == 403
    assert "account_access_diagnosis" not in tool_context.state


def test_unauthorized_graph_status_does_not_call_graph(monkeypatch):
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    graph_get = Mock()
    monkeypatch.setattr(aad_tool, "_graph_get", graph_get)

    result = _status(_tool_context())

    assert result["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    graph_get.assert_not_called()


def test_graph_enable_updates_and_verifies_real_account(monkeypatch):
    tool_context = _tool_context()
    _authorize_action(tool_context, "ad.enable_account")
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    graph_get = Mock(
        side_effect=[
            _graph_response(200, _graph_account_payload(False)),
            _graph_response(200, _graph_account_payload(True)),
        ]
    )
    graph_patch = Mock(return_value=_graph_response(204, {}))
    monkeypatch.setattr(aad_tool, "_graph_get", graph_get)
    monkeypatch.setattr(aad_tool, "_graph_patch", graph_patch)

    result = _enable(tool_context)

    assert result["status"] == "ok"
    assert result["enable"]["was_enabled"] is False
    assert result["enable"]["is_enabled"] is True
    assert result["enable"]["backend"] == "microsoft_graph"
    assert result["enable"]["verification_attempts"] == 1
    graph_patch.assert_called_once_with(
        "users/target%40example.com",
        {"accountEnabled": True},
    )
    assert graph_get.call_count == 2


def test_graph_enable_waits_for_delayed_verification_without_repeating_patch(
    monkeypatch,
):
    tool_context = _tool_context()
    _authorize_action(tool_context, "ad.enable_account")
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    graph_get = Mock(
        side_effect=[
            _graph_response(200, _graph_account_payload(False)),
            _graph_response(200, _graph_account_payload(False)),
            _graph_response(200, _graph_account_payload(False)),
            _graph_response(200, _graph_account_payload(True)),
        ]
    )
    graph_patch = Mock(return_value=_graph_response(204, {}))
    sleep = Mock()
    monkeypatch.setattr(aad_tool, "_graph_get", graph_get)
    monkeypatch.setattr(aad_tool, "_graph_patch", graph_patch)
    monkeypatch.setattr(ad_account_tool.time, "sleep", sleep)

    result = _enable(tool_context)

    assert result["status"] == "ok"
    assert result["enable"]["is_enabled"] is True
    assert result["enable"]["verification_attempts"] == 3
    assert result["enable"]["verification_window_seconds"] == 60
    assert result["enable"]["verification_interval_seconds"] == 5
    graph_patch.assert_called_once_with(
        "users/target%40example.com",
        {"accountEnabled": True},
    )
    assert graph_get.call_count == 4
    assert sleep.call_count == 2
    sleep.assert_called_with(5)


def test_graph_enable_stops_after_one_minute_without_claiming_success(monkeypatch):
    tool_context = _tool_context()
    _authorize_action(tool_context, "ad.enable_account")
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    graph_get = Mock(
        return_value=_graph_response(200, _graph_account_payload(False))
    )
    graph_patch = Mock(return_value=_graph_response(204, {}))
    sleep = Mock()
    monkeypatch.setattr(aad_tool, "_graph_get", graph_get)
    monkeypatch.setattr(aad_tool, "_graph_patch", graph_patch)
    monkeypatch.setattr(ad_account_tool.time, "sleep", sleep)

    result = _enable(tool_context)

    assert result["status"] == "error"
    assert result["code"] == "GRAPH_ACCOUNT_ENABLE_VERIFICATION_FAILED"
    assert result["enable"]["verification_attempts"] == 13
    assert result["enable"]["verification_window_seconds"] == 60
    assert result["enable"]["verification_interval_seconds"] == 5
    assert "accepted the enable operation" in result["message"]
    assert "success was not claimed" in result["message"]
    graph_patch.assert_called_once()
    assert graph_get.call_count == 14
    assert sleep.call_count == 12


def test_graph_enable_failure_does_not_claim_success(monkeypatch):
    tool_context = _tool_context()
    _authorize_action(tool_context, "ad.enable_account")
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    monkeypatch.setattr(
        aad_tool,
        "_graph_get",
        Mock(return_value=_graph_response(200, _graph_account_payload(False))),
    )
    monkeypatch.setattr(
        aad_tool,
        "_graph_patch",
        Mock(
            return_value=_graph_response(
                403,
                {"error": {"code": "Authorization_RequestDenied", "message": "Denied"}},
            )
        ),
    )

    result = _enable(tool_context)

    assert result["status"] == "error"
    assert result["code"] == "GRAPH_ACCOUNT_ENABLE_FAILED"
    assert result["enable"]["status"] == "error"


def test_graph_unlock_fails_truthfully_without_mutation(monkeypatch):
    tool_context = _tool_context()
    _authorize_action(tool_context, "ad.unlock_account")
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    graph_get = Mock()
    graph_patch = Mock()
    monkeypatch.setattr(aad_tool, "_graph_get", graph_get)
    monkeypatch.setattr(aad_tool, "_graph_patch", graph_patch)

    result = _unlock(tool_context)

    assert result["status"] == "error"
    assert result["code"] == "GRAPH_ACCOUNT_UNLOCK_UNAVAILABLE"
    graph_get.assert_not_called()
    graph_patch.assert_not_called()


def test_off_backend_blocks_status_unlock_and_enable_without_mutation(monkeypatch):
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "off")

    status_context = _tool_context()
    _authorize_self(status_context)
    unlock_context = _tool_context()
    _authorize_action(unlock_context, "ad.unlock_account")
    enable_context = _tool_context()
    _authorize_action(enable_context, "ad.enable_account")

    results = [
        _status(status_context),
        _unlock(unlock_context),
        _enable(enable_context),
    ]

    assert {result["code"] for result in results} == {"AD_ACCOUNT_BACKEND_OFF"}
    assert all(result["status"] == "error" for result in results)
    assert "account_access_diagnosis" not in status_context.state
    assert TARGET_UPN in ad_account_tool._demo_locked_upns
    assert TARGET_UPN in ad_account_tool._demo_disabled_upns


def test_runtime_has_no_environment_driven_per_user_status_fixtures():
    source = inspect.getsource(ad_account_tool)

    assert "AD_DEMO_LOCKED_UPNS" not in source
    assert "AD_DEMO_DISABLED_UPNS" not in source


def test_identity_context_manager_comes_from_persona_not_a_hardcoded_user():
    state = {
        "persona": {
            "name": "Requesting User",
            "user_principal_name": "requester@example.com",
            "email": "requester@example.com",
            "manager": {
                "displayName": "Directory Manager",
                "userPrincipalName": "directory.manager@example.com",
            },
        }
    }

    result = ensure_identity_context_in_state(state)

    assert result["identity"]["manager"] == {
        "name": "Directory Manager",
        "email": "directory.manager@example.com",
    }


def test_identity_context_does_not_invent_a_missing_manager():
    state = {
        "persona": {
            "name": "Requesting User",
            "user_principal_name": "requester@example.com",
            "email": "requester@example.com",
        }
    }

    result = ensure_identity_context_in_state(state)

    assert result["identity"]["manager"] == {"name": None, "email": None}


def test_account_tools_and_registry_actions_are_registered():
    registry_ids = {item["id"] for item in reasoning_composer._load_registry()}
    tool_names = {tool.name for tool in ad_account_tool.ad_account_tools}

    assert {"ad.unlock_account", "ad.enable_account", "aad.reset_password"} <= registry_ids
    assert {
        "ad_get_account_status",
        "ad_unlock_account",
        "ad_enable_account",
    } <= tool_names
    assert aad_reset_password.name == "aad_reset_password"


def test_root_agent_export_and_account_tools_remain_available():
    root_tool_names = {getattr(tool, "name", "") for tool in root_agent.tools}

    assert root_agent is sd_chat
    assert "aad_reset_password" in root_tool_names
    assert "ad_get_account_status" in root_tool_names
    assert "ad_unlock_account" in root_tool_names
    assert "ad_enable_account" in root_tool_names
    assert "diagnose_account_access_for_other_user" in root_tool_names
    assert "execute_explicit_account_unlock_for_other_user" in root_tool_names
    assert "aad_user_lookup" not in root_tool_names
    assert "aad_get_manager" not in root_tool_names


def test_account_access_routing_and_stale_confirmation_contract():
    instruction = sd_chat.instruction

    assert "I can't access my account" in instruction
    assert "cannot sign" in instruction
    assert "in to any or multiple systems" in instruction
    assert "identity-wide symptoms" in instruction
    assert "enters the protected Account Access diagnosis" in instruction
    assert "Named-system routing has precedence" in instruction
    assert "AWS WorkSpaces, HOST, Teams, ServiceNow, or VPN" in instruction
    assert "generic Account Access status check" in instruction
    assert "must not replace, diagnosis of the named system" in instruction
    assert "A bare confirmation" in instruction
    assert "Never let stale consent" in instruction
    assert "call aad_get_manager" in instruction
    assert "immediately before check_list" in instruction
    assert "do not call check_list first" in instruction
    assert "never call raw aad_user_lookup or aad_get_manager" in instruction
    assert "no candidate directory records" in instruction
    assert "do not list candidates" in instruction


def test_disabled_locked_and_healthy_branch_contracts_are_explicit():
    instruction = sd_chat.instruction

    assert "If enabled == false and locked == true" in instruction
    assert "offer only enable first" in instruction
    assert "If enabled == false and locked == null" in instruction
    assert "account is disabled and that current lock state is unavailable" in instruction
    assert "do not execute until the user confirms" in instruction.lower()
    assert "If enabled == true and locked == false" in instruction
    assert "offer the existing password reset" in instruction
    assert "If enabled == true and locked == null" in instruction
    assert "Null means unknown, never false" in instruction
    assert 'never say "not locked"' in instruction
    assert "re-run the canonical authorization gate" in instruction
    assert "offer unlock as a" in instruction
    assert "separate second action" in instruction


def test_three_account_remediations_are_explicitly_isolated():
    instruction = sd_chat.instruction

    assert "Unlock must never enable an account or reset a password" in instruction
    assert "Enable must never unlock" in instruction
    assert "or reset a password" in instruction
    assert "exactly one approved action" in instruction
    assert 'ctx_vars=["target_upn"]' in instruction
    assert 'never "target_upn:<value>"' in instruction
    assert '["Enable the target Active Directory account"]' in instruction
    assert "Do not pass SOP" in instruction
    assert "different remediation than the explicit request" in instruction
    assert "do not substitute or offer" in instruction
    assert "without asking a second" in instruction
    assert "The diagnosis policy grant is not reusable" in instruction
    assert "NEVER call ad_enable_account" in instruction


def test_password_reset_implementation_is_still_callable():
    assert callable(aad_reset_password.func)
