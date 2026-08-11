import inspect
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sd_chat.tools import aad_tool, ad_account_tool
from sd_chat.tools import account_access_orchestrator as orchestrator
from sd_chat.tools.policy_tool import (
    ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY,
    ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY,
    check_list,
)


CALLER_UPN = "requester@example.com"
TARGET_UPN = "employee@example.com"
MANAGER_UPN = "manager@example.com"


@pytest.fixture(autouse=True)
def isolated_backend(monkeypatch):
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "demo")
    monkeypatch.setattr(ad_account_tool, "_demo_locked_upns", set())
    monkeypatch.setattr(ad_account_tool, "_demo_disabled_upns", set())


def _context(caller_upn=CALLER_UPN, invocation_id="turn-1"):
    object_id = f"id-{caller_upn.split('@', 1)[0]}"
    persona = {
        "displayName": caller_upn.split("@", 1)[0].title(),
        "userPrincipalName": caller_upn,
        "id": object_id,
    }
    return SimpleNamespace(
        state={"persona": persona, "user:persona": persona},
        invocation_id=invocation_id,
    )


def _directory_user(upn):
    return {
        "upn": upn,
        "aad_object_id": f"id-{upn.split('@', 1)[0]}",
        "display_name": upn.split("@", 1)[0].title(),
        "mail": upn,
    }


def _install_directory(
    monkeypatch,
    manager_upn=MANAGER_UPN,
    device_error_for=None,
):
    manager_state = {"upn": manager_upn}
    calls = {"users": [], "managers": [], "devices": []}

    def read_user(upn):
        calls["users"].append(upn)
        return _directory_user(upn), None

    def read_manager(target_upn):
        calls["managers"].append(target_upn)
        current = manager_state["upn"]
        if current is None:
            return None, None
        return {
            "upn": current,
            "aad_object_id": f"id-{current.split('@', 1)[0]}",
            "display_name": current.split("@", 1)[0].title(),
        }, None

    def read_devices(upn):
        calls["devices"].append(upn)
        if upn == device_error_for:
            return None, {
                "status": "error",
                "code": "DIRECTORY_DEVICE_LOOKUP_FAILED",
                "message": "Graph device lookup failed.",
            }
        return [
            {
                "directory_object_id": f"directory-device-{upn}",
                "device_id": f"device-{upn}",
                "display_name": f"{upn.split('@', 1)[0]}-laptop",
                "operating_system": "Windows",
            }
        ], None

    monkeypatch.setattr(orchestrator, "_read_directory_user", read_user)
    monkeypatch.setattr(orchestrator, "_read_manager", read_manager)
    monkeypatch.setattr(orchestrator, "_read_registered_devices", read_devices)
    return calls, manager_state


def _install_planning(monkeypatch, forced_action_id=None):
    retrieval = Mock(
        return_value={
            "status": "ok",
            "snippets": ["LLM couldn’t extract procedural steps from the SOP, Please retry."],
            "meta": {"results_count": 1},
        }
    )

    action_by_label = {
        "Unlock the target Active Directory account": "ad.unlock_account",
        "Enable the target Active Directory account": "ad.enable_account",
        "Reset Azure AD password for a user": "aad.reset_password",
    }

    def plan(user_text, ctx_vars, sop_texts):
        action_id = forced_action_id or action_by_label[sop_texts[0]]
        return {
            "status": "ok",
            "plan": {
                "required_inputs": [],
                "preconditions": ["caller_is_self_or_manager"],
                "tool_sequence": [{"action_id": action_id}],
                "unmapped": [],
                "can_execute_fully": True,
                "low_confidence": False,
            },
        }

    monkeypatch.setattr(orchestrator, "sop_retriever", retrieval)
    monkeypatch.setattr(orchestrator, "propose_plan", plan)
    return retrieval


def test_self_diagnosis_binds_requester_manager_and_devices(monkeypatch):
    calls, _ = _install_directory(monkeypatch, manager_upn=MANAGER_UPN)
    context = _context()
    ad_account_tool._demo_disabled_upns.add(CALLER_UPN)

    result = orchestrator.diagnose_account_access.func(CALLER_UPN, context)

    assert result["status"] == "ok"
    assert result["account"]["enabled"] is False
    assert result["offer"]["action_id"] == "ad.enable_account"
    evidence = result["identity_verification"]
    assert evidence["requester"]["upn"] == CALLER_UPN
    assert evidence["target"]["upn"] == CALLER_UPN
    assert evidence["manager"]["upn"] == MANAGER_UPN
    assert evidence["authorization_basis"] == "self"
    assert evidence["requester_devices"] == evidence["target_devices"]
    assert calls["managers"] == [CALLER_UPN]
    assert calls["devices"] == [CALLER_UPN]


def test_current_graph_manager_can_diagnose_employee_with_both_device_sets(monkeypatch):
    calls, _ = _install_directory(monkeypatch, manager_upn=CALLER_UPN)
    context = _context()

    result = orchestrator.diagnose_account_access.func(TARGET_UPN, context)

    assert result["status"] == "ok"
    assert result["identity_verification"]["authorization_basis"] == "current_graph_manager"
    assert result["identity_verification"]["manager"]["upn"] == CALLER_UPN
    assert calls["devices"] == [CALLER_UPN, TARGET_UPN]


def test_sign_in_evidence_never_creates_an_automatic_remediation_offer(monkeypatch):
    _install_directory(monkeypatch, manager_upn=MANAGER_UPN)
    context = _context()
    status = Mock(
        return_value={
            "status": "ok",
            "account": {
                "target_upn": CALLER_UPN,
                "enabled": True,
                "locked": None,
                "recommended_action": "investigate_sign_in",
                "sign_in_investigation": {
                    "status": "ok",
                    "current_lock_state": "unknown",
                    "possible_lockout_evidence": {
                        "found": True,
                        "error_code": 50053,
                    },
                },
            },
        }
    )
    monkeypatch.setattr(ad_account_tool.ad_get_account_status, "func", status)

    result = orchestrator.diagnose_account_access.func(CALLER_UPN, context)

    assert result["status"] == "ok"
    assert result["account"]["locked"] is None
    assert result["account"]["recommended_action"] == "investigate_sign_in"
    assert result["offer"] is None
    assert context.state[orchestrator.ACCOUNT_ACCESS_OFFER_STATE_KEY] is None


def test_unauthorized_requester_cannot_read_target_devices_or_account_state(monkeypatch):
    calls, _ = _install_directory(monkeypatch, manager_upn=MANAGER_UPN)
    context = _context()
    status = Mock(wraps=ad_account_tool.ad_get_account_status.func)
    monkeypatch.setattr(ad_account_tool.ad_get_account_status, "func", status)

    result = orchestrator.diagnose_account_access.func(TARGET_UPN, context)

    assert result["status"] == "error"
    assert result["code"] == "REQUESTER_NOT_TARGET_MANAGER"
    assert calls["devices"] == []
    status.assert_not_called()
    assert "account_access_diagnosis" not in context.state


def test_device_lookup_failure_revokes_policy_and_stops_before_status(monkeypatch):
    _install_directory(monkeypatch, manager_upn=MANAGER_UPN, device_error_for=CALLER_UPN)
    context = _context()
    status = Mock(wraps=ad_account_tool.ad_get_account_status.func)
    monkeypatch.setattr(ad_account_tool.ad_get_account_status, "func", status)

    result = orchestrator.diagnose_account_access.func(CALLER_UPN, context)

    assert result["code"] == "DIRECTORY_DEVICE_LOOKUP_FAILED"
    assert context.state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] is None
    status.assert_not_called()


def test_self_manager_lookup_technical_failure_stops_protected_flow(monkeypatch):
    _install_directory(monkeypatch, manager_upn=MANAGER_UPN)
    monkeypatch.setattr(
        orchestrator,
        "_read_manager",
        lambda target_upn: (
            None,
            {
                "status": "error",
                "code": "DIRECTORY_MANAGER_LOOKUP_FAILED",
                "message": "Graph manager lookup failed.",
            },
        ),
    )
    context = _context()

    result = orchestrator.diagnose_account_access.func(CALLER_UPN, context)

    assert result["code"] == "DIRECTORY_MANAGER_LOOKUP_FAILED"
    assert "account_access_diagnosis" not in context.state


def test_session_object_id_must_match_requester_graph_object(monkeypatch):
    calls, _ = _install_directory(monkeypatch, manager_upn=MANAGER_UPN)
    context = _context()
    context.state["persona"]["id"] = "different-object-id"

    result = orchestrator.diagnose_account_access.func(CALLER_UPN, context)

    assert result["code"] == "REQUESTER_DIRECTORY_ID_MISMATCH"
    assert calls["managers"] == []
    assert calls["devices"] == []


def test_confirmation_accepts_no_identity_or_action_arguments():
    signature = inspect.signature(orchestrator.confirm_account_access_offer.func)

    assert list(signature.parameters) == ["tool_context"]


def test_real_graph_raw_status_cannot_bypass_controller_device_evidence(monkeypatch):
    context = _context()
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "graph")
    graph_get = Mock()
    monkeypatch.setattr(aad_tool, "_graph_get", graph_get)
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        tool_context=context,
    )

    result = ad_account_tool.ad_get_account_status.func(context, CALLER_UPN)

    assert policy["status"] == "ok"
    assert result["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    graph_get.assert_not_called()


def test_confirmation_executes_exact_offer_then_requires_new_turn_for_next_action(monkeypatch):
    calls, _ = _install_directory(monkeypatch, manager_upn=MANAGER_UPN)
    retrieval = _install_planning(monkeypatch)
    context = _context(invocation_id="diagnosis-turn")
    ad_account_tool._demo_disabled_upns.add(CALLER_UPN)
    ad_account_tool._demo_locked_upns.add(CALLER_UPN)

    diagnosis = orchestrator.diagnose_account_access.func(CALLER_UPN, context)
    assert diagnosis["offer"]["action_id"] == "ad.enable_account"

    context.invocation_id = "enable-confirmation-turn"
    enabled = orchestrator.confirm_account_access_offer.func(context)

    assert enabled["status"] == "ok"
    assert enabled["action_id"] == "ad.enable_account"
    assert CALLER_UPN not in ad_account_tool._demo_disabled_upns
    assert CALLER_UPN in ad_account_tool._demo_locked_upns
    next_offer = context.state[orchestrator.ACCOUNT_ACCESS_OFFER_STATE_KEY]
    assert next_offer["phase"] == "offered"
    assert next_offer["action_id"] == "ad.unlock_account"
    assert context.state["account_access_last_offer"]["phase"] == "executed"
    assert retrieval.call_count == 1

    same_turn = orchestrator.confirm_account_access_offer.func(context)
    assert same_turn["code"] == "ACCOUNT_ACCESS_NEW_CONFIRMATION_REQUIRED"
    assert CALLER_UPN in ad_account_tool._demo_locked_upns

    context.invocation_id = "unlock-confirmation-turn"
    unlocked = orchestrator.confirm_account_access_offer.func(context)
    assert unlocked["status"] == "ok"
    assert unlocked["action_id"] == "ad.unlock_account"
    assert CALLER_UPN not in ad_account_tool._demo_locked_upns
    assert retrieval.call_count == 2
    # Diagnosis, enable authorization, post-enable verification, unlock
    # authorization and post-unlock verification all use fresh device evidence.
    assert calls["devices"].count(CALLER_UPN) >= 5


def test_manager_change_between_offer_and_confirmation_fails_closed(monkeypatch):
    _, manager_state = _install_directory(monkeypatch, manager_upn=CALLER_UPN)
    _install_planning(monkeypatch)
    context = _context(invocation_id="diagnosis-turn")
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    diagnosis = orchestrator.diagnose_account_access.func(TARGET_UPN, context)
    assert diagnosis["status"] == "ok"

    manager_state["upn"] = MANAGER_UPN
    context.invocation_id = "confirmation-turn"
    result = orchestrator.confirm_account_access_offer.func(context)

    assert result["code"] == "REQUESTER_NOT_TARGET_MANAGER"
    assert TARGET_UPN in ad_account_tool._demo_disabled_upns
    assert context.state[orchestrator.ACCOUNT_ACCESS_OFFER_STATE_KEY]["phase"] == "failed"


def test_requester_change_invalidates_retained_offer_before_planning(monkeypatch):
    _install_directory(monkeypatch, manager_upn=CALLER_UPN)
    retrieval = _install_planning(monkeypatch)
    context = _context(invocation_id="diagnosis-turn")
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    diagnosis = orchestrator.diagnose_account_access.func(TARGET_UPN, context)
    assert diagnosis["status"] == "ok"

    replacement = {
        "displayName": "Employee",
        "userPrincipalName": TARGET_UPN,
        "id": "id-employee",
    }
    context.state["persona"] = replacement
    context.state["user:persona"] = replacement
    context.invocation_id = "confirmation-turn"
    result = orchestrator.confirm_account_access_offer.func(context)

    assert result["code"] == "ACCOUNT_ACCESS_REQUESTER_CHANGED"
    assert retrieval.call_count == 0
    assert TARGET_UPN in ad_account_tool._demo_disabled_upns


def test_recreated_target_object_invalidates_offer_before_action(monkeypatch):
    _install_directory(monkeypatch, manager_upn=CALLER_UPN)
    _install_planning(monkeypatch)
    context = _context(invocation_id="diagnosis-turn")
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    diagnosis = orchestrator.diagnose_account_access.func(TARGET_UPN, context)
    assert diagnosis["status"] == "ok"

    original_lookup = orchestrator._read_directory_user

    def recreated_target(upn):
        user, error = original_lookup(upn)
        if upn == TARGET_UPN and user:
            user = dict(user)
            user["aad_object_id"] = "replacement-target-object-id"
        return user, error

    monkeypatch.setattr(orchestrator, "_read_directory_user", recreated_target)
    context.invocation_id = "confirmation-turn"
    result = orchestrator.confirm_account_access_offer.func(context)

    assert result["code"] == "ACCOUNT_ACCESS_OFFER_IDENTITY_CHANGED"
    assert TARGET_UPN in ad_account_tool._demo_disabled_upns


def test_unexpected_planner_action_stops_before_identity_or_mutation(monkeypatch):
    calls, _ = _install_directory(monkeypatch, manager_upn=MANAGER_UPN)
    _install_planning(monkeypatch, forced_action_id="ad.unlock_account")
    context = _context(invocation_id="diagnosis-turn")
    ad_account_tool._demo_disabled_upns.add(CALLER_UPN)
    orchestrator.diagnose_account_access.func(CALLER_UPN, context)
    initial_device_calls = len(calls["devices"])

    context.invocation_id = "confirmation-turn"
    result = orchestrator.confirm_account_access_offer.func(context)

    assert result["code"] == "ACCOUNT_ACCESS_PLAN_NOT_EXECUTABLE"
    assert len(calls["devices"]) == initial_device_calls
    assert CALLER_UPN in ad_account_tool._demo_disabled_upns


def test_missing_sop_stops_confirmation_before_fresh_identity_or_mutation(monkeypatch):
    calls, _ = _install_directory(monkeypatch, manager_upn=MANAGER_UPN)
    context = _context(invocation_id="diagnosis-turn")
    ad_account_tool._demo_disabled_upns.add(CALLER_UPN)
    orchestrator.diagnose_account_access.func(CALLER_UPN, context)
    initial_device_calls = len(calls["devices"])
    monkeypatch.setattr(
        orchestrator,
        "sop_retriever",
        Mock(return_value={"status": "error", "snippets": []}),
    )

    context.invocation_id = "confirmation-turn"
    result = orchestrator.confirm_account_access_offer.func(context)

    assert result["code"] == "ACCOUNT_ACCESS_SOP_UNAVAILABLE"
    assert len(calls["devices"]) == initial_device_calls
    assert CALLER_UPN in ad_account_tool._demo_disabled_upns


def test_expired_offer_cannot_execute(monkeypatch):
    _install_directory(monkeypatch, manager_upn=MANAGER_UPN)
    retrieval = _install_planning(monkeypatch)
    context = _context(invocation_id="diagnosis-turn")
    ad_account_tool._demo_disabled_upns.add(CALLER_UPN)
    orchestrator.diagnose_account_access.func(CALLER_UPN, context)
    context.state[orchestrator.ACCOUNT_ACCESS_OFFER_STATE_KEY]["expires_at"] = 0

    context.invocation_id = "confirmation-turn"
    result = orchestrator.confirm_account_access_offer.func(context)

    assert result["code"] == "ACCOUNT_ACCESS_OFFER_EXPIRED"
    assert retrieval.call_count == 0
    assert CALLER_UPN in ad_account_tool._demo_disabled_upns


def test_explicit_enable_uses_sop_plan_fresh_identity_manager_and_devices(monkeypatch):
    calls, _ = _install_directory(monkeypatch, manager_upn=CALLER_UPN)
    retrieval = _install_planning(monkeypatch)
    context = _context()
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)

    result = orchestrator.execute_explicit_account_enable.func(TARGET_UPN, context)

    assert result["status"] == "ok"
    assert result["action_id"] == "ad.enable_account"
    assert TARGET_UPN not in ad_account_tool._demo_disabled_upns
    assert calls["managers"] == [TARGET_UPN]
    assert calls["devices"] == [CALLER_UPN, TARGET_UPN]
    retrieval.assert_called_once()


def test_password_reset_backend_requires_and_consumes_exact_policy_grant(monkeypatch):
    context = _context()
    # Avoid a real Graph mutation; reaching CONFIG_MISSING proves the exact grant
    # passed the new backend guard, and the second call proves it was consumed.
    monkeypatch.setattr(aad_tool, "_graph_is_configured", lambda: False)
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        account_action_id="aad.reset_password",
        plan_can_execute_fully=True,
        plan_low_confidence=False,
        plan_unmapped_count=0,
        plan_action_count=1,
        tool_context=context,
    )
    verification_id = "password-reset-controller-proof"
    context.state[ACCOUNT_ACCESS_IDENTITY_VERIFICATION_STATE_KEY] = {
        "verification_id": verification_id,
        "verified_at": time.time(),
        "requester": {"upn": CALLER_UPN},
        "target": {"upn": CALLER_UPN},
        "manager": None,
        "authorization_basis": "self",
        "requester_devices": [],
        "target_devices": [],
        "policy_action_id": "aad.reset_password",
    }
    context.state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY][
        "identity_verification_id"
    ] = verification_id

    first = aad_tool.aad_reset_password.func(context, CALLER_UPN)
    second = aad_tool.aad_reset_password.func(context, CALLER_UPN)

    assert policy["status"] == "ok"
    assert "CONFIG_MISSING" in first["reset"]["error"]
    assert second["reset"]["error"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert context.state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] is None
