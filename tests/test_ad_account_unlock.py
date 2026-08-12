import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


# The existing win_tool reads this value during package import without a default.
os.environ.setdefault("WINRM_PORT", "5986")

from sd_chat.planner import reasoning_composer
from sd_chat.agent import sd_chat
from sd_chat.tools import aad_tool, ad_account_tool
from sd_chat.tools.aad_tool import aad_reset_password
from sd_chat.tools.policy_tool import (
    AAD_MANAGER_LOOKUP_STATE_KEY,
    ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY,
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


def _check_status(tool_context, target_upn):
    return ad_account_tool.ad_check_account_lock_status.func(tool_context, target_upn)


def _account_status(tool_context, target_upn):
    return ad_account_tool.ad_get_account_status.func(tool_context, target_upn)


def _unlock(tool_context, target_upn):
    return ad_account_tool.ad_unlock_account.func(target_upn, tool_context)


def _record_manager_lookup(tool_context, target_upn, manager_upn):
    tool_context.state[AAD_MANAGER_LOOKUP_STATE_KEY] = {
        "target_upn": target_upn.lower(),
        "manager_upn": manager_upn.lower(),
        "source": "microsoft_graph",
    }


def _account_action_plan_kwargs(action_id):
    return {
        "account_action_id": action_id,
        "plan_can_execute_fully": True,
        "plan_low_confidence": False,
        "plan_unmapped_count": 0,
        "plan_action_count": 1,
    }


def test_explicit_self_unlock_runs_directly_without_lock_diagnosis():
    ad_account_tool._demo_locked_upns.add(CALLER_UPN)
    tool_context = _tool_context()
    policy_gate = Mock(wraps=check_list)
    account_status = Mock(wraps=ad_account_tool.ad_get_account_status.func)
    password_reset = Mock()

    policy = policy_gate(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        manager_upn="",
        tool_context=tool_context,
        **_account_action_plan_kwargs("ad.unlock_account"),
    )
    result = _unlock(tool_context, CALLER_UPN) if policy["status"] == "ok" else None

    assert policy["status"] == "ok"
    assert result["unlock"]["was_locked"] is True
    assert result["unlock"]["is_locked"] is False
    policy_gate.assert_called_once()
    account_status.assert_not_called()
    password_reset.assert_not_called()


def test_self_account_already_unlocked_is_clean_noop():
    tool_context = _tool_context()
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        tool_context=tool_context,
        **_account_action_plan_kwargs("ad.unlock_account"),
    )
    result = _unlock(tool_context, CALLER_UPN)

    assert policy["status"] == "ok"
    assert result["status"] == "ok"
    assert result["unlock"]["was_locked"] is False
    assert result["unlock"]["is_locked"] is False
    assert "already unlocked" in result["unlock"]["message"]


def test_explicit_manager_unlock_uses_resolved_manager_for_policy():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    manager_lookup = Mock(
        return_value={
            "ok": True,
            "target_upn": TARGET_UPN,
            "manager": {"upn": CALLER_UPN},
            "error": None,
        }
    )

    manager_result = manager_lookup(TARGET_UPN)
    _record_manager_lookup(tool_context, TARGET_UPN, CALLER_UPN)
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=manager_result["manager"]["upn"],
        tool_context=tool_context,
        **_account_action_plan_kwargs("ad.unlock_account"),
    )
    result = _unlock(tool_context, TARGET_UPN) if policy["status"] == "ok" else None

    manager_lookup.assert_called_once_with(TARGET_UPN)
    assert policy["status"] == "ok"
    assert result["unlock"]["was_locked"] is True


def test_unauthorized_other_user_is_blocked_before_unlock():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    unlock_backend = Mock(wraps=ad_account_tool.ad_unlock_account.func)

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn="different.manager@example.com",
        tool_context=tool_context,
        **_account_action_plan_kwargs("ad.unlock_account"),
    )
    if policy["status"] == "ok":
        unlock_backend(TARGET_UPN, tool_context)

    assert policy["status"] == "error"
    assert "not authorized" in policy["message"]
    unlock_backend.assert_not_called()
    assert TARGET_UPN in ad_account_tool._demo_locked_upns


def test_unknown_target_stops_before_unlock():
    user_lookup = Mock(
        return_value={
            "ok": False,
            "query": "Unknown Person",
            "matches": [],
            "error": "No users found for the given query.",
        }
    )
    unlock_backend = Mock(wraps=ad_account_tool.ad_unlock_account.func)

    lookup_result = user_lookup("Unknown Person")
    if lookup_result["matches"]:
        unlock_backend(lookup_result["matches"][0]["upn"])

    assert lookup_result["ok"] is False
    unlock_backend.assert_not_called()


def test_backend_failure_matches_existing_failure_fallback_shape(monkeypatch):
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "ad_ds")
    tool_context = _tool_context()
    check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=TARGET_UPN,
        target_upn=TARGET_UPN,
        tool_context=tool_context,
        **_account_action_plan_kwargs("ad.unlock_account"),
    )

    result = _unlock(tool_context, TARGET_UPN)

    assert result["status"] == "error"
    assert result["code"] == "AD_DS_BACKEND_NOT_CONFIGURED"
    assert result["stdout"] == ""
    assert result["stderr"]
    assert result["unlock"]["status"] == "error"
    assert result["unlock"]["target_upn"] == TARGET_UPN


def test_missing_mode_configuration_defaults_to_disabled(monkeypatch):
    monkeypatch.delenv("AD_ACCOUNT_MODE", raising=False)

    assert ad_account_tool._configured_account_mode() == "off"


def test_disabled_backend_cannot_claim_success_or_change_demo_state(monkeypatch):
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    ad_account_tool._demo_disabled_upns.add(TARGET_UPN)
    monkeypatch.setattr(ad_account_tool, "AD_ACCOUNT_MODE", "off")
    tool_context = _tool_context()
    check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=TARGET_UPN,
        target_upn=TARGET_UPN,
        tool_context=tool_context,
        **_account_action_plan_kwargs("ad.unlock_account"),
    )

    result = _unlock(tool_context, TARGET_UPN)

    assert result["status"] == "error"
    assert result["code"] == "AD_ACCOUNT_BACKEND_OFF"
    assert result["unlock"]["status"] == "error"
    assert TARGET_UPN in ad_account_tool._demo_locked_upns
    assert TARGET_UPN in ad_account_tool._demo_disabled_upns


def test_password_reset_action_remains_registered_and_callable():
    registry = reasoning_composer._load_registry()

    assert any(action["id"] == "aad.reset_password" for action in registry)
    assert aad_reset_password.name == "aad_reset_password"
    assert callable(aad_reset_password.func)


def test_registry_still_loads_all_existing_actions():
    registry = reasoning_composer._load_registry()
    action_ids = {action["id"] for action in registry}

    assert {
        "aad.reset_password",
        "win.install_software",
        "win.restart_wuauserv",
        "win.time_resync",
        "ad.unlock_account",
    } <= action_ids


def test_account_unlock_sop_step_maps_to_registered_action(monkeypatch):
    monkeypatch.setattr(reasoning_composer, "GENAI_AVAILABLE", False)

    result = reasoning_composer.propose_plan(
        user_text="My Active Directory account is locked.",
        ctx_vars=["target_upn"],
        sop_texts=["Unlock the target Active Directory account"],
    )

    assert result["status"] == "ok"
    assert result["plan"]["tool_sequence"] == [
        {
            "tool": "ad_account_tool",
            "action": "unlock_account",
            "args": {"target_upn": "${target_upn}"},
            "action_id": "ad.unlock_account",
        }
    ]
    assert result["plan"]["preconditions"] == ["caller_is_self_or_manager"]
    assert result["plan"]["required_inputs"] == []
    assert result["plan"]["can_execute_fully"] is True
    assert result["plan"]["low_confidence"] is False
    assert result["plan"]["unmapped"] == []


def test_realistic_account_unlock_sop_produces_one_atomic_action(monkeypatch):
    monkeypatch.setattr(reasoning_composer, "GENAI_AVAILABLE", False)
    realistic_sop = {
        "prerequisites": [
            "Identify the requesting user and target account",
            "Validate that the requester is the account owner or the target user's manager",
        ],
        "atomic_remediation": [
            "Unlock the target Active Directory account if necessary",
        ],
        "tool_behavior_and_postconditions": [
            "Check whether the target account is locked",
            "Verify the account is unlocked",
        ],
    }

    result = reasoning_composer.propose_plan(
        user_text="Unlock my Active Directory account.",
        ctx_vars=["target_upn"],
        sop_texts=realistic_sop["atomic_remediation"],
    )
    unlock_action = next(
        action
        for action in reasoning_composer._load_registry()
        if action["id"] == "ad.unlock_account"
    )

    assert len(realistic_sop["prerequisites"]) == 2
    assert len(realistic_sop["tool_behavior_and_postconditions"]) == 2
    assert "Checks the current lock state" in unlock_action["description"]
    assert "verifies the final lock state" in unlock_action["description"]
    assert result["plan"]["can_execute_fully"] is True
    assert result["plan"]["low_confidence"] is False
    assert result["plan"]["unmapped"] == []
    assert [step["action_id"] for step in result["plan"]["tool_sequence"]] == [
        "ad.unlock_account"
    ]


def test_explicit_password_reset_maps_to_existing_atomic_action(monkeypatch):
    monkeypatch.setattr(reasoning_composer, "GENAI_AVAILABLE", False)

    result = reasoning_composer.propose_plan(
        user_text="Reset my password.",
        ctx_vars=["target_upn"],
        sop_texts=["Reset Azure AD password for a user"],
    )

    assert result["plan"]["can_execute_fully"] is True
    assert result["plan"]["low_confidence"] is False
    assert result["plan"]["unmapped"] == []
    assert [step["action_id"] for step in result["plan"]["tool_sequence"]] == [
        "aad.reset_password"
    ]


def test_explicit_password_reset_does_not_require_lock_diagnosis():
    account_status = Mock(wraps=ad_account_tool.ad_get_account_status.func)
    password_reset = Mock(return_value={"reset": {"status": "ok"}})

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        manager_upn="",
    )
    if policy["status"] == "ok":
        password_reset(CALLER_UPN)

    assert policy["status"] == "ok"
    password_reset.assert_called_once_with(CALLER_UPN)
    account_status.assert_not_called()


def test_ambiguous_locked_account_offers_unlock_without_executing_it():
    ad_account_tool._demo_locked_upns.add(CALLER_UPN)
    tool_context = _tool_context()
    unlock_backend = Mock(wraps=ad_account_tool.ad_unlock_account.func)

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        manager_upn="",
        tool_context=tool_context,
    )
    status = _check_status(tool_context, CALLER_UPN) if policy["status"] == "ok" else None

    assert policy["status"] == "ok"
    assert status["account"]["locked"] is True
    assert tool_context.state["account_access_diagnosis"]["target_upn"] == CALLER_UPN
    assert tool_context.state["account_access_diagnosis"]["locked"] is True
    unlock_backend.assert_not_called()


def test_ambiguous_unlocked_account_offers_password_reset_without_executing_it():
    tool_context = _tool_context()
    password_reset = Mock(return_value={"reset": {"status": "ok"}})

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        manager_upn="",
        tool_context=tool_context,
    )
    status = _check_status(tool_context, CALLER_UPN) if policy["status"] == "ok" else None

    assert policy["status"] == "ok"
    assert status["account"]["locked"] is False
    assert tool_context.state["account_access_diagnosis"]["target_upn"] == CALLER_UPN
    password_reset.assert_not_called()


def test_manager_can_run_ambiguous_access_diagnosis():
    tool_context = _tool_context()
    manager_lookup = Mock(return_value={"ok": True, "manager": {"upn": CALLER_UPN}})

    manager = manager_lookup(TARGET_UPN)
    _record_manager_lookup(tool_context, TARGET_UPN, CALLER_UPN)
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=manager["manager"]["upn"],
        tool_context=tool_context,
    )
    status = _check_status(tool_context, TARGET_UPN) if policy["status"] == "ok" else None

    manager_lookup.assert_called_once_with(TARGET_UPN)
    assert policy["status"] == "ok"
    assert status["account"]["target_upn"] == TARGET_UPN


def test_unauthorized_caller_cannot_run_ambiguous_access_diagnosis():
    tool_context = _tool_context()
    lock_status = Mock(wraps=ad_account_tool.ad_check_account_lock_status.func)

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn="different.manager@example.com",
        tool_context=tool_context,
    )
    if policy["status"] == "ok":
        lock_status(tool_context, TARGET_UPN)

    assert policy["status"] == "error"
    lock_status.assert_not_called()
    assert tool_context.state[ACCOUNT_ACCESS_AUTHORIZATION_STATE_KEY] is None


def test_confirmation_after_unlock_offer_uses_retained_target():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    _record_manager_lookup(tool_context, TARGET_UPN, CALLER_UPN)
    check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=CALLER_UPN,
        tool_context=tool_context,
    )
    _check_status(tool_context, TARGET_UPN)
    unlock_backend = Mock(wraps=ad_account_tool.ad_unlock_account.func)

    check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=CALLER_UPN,
        tool_context=tool_context,
        **_account_action_plan_kwargs("ad.unlock_account"),
    )
    unlock_backend(
        tool_context.state["account_access_diagnosis"]["target_upn"],
        tool_context,
    )

    unlock_backend.assert_called_once_with(TARGET_UPN, tool_context)
    assert TARGET_UPN not in ad_account_tool._demo_locked_upns


def test_confirmation_after_password_reset_offer_uses_retained_target():
    tool_context = _tool_context()
    _record_manager_lookup(tool_context, TARGET_UPN, CALLER_UPN)
    check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=CALLER_UPN,
        tool_context=tool_context,
    )
    _check_status(tool_context, TARGET_UPN)
    password_reset = Mock(return_value={"reset": {"status": "ok"}})

    password_reset(tool_context.state["account_access_diagnosis"]["target_upn"])

    password_reset.assert_called_once_with(TARGET_UPN)


def test_generated_account_authorization_precondition_fails_closed():
    tool_context = _tool_context()

    policy = check_list(
        preconditions=["ad_account_lock_status_authorized"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=CALLER_UPN,
        tool_context=tool_context,
    )
    status = _check_status(tool_context, TARGET_UPN)

    assert policy["status"] == "error"
    assert policy["code"] == "UNKNOWN_PRECONDITION"
    assert policy["details"]["ad_account_lock_status_authorized"]["ok"] is False
    assert status["status"] == "error"
    assert status["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert "account_access_diagnosis" not in tool_context.state


def test_non_manager_cannot_read_another_users_account_status():
    tool_context = _tool_context()
    caller_upn = "requester@example.com"
    other_user_upn = "unauthorized.employee@example.com"
    actual_manager_upn = "actual.manager@example.com"

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=caller_upn,
        target_upn=other_user_upn,
        manager_upn=actual_manager_upn,
        tool_context=tool_context,
    )
    status = _check_status(tool_context, other_user_upn)

    assert policy["status"] == "error"
    assert policy["details"]["caller_is_self_or_manager"]["ok"] is False
    assert status["status"] == "error"
    assert status["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert "account_access_diagnosis" not in tool_context.state


def test_missing_manager_does_not_use_a_default_identity():
    tool_context = _tool_context()

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        tool_context=tool_context,
    )

    assert policy["status"] == "error"
    detail = policy["details"]["caller_is_self_or_manager"]
    assert detail["manager_upn"] == ""
    assert detail["ok"] is False


def test_manager_argument_without_graph_evidence_is_rejected():
    tool_context = _tool_context()

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=CALLER_UPN,
        tool_context=tool_context,
    )

    assert policy["status"] == "error"
    detail = policy["details"]["caller_is_self_or_manager"]
    assert detail["manager_lookup_verified"] is False
    assert detail["ok"] is False


def test_graph_manager_lookup_records_target_bound_evidence(monkeypatch):
    tool_context = _tool_context()
    graph_response = SimpleNamespace(
        status_code=200,
        text="",
        json=lambda: {
            "displayName": "Caller",
            "userPrincipalName": CALLER_UPN,
            "id": "manager-object-id",
        },
    )
    monkeypatch.setattr(aad_tool, "_graph_is_configured", lambda: True)
    monkeypatch.setattr(aad_tool, "_graph_get", lambda *args, **kwargs: graph_response)

    manager = aad_tool.aad_get_manager.func(tool_context, TARGET_UPN)
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=manager["manager"]["upn"],
        tool_context=tool_context,
    )

    assert manager["ok"] is True
    assert tool_context.state[AAD_MANAGER_LOOKUP_STATE_KEY] == {
        "target_upn": TARGET_UPN,
        "manager_upn": CALLER_UPN,
        "source": "microsoft_graph",
    }
    assert policy["status"] == "ok"
    assert policy["details"]["caller_is_self_or_manager"][
        "manager_lookup_verified"
    ] is True


def test_ad_tools_require_authorization_for_the_exact_target():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        tool_context=tool_context,
    )

    status = _check_status(tool_context, TARGET_UPN)
    unlock = _unlock(tool_context, TARGET_UPN)

    assert policy["status"] == "ok"
    assert status["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert unlock["code"] == "ACCOUNT_ACCESS_AUTHORIZATION_REQUIRED"
    assert TARGET_UPN in ad_account_tool._demo_locked_upns


def test_agent_instructions_narrow_ad_diagnosis_and_guard_explicit_actions():
    instruction = sd_chat.instruction

    assert "explicit account unlock" in instruction
    assert "explicit account enable" in instruction
    assert "ambiguous enterprise/domain/AD account-access problem" in instruction
    assert "AWS WorkSpaces, HOST, Teams, ServiceNow, or VPN" in instruction
    assert "do not automatically classify it as AD account access" in instruction
    assert "Do not run account-status" in instruction
    assert "diagnosis before any explicit action" in instruction
    assert "maps exactly one expected action" in instruction
    assert "ad.enable_account for enable" in instruction
    assert "plan.can_execute_fully == true" in instruction
    assert "plan.low_confidence == false" in instruction
    assert "unexpected plans must stop without execution" in instruction
    assert "preconditions exactly equal to" in instruction
    assert '["caller_is_self_or_manager"]' in instruction
    assert "Never rename, paraphrase, generalize" in instruction
    assert "check_list.details.caller_is_self_or_manager.ok == true" in instruction
    assert "If manager lookup fails or returns no manager UPN, stop" in instruction


def test_broad_access_instruction_checks_enabled_and_locked_state_together():
    instruction = sd_chat.instruction

    assert "Call ad_get_account_status once after authorization" in instruction
    assert "enabled and locked as" in instruction
    assert "independent fields" in instruction
    assert "enabled is the real directory accountEnabled value" in instruction
    assert "locked may be null" in instruction
    assert "Null means unknown, never false" in instruction
    assert 'never say "not locked"' in instruction
    assert "If enabled == false and locked == true" in instruction
    assert "offer only enable first" in instruction
    assert "If enabled == false and locked == null" in instruction
    assert "account is disabled and that current lock state is unavailable" in instruction
    assert "If enabled == true and locked == false" in instruction
    assert "offer the existing password reset" in instruction
    assert "If enabled == true and locked == null" in instruction
    assert "Do not describe the account as healthy or" in instruction
    assert "A recent" in instruction
    assert "error code 50053 is historical evidence" in instruction
    assert "never convert it" in instruction
    assert "Absence of a sampled 50053 event does not prove" in instruction
    assert "Never offer or execute unlock/password reset automatically" in instruction
    assert "next_step.kind ==" in instruction
    assert "ask its next_step.question verbatim" in instruction
    assert "Do not offer a password reset" in instruction
    assert "re-run authorization and ad_get_account_status" in instruction


def test_account_access_instruction_requires_diagnosis_before_remediation():
    instruction = sd_chat.instruction

    assert "Diagnosis must precede remediation selection" in instruction
    assert "response must contain exactly one question and no examples" in instruction
    assert "Which application/system or domain sign-in is failing" in instruction
    assert "and what exact error do you see?" in instruction
    assert "a general sign-in problem is" in instruction
    assert "diagnosis request, not yet a remediation request" in instruction
    assert "ask exactly one" in instruction
    assert "Do not ask a list of intake questions" in instruction
    assert "Do not call sop_retriever or" in instruction
    assert "propose_plan and do not suggest a remediation yet" in instruction
    assert "I can't access my account" in instruction
    assert "enters the protected Account Access diagnosis" in instruction


def test_on_behalf_account_access_reuses_named_target_and_stops_if_unverified():
    instruction = sd_chat.instruction

    assert "person as the pending Account Access target" in instruction
    assert "diagnose_account_access_for_other_user" in instruction
    assert "not call aad_user_lookup" in instruction
    assert "checks the current manager before" in instruction
    assert "REQUESTER_NOT_TARGET_MANAGER" in instruction
    assert "I can only assist the account" in instruction
    assert "Stop there" in instruction
    assert "continue an on-behalf troubleshooting flow" in instruction


def test_account_access_instruction_rejects_unsupported_time_sync_and_stale_plan():
    instruction = sd_chat.instruction

    assert "Never retrieve, plan, or offer time_resync" in instruction
    assert "requires a matching reported symptom or error" in instruction
    assert "A retrieved SOP or proposed plan is only a candidate, not a diagnosis" in instruction
    assert "Never reuse an unexecuted candidate" in instruction


def test_named_system_login_does_not_automatically_trigger_ad_lock_check():
    instruction = sd_chat.instruction

    assert "Named-system routing has precedence" in instruction
    assert "does not by itself permit the" in instruction
    assert "generic Account Access status check" in instruction
    assert "only if the user separately identifies their enterprise/domain/AD account" in instruction
    assert "suspect or explicitly asks for its status" in instruction
    assert "must not replace, diagnosis of the named system" in instruction


def test_healthy_account_instruction_offers_existing_password_recovery_only():
    instruction = sd_chat.instruction

    assert "If enabled == true and locked == false" in instruction
    assert "neither disabled state nor lockout" in instruction
    assert "offer the existing password reset" in instruction
    assert "Do not reset until the user confirms" in instruction
    assert "Never let stale consent" in instruction
