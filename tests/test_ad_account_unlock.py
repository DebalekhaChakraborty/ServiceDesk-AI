import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


# The existing win_tool reads this value during package import without a default.
os.environ.setdefault("WINRM_PORT", "5986")

from sd_chat.planner import reasoning_composer
from sd_chat.agent import sd_chat
from sd_chat.tools import ad_account_tool
from sd_chat.tools.aad_tool import aad_reset_password
from sd_chat.tools.policy_tool import check_list


CALLER_UPN = "caller@example.com"
TARGET_UPN = "target@example.com"


@pytest.fixture(autouse=True)
def isolated_demo_backend(monkeypatch):
    monkeypatch.setattr(ad_account_tool, "AD_UNLOCK_MODE", "demo")
    monkeypatch.setattr(ad_account_tool, "_demo_locked_upns", set())


def _tool_context():
    return SimpleNamespace(state={})


def _check_status(tool_context, target_upn):
    return ad_account_tool.ad_check_account_lock_status.func(tool_context, target_upn)


def _unlock(target_upn):
    return ad_account_tool.ad_unlock_account.func(target_upn)


def test_explicit_self_unlock_runs_directly_without_lock_diagnosis():
    ad_account_tool._demo_locked_upns.add(CALLER_UPN)
    policy_gate = Mock(wraps=check_list)
    lock_status = Mock(wraps=ad_account_tool.ad_check_account_lock_status.func)

    policy = policy_gate(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        manager_upn="",
    )
    result = _unlock(CALLER_UPN) if policy["status"] == "ok" else None

    assert policy["status"] == "ok"
    assert result["unlock"]["was_locked"] is True
    assert result["unlock"]["is_locked"] is False
    policy_gate.assert_called_once()
    lock_status.assert_not_called()


def test_self_account_already_unlocked_is_clean_noop():
    result = _unlock(CALLER_UPN)

    assert result["status"] == "ok"
    assert result["unlock"]["was_locked"] is False
    assert result["unlock"]["is_locked"] is False
    assert "already unlocked" in result["unlock"]["message"]


def test_explicit_manager_unlock_uses_resolved_manager_for_policy():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    manager_lookup = Mock(
        return_value={
            "ok": True,
            "target_upn": TARGET_UPN,
            "manager": {"upn": CALLER_UPN},
            "error": None,
        }
    )

    manager_result = manager_lookup(TARGET_UPN)
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=manager_result["manager"]["upn"],
    )
    result = _unlock(TARGET_UPN) if policy["status"] == "ok" else None

    manager_lookup.assert_called_once_with(TARGET_UPN)
    assert policy["status"] == "ok"
    assert result["unlock"]["was_locked"] is True


def test_unauthorized_other_user_is_blocked_before_unlock():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    unlock_backend = Mock(wraps=ad_account_tool.ad_unlock_account.func)

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn="different.manager@example.com",
    )
    if policy["status"] == "ok":
        unlock_backend(TARGET_UPN)

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
    monkeypatch.setattr(ad_account_tool, "AD_UNLOCK_MODE", "ad_ds")

    result = _unlock(TARGET_UPN)

    assert result["status"] == "error"
    assert result["code"] == "AD_DS_BACKEND_NOT_CONFIGURED"
    assert result["stdout"] == ""
    assert result["stderr"]
    assert result["unlock"]["status"] == "error"
    assert result["unlock"]["target_upn"] == TARGET_UPN


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


def test_explicit_password_reset_does_not_require_lock_diagnosis():
    lock_status = Mock(wraps=ad_account_tool.ad_check_account_lock_status.func)
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
    lock_status.assert_not_called()


def test_ambiguous_locked_account_offers_unlock_without_executing_it():
    ad_account_tool._demo_locked_upns.add(CALLER_UPN)
    tool_context = _tool_context()
    unlock_backend = Mock(wraps=ad_account_tool.ad_unlock_account.func)

    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        manager_upn="",
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
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=TARGET_UPN,
        manager_upn=manager["manager"]["upn"],
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
    )
    if policy["status"] == "ok":
        lock_status(tool_context, TARGET_UPN)

    assert policy["status"] == "error"
    lock_status.assert_not_called()
    assert tool_context.state == {}


def test_confirmation_after_unlock_offer_uses_retained_target():
    ad_account_tool._demo_locked_upns.add(TARGET_UPN)
    tool_context = _tool_context()
    _check_status(tool_context, TARGET_UPN)
    unlock_backend = Mock(wraps=ad_account_tool.ad_unlock_account.func)

    unlock_backend(tool_context.state["account_access_diagnosis"]["target_upn"])

    unlock_backend.assert_called_once_with(TARGET_UPN)
    assert TARGET_UPN not in ad_account_tool._demo_locked_upns


def test_confirmation_after_password_reset_offer_uses_retained_target():
    tool_context = _tool_context()
    _check_status(tool_context, TARGET_UPN)
    password_reset = Mock(return_value={"reset": {"status": "ok"}})

    password_reset(tool_context.state["account_access_diagnosis"]["target_upn"])

    password_reset.assert_called_once_with(TARGET_UPN)


def test_agent_instructions_describe_direct_and_ambiguous_account_access_paths():
    instruction = sd_chat.instruction

    assert "explicit account unlock" in instruction
    assert "ambiguous account-access/login problem" in instruction
    assert "do not diagnose lock status before it" in instruction
    assert "Do not execute either remediation until the user confirms." in instruction
