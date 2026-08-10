import os
from unittest.mock import Mock

import pytest


# The existing win_tool reads this value during package import without a default.
os.environ.setdefault("WINRM_PORT", "5986")

from sd_chat.planner import reasoning_composer
from sd_chat.tools import ad_account_tool
from sd_chat.tools.aad_tool import aad_reset_password
from sd_chat.tools.policy_tool import check_list


CALLER_UPN = "caller@example.com"
TARGET_UPN = "target@example.com"


@pytest.fixture(autouse=True)
def isolated_demo_backend(monkeypatch):
    monkeypatch.setattr(ad_account_tool, "AD_UNLOCK_MODE", "demo")
    monkeypatch.setattr(ad_account_tool, "_demo_locked_upns", set())


def _check_status(target_upn):
    return ad_account_tool.ad_check_account_lock_status.func(target_upn)


def _unlock(target_upn):
    return ad_account_tool.ad_unlock_account.func(target_upn)


def test_self_unlock_checks_policy_unlocks_and_verifies():
    ad_account_tool._demo_locked_upns.add(CALLER_UPN)
    policy_gate = Mock(wraps=check_list)

    before = _check_status(CALLER_UPN)
    policy = policy_gate(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn=CALLER_UPN,
        manager_upn="",
    )
    result = _unlock(CALLER_UPN) if policy["status"] == "ok" else None
    after = _check_status(CALLER_UPN)

    assert before["account"]["locked"] is True
    assert policy["status"] == "ok"
    assert result["unlock"]["was_locked"] is True
    assert result["unlock"]["is_locked"] is False
    assert after["account"]["locked"] is False
    policy_gate.assert_called_once()


def test_self_account_already_unlocked_is_clean_noop():
    result = _unlock(CALLER_UPN)

    assert result["status"] == "ok"
    assert result["unlock"]["was_locked"] is False
    assert result["unlock"]["is_locked"] is False
    assert "already unlocked" in result["unlock"]["message"]


def test_manager_unlock_uses_resolved_manager_for_policy():
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
    assert _check_status(TARGET_UPN)["account"]["locked"] is False


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
    assert _check_status(TARGET_UPN)["account"]["locked"] is True


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
