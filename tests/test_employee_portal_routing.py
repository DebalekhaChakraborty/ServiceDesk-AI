"""Employee Portal login reports should not be asked "which application/system".

A caller who says "I'm unable to log in to the Employee Portal" has already
named both the system (the Employee Access Portal) and the problem domain
(account access / authentication, since the portal is backed by the same
Microsoft Entra directory Account Access already diagnoses). Before this fix,
sd_chat's own instructions had no vocabulary for "Employee Portal" at all, so
the model fell back to its generic "which application/system" question even
though the caller had just answered it.

sd_chat is an LLM-driven agent with no offline harness that actually drives
Gemini, so — matching the existing convention in test_ad_account_unlock.py
and friends (see test_agent_instructions_narrow_ad_diagnosis_and_guard_explicit_actions
and test_named_system_login_does_not_automatically_trigger_ad_lock_check) —
these tests pin the exact instruction text the model is given, plus the
deterministic Python-level context plumbing that feeds it.
"""

from __future__ import annotations

import inspect
import json
import os

# win_tool reads this at import time with no default; other suites in this
# repo set it the same way before importing sd_chat.agent.
os.environ.setdefault("WINRM_PORT", "5986")

from sd_chat.agent import sd_chat
from sd_chat.tools import account_access_orchestrator as orchestrator
from sd_chat.tools.identity_context_tool import ensure_identity_context_in_state


PERSONA = {
    "userPrincipalName": "alice@example.invalid",
    "mail": "alice@example.invalid",
    "displayName": "Alice Test",
    "id": "aaaaaaaa-0000-0000-0000-000000000001",
}

EMPLOYEE_PORTAL_ENTRYPOINT = {
    "channel": "external_voice",
    "continuation": True,
    "suppress_initial_greeting": True,
    "entrypoint": "employee_access_portal",
    "current_application": "employee_access_portal",
}


# ---------------------------------------------------------------------------
# 1. The system and domain resolve without a redundant question.
# ---------------------------------------------------------------------------

def test_employee_portal_phrases_resolve_to_the_canonical_system():
    instruction = sd_chat.instruction

    assert "Employee Portal Context Resolution" in instruction
    for phrase in (
        '"employee portal"', '"employee access portal"',
        '"enterprise workspace"', '"employee workspace"',
        '"portal" /\n"this portal"'.replace("\n", " "),
    ):
        assert phrase in instruction.replace("\n", " "), phrase
    assert "employee_access_portal" in instruction


def test_a_login_report_answers_both_system_and_domain_at_once():
    instruction = sd_chat.instruction

    assert (
        "already answers\nboth open questions at once: the affected system "
        "(Employee Access Portal) and\nthe problem domain (account access / "
        "authentication)" in instruction
        or "already answers\nboth open questions at once" in instruction
    )
    assert "the problem domain (account access / authentication)" in instruction


def test_no_which_application_or_system_clarification_for_employee_portal():
    instruction = sd_chat.instruction

    # The exemption sits right next to the rule it exempts, and both survive
    # verbatim (a regression here would mean one was edited out from under
    # the other).
    assert "Which application/system or domain sign-in is failing" in instruction
    assert (
        'do not ask\n"Which application/system or domain sign-in is failing"'
        in instruction
    )


def test_no_endpoint_class_clarification_for_employee_portal():
    instruction = sd_chat.instruction

    assert (
        "do not ask which\ndevice or whether it is a registered device or VDI"
        in instruction
    )


def test_employee_portal_routes_directly_into_account_access_diagnosis():
    instruction = sd_chat.instruction

    assert "call diagnose_account_access directly" in instruction.replace("\n", " ")
    assert "I can't access my account" in instruction  # the existing analogue


# ---------------------------------------------------------------------------
# 2. It resolves a diagnosis PATH, not a diagnosis RESULT.
# ---------------------------------------------------------------------------

def test_no_root_cause_is_invented_before_diagnosis_runs():
    instruction = sd_chat.instruction

    assert "NOT itself a diagnosis or a\nconclusion" in instruction
    assert (
        "Never say or imply the account is locked, disabled, or that the\n"
        "password is wrong before ad_get_account_status actually reports that"
        in instruction
    )
    # The existing account-status handling this hands off to is untouched:
    # still no auto-remediation and still a real Graph/AD read every time.
    assert "Never offer or execute unlock/password reset automatically" in instruction


def test_diagnose_account_access_still_requires_live_verification():
    """The routing shortcut never reaches past sd_chat's own instructions.

    diagnose_account_access is the SAME protected controller as before: it
    still calls _verify_identity (fresh Graph reads, manager check, device
    evidence) before any account state is returned. Nothing about entrypoint
    resolution changes that function.
    """
    source = inspect.getsource(orchestrator._diagnose_verified_target)
    assert "_verify_identity(tool_context, target_upn)" in source
    assert "ad_get_account_status" in source


# ---------------------------------------------------------------------------
# 3. Bare "portal" needs backing context; it is never force-mapped.
# ---------------------------------------------------------------------------

def test_bare_portal_mention_is_not_force_mapped_without_context():
    instruction = sd_chat.instruction

    assert "ONLY when identity_context_tool's interaction.current_application" in instruction
    assert (
        'Do not force-map a bare "portal" mention\nwith no such backing signal'
        in instruction
    )
    assert "treat it as underspecified and fall back to the\nexisting single combined question" in instruction


def test_interaction_context_alone_carries_no_authority_over_routing():
    instruction = sd_chat.instruction

    assert "never usable to select a target user or bypass a\npolicy check" in instruction
    assert "never a substitute for\nDuo/Graph verification" in instruction
    assert "never a source of authorization" in instruction


# ---------------------------------------------------------------------------
# 4. Other named systems do not regress.
# ---------------------------------------------------------------------------

def test_other_named_systems_still_use_their_own_routing():
    instruction = sd_chat.instruction

    # Unchanged, pinned rule: still present verbatim. The Employee Portal
    # carve-out names these systems only in passing, to contrast why it is an
    # exception (its sign-in IS the Entra directory Account Access already
    # diagnoses; theirs is not) — the rule that sends THEM to their own
    # SOP/RAG flow, unaffected, is this exact sentence, still intact.
    assert "AWS WorkSpaces, HOST, Teams, ServiceNow, or VPN" in instruction
    assert "Named-system routing has precedence" in instruction
    assert (
        "let that system's existing\n  SOP/RAG/planner flow handle it"
        in instruction
    )


def test_sap_login_does_not_resolve_to_employee_portal():
    """"I can't log in to SAP" must never satisfy the Employee Portal rule.

    There is no live model to drive here, so this pins the two structural
    facts that make a wrong resolution impossible: SAP is not one of the
    resolvable phrases anywhere in the instructions, and the bare-word
    fallback requires an entrypoint signal that a plain SAP report never
    carries.
    """
    instruction = sd_chat.instruction

    assert "sap" not in instruction.lower()
    result = ensure_identity_context_in_state({
        "persona": PERSONA,
        "interaction_context": {
            "channel": "chat", "continuation": False,
            "suppress_initial_greeting": False,
        },
    })
    assert result["interaction"]["current_application"] is None


# ---------------------------------------------------------------------------
# 5. The entrypoint context itself: seeded, typed, and scoped to voice.
# ---------------------------------------------------------------------------

def test_employee_portal_entrypoint_context_reaches_the_model():
    result = ensure_identity_context_in_state({
        "persona": PERSONA, "interaction_context": EMPLOYEE_PORTAL_ENTRYPOINT,
    })

    assert result["interaction"]["entrypoint"] == "employee_access_portal"
    assert result["interaction"]["current_application"] == "employee_access_portal"
    # Still nothing about identity.
    identity_blob = json.dumps(result["identity"])
    assert "employee_access_portal" not in identity_blob


def test_a_normal_web_chat_session_has_no_entrypoint_opinion():
    """No voice launch means no claim about where the conversation started."""
    result = ensure_identity_context_in_state({"persona": PERSONA})

    assert result["interaction"]["entrypoint"] is None
    assert result["interaction"]["current_application"] is None
