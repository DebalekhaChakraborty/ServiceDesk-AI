"""Post-remediation: a successful unlock/enable must not restart sign-in intake.

Bug reproduced manually: caller says "I'm unable to log in to the Employee
Portal", goes through Account Access diagnosis, an unlock/enable is offered
and confirmed, it succeeds - and the agent then asked "What application or
system are you having problems with?" even though the application and symptom
were already known and the remediation had just completed.

Root cause (see account_access_orchestrator.py): _diagnose_verified_target is
shared between a FRESH initial diagnosis and the POST-ACTION recheck that
follows a successful enable/unlock (`response["post_action_status"] =
_diagnose_verified_target(...)` inside _execute_exact_action). Both used the
same _next_step() with no way to distinguish "nothing is known yet" from
"everything is already known, an action just ran". An identical Graph
snapshot (enabled=true, lock state unknown -> recommended_action =
"investigate_sign_in") therefore always produced the same generic
sign_in_intake question, regardless of context.

The fix adds an explicit `context` argument (INITIAL_DIAGNOSIS_CONTEXT vs
POST_REMEDIATION_CONTEXT) so the SAME ambiguous snapshot deterministically
produces a different next_step depending on which one is true - decided once
in the controller, never inferred by the agent from conversation prose. See
tests/test_account_access_orchestrator.py for the Python-level proof of that
branch; this file pins the sd_chat instruction text that consumes it, the
same way test_ad_account_unlock.py and test_employee_portal_routing.py already
pin the rest of this prompt (no live-model harness exists in this repo).
"""

from __future__ import annotations

import os

os.environ.setdefault("WINRM_PORT", "5986")

from sd_chat.agent import sd_chat
from sd_chat.tools import account_access_orchestrator as orchestrator


# ---------------------------------------------------------------------------
# 1. The controller-level distinction the instructions rely on
# ---------------------------------------------------------------------------

def test_orchestrator_exposes_the_two_named_contexts():
    assert orchestrator.INITIAL_DIAGNOSIS_CONTEXT == "initial_diagnosis"
    assert orchestrator.POST_REMEDIATION_CONTEXT == "post_remediation_verification"
    assert orchestrator._RETRY_ORIGINAL_REQUEST_NEXT_STEP["kind"] == "retry_original_request"
    assert orchestrator._SIGN_IN_INVESTIGATION_NEXT_STEP["kind"] == "sign_in_intake"


def test_the_controller_has_no_notion_of_which_application_this_is():
    """The system/symptom distinction is conversational, not something the
    Python controller tracks - it never receives an app name, only a UPN. The
    fix therefore has to be prompt-level for THAT part, and deterministic
    (context-based) only for the next_step kind itself. This is a structural
    check that the controller stays that narrow."""
    import inspect

    sig = inspect.signature(orchestrator._diagnose_verified_target)
    params = set(sig.parameters)
    assert params == {"target_upn", "tool_context", "context"}


# ---------------------------------------------------------------------------
# 2. Instruction text: what the agent does with post_action_status
# ---------------------------------------------------------------------------

def test_post_remediation_is_distinguished_from_a_fresh_diagnosis():
    instruction = sd_chat.instruction

    assert (
        "the reply\n  is a post-remediation turn, not a fresh diagnosis"
        in instruction
    )
    assert (
        "When post_action_status.next_step.kind ==\n"
        '  "retry_original_request"'
        in instruction
    )


def test_successful_action_leads_with_the_result_not_a_lock_state_claim():
    instruction = sd_chat.instruction

    assert "Lead with the action's own result message" in instruction
    assert (
        "never claim\n  a current lock state the backend did not confirm"
        in instruction
    )
    assert "say the action completed" in instruction


def test_post_remediation_never_asks_which_application_or_system():
    instruction = sd_chat.instruction

    assert (
        'Do not ask "which\n'
        "  application or system\", do not ask for a device or registered-device/VDI\n"
        "  class, and do not restart generic sign-in intake"
        in instruction
    )


def test_post_remediation_asks_the_caller_to_retry_the_original_request():
    instruction = sd_chat.instruction

    assert "ask\n  the caller to retry that SAME original request" in instruction
    assert "interaction.current_application" in instruction


def test_a_genuine_second_offer_still_gets_separate_confirmation():
    """enable -> unlock offer chain is untouched: this only changes what
    happens when there is NO further offer."""
    instruction = sd_chat.instruction

    assert "If post_action_status.offer\n  exists" in instruction
    assert "ask for that separate confirmation per the rule above" in instruction
    # The original, unmodified rule this builds on:
    assert "If it offers unlock, ask for" in instruction
    assert "do not unlock automatically" in instruction


# ---------------------------------------------------------------------------
# 3. "It still doesn't work" - continue, don't restart, don't re-ask known info
# ---------------------------------------------------------------------------

def test_still_failing_continues_the_same_system_without_reasking():
    instruction = sd_chat.instruction

    assert '"it still\n' in instruction or "it still\n    doesn't work" in instruction.replace(
        "'", '"')
    assert (
        "continue\n  investigating that SAME already-known application/system"
        in instruction
    )
    assert "never ask which\n  application or system again" in instruction


def test_already_supplied_evidence_is_not_asked_for_twice():
    instruction = sd_chat.instruction

    assert (
        "if the caller already gave that error earlier\n  in the conversation, "
        "do not ask for it again either"
        in instruction
    )


# ---------------------------------------------------------------------------
# 4. Regression: generic initial intake and named-system routing are untouched
# ---------------------------------------------------------------------------

def test_generic_initial_sign_in_intake_still_exists_for_a_truly_fresh_case():
    """"I can't sign in" with nothing else known must still be able to ask
    which application/system - this instruction is unmodified."""
    instruction = sd_chat.instruction

    assert "Which application/system or domain sign-in is failing" in instruction
    assert "and what exact error do you see?" in instruction
    assert "diagnosis request, not yet a remediation request" in instruction


def test_named_system_routing_is_unmodified():
    instruction = sd_chat.instruction

    assert "AWS WorkSpaces, HOST, Teams, ServiceNow, or VPN" in instruction
    assert "Named-system routing has precedence" in instruction


def test_the_new_retry_guidance_is_system_agnostic_not_hardcoded_to_one_app():
    """The fix must generalise to ANY already-known system (SAP, Employee
    Portal, ...), not just the Employee Portal example from the bug report.
    Pull out the new bullets and check they never hardcode a system name."""
    instruction = sd_chat.instruction
    start = instruction.index("After ANY successful unlock or enable")
    end = instruction.index(
        "When the user asks to recheck", start)
    block = instruction[start:end].lower()

    for hardcoded_system in ("sap", "employee portal", "employee_access_portal",
                              "workspaces", "vpn", "servicenow"):
        assert hardcoded_system not in block, hardcoded_system
    # It reasons about "the" already-known system generically instead.
    assert "already known from earlier in the conversation" in block


def test_employee_portal_context_resolution_is_unmodified():
    """The earlier Employee Portal routing fix (separate task) must still be
    intact: this task only changes what happens AFTER remediation, not how
    the system/domain first resolve."""
    instruction = sd_chat.instruction

    assert "Employee Portal Context Resolution" in instruction
    assert "call diagnose_account_access directly" in instruction.replace("\n", " ")
