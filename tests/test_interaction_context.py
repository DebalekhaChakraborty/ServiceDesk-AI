"""Voice continuation: the presentation flag that stops a second greeting.

A voice caller states their problem, is taken through Duo, and only then does
their ORIGINAL sentence arrive here as the first message of a brand-new ADK
session. To sd_chat that looks like the start of a conversation, so it greets —
and the caller hears a second introduction from what is meant to be one
continuous Service Desk.

The fix is one server-seeded boolean. These tests pin the two things that make
it safe to have at all: it says nothing except whether to say hello, and it
cannot be written by anyone but the server.
"""

from __future__ import annotations

import json

from sd_chat.tools.identity_context_tool import ensure_identity_context_in_state

PERSONA = {
    "userPrincipalName": "alice@example.invalid",
    "mail": "alice@example.invalid",
    "displayName": "Alice Test",
    "id": "aaaaaaaa-0000-0000-0000-000000000001",
    # Provenance the voice gateway attaches. None of it is the caller's PURPOSE.
    "channel": "external_voice",
    "identity_source": "duo_external_voice",
    "recovery_scope": "self_account_recovery",
    "auth_method": "duo_push",
    "employee_id": "1999",
}
VOICE_CONTINUATION = {
    "channel": "external_voice",
    "continuation": True,
    "suppress_initial_greeting": True,
}


def test_a_voice_continuation_is_reported_to_the_agent():
    result = ensure_identity_context_in_state({
        "persona": PERSONA, "interaction_context": VOICE_CONTINUATION,
    })

    assert result["ok"] is True
    assert result["interaction"]["suppress_initial_greeting"] is True
    assert result["interaction"]["continuation"] is True
    assert result["interaction"]["channel"] == "external_voice"
    # The identity lookup still happens and still works; this is additive.
    assert result["identity"]["display_name"] == "Alice Test"


def test_b_an_ordinary_chat_session_still_greets():
    """No context seeded means the normal web/portal behaviour, unchanged."""
    result = ensure_identity_context_in_state({"persona": PERSONA})

    assert result["interaction"]["suppress_initial_greeting"] is False
    assert result["interaction"]["continuation"] is False
    assert result["interaction"]["channel"] == "chat"


def test_c_the_flag_is_never_part_of_identity():
    """Two separate keys, so one can never be mistaken for the other."""
    result = ensure_identity_context_in_state({
        "persona": PERSONA, "interaction_context": VOICE_CONTINUATION,
    })

    identity_blob = json.dumps(result["identity"])
    assert "suppress_initial_greeting" not in identity_blob
    assert "continuation" not in identity_blob


def test_d_the_context_carries_no_authority_however_it_is_stuffed():
    """Extra keys are dropped, not passed through.

    The seeding path is server-side today, but the value is normalised rather
    than trusted wholesale: only the five presentation fields survive, so a
    future writer cannot smuggle a permission through this channel.
    """
    result = ensure_identity_context_in_state({
        "persona": PERSONA,
        "interaction_context": {
            **VOICE_CONTINUATION,
            "entrypoint": "employee_access_portal",
            "current_application": "employee_access_portal",
            "is_admin": True,
            "authenticated": True,
            "upn": "attacker@example.invalid",
            "allowed_hosts": ["dc01"],
            "skip_policy": True,
        },
    })

    assert set(result["interaction"]) == {
        "channel", "continuation", "suppress_initial_greeting",
        "entrypoint", "current_application",
    }
    blob = json.dumps(result).lower()
    for smuggled in ("is_admin", "skip_policy", "attacker@example.invalid", "dc01"):
        assert smuggled not in blob, smuggled


def test_d2_entrypoint_and_current_application_pass_through_when_present():
    """The two new presentation fields ride the same trusted path as the rest."""
    result = ensure_identity_context_in_state({
        "persona": PERSONA,
        "interaction_context": {
            **VOICE_CONTINUATION,
            "entrypoint": "employee_access_portal",
            "current_application": "employee_access_portal",
        },
    })

    assert result["interaction"]["entrypoint"] == "employee_access_portal"
    assert result["interaction"]["current_application"] == "employee_access_portal"


def test_d3_non_string_entrypoint_degrades_to_none():
    """Anything that is not a plain string collapses to no context, not junk."""
    for junk in (123, ["employee_access_portal"], {"name": "x"}, "", None, True):
        result = ensure_identity_context_in_state({
            "persona": PERSONA,
            "interaction_context": {**VOICE_CONTINUATION, "entrypoint": junk,
                                     "current_application": junk},
        })
        assert result["interaction"]["entrypoint"] is None
        assert result["interaction"]["current_application"] is None


def test_d4_missing_entrypoint_defaults_to_none_not_a_guess():
    """An ordinary chat session states no entrypoint, and none is invented."""
    result = ensure_identity_context_in_state({"persona": PERSONA})

    assert result["interaction"]["entrypoint"] is None
    assert result["interaction"]["current_application"] is None


def test_e_identity_is_unaffected_by_the_interaction_context():
    """Turning greeting off must not change WHO the agent thinks it is talking to."""
    plain = ensure_identity_context_in_state({"persona": PERSONA})
    voice = ensure_identity_context_in_state({
        "persona": PERSONA, "interaction_context": VOICE_CONTINUATION,
    })

    assert plain["identity"] == voice["identity"]


def test_f_the_recovery_markers_stay_out_of_what_the_model_sees():
    """The persona keeps a scope restriction; the tool does not surface it.

    `recovery_scope` is deliberately retained on the persona — it RESTRICTS the
    identity to the caller's own account, and dropping a restriction because its
    wording is unfashionable is how a rename widens authorization. What matters
    is that it never becomes conversational, and that is asserted here rather
    than assumed from the fact that nothing reads it today.
    """
    result = ensure_identity_context_in_state({
        "persona": PERSONA, "interaction_context": VOICE_CONTINUATION,
    })

    model_visible = json.dumps(result).lower()
    for marker in ("recovery_scope", "self_account_recovery", "account_recovery",
                   "duo_external_voice", "duo_push", "external_voice"):
        if marker == "external_voice":
            # The CHANNEL is legitimately visible: it is what tells the agent
            # this is a continuing spoken conversation.
            continue
        assert marker not in model_visible, marker


def test_g_a_malformed_context_degrades_to_greeting():
    """Anything unreadable means "behave normally", never "suppress"."""
    for junk in (None, "true", 1, [], {"suppress_initial_greeting": "yes-please"}):
        result = ensure_identity_context_in_state({
            "persona": PERSONA, "interaction_context": junk,
        })
        assert isinstance(result["interaction"]["suppress_initial_greeting"], bool)


def test_h_the_agent_instruction_actually_reads_the_flag():
    """The tool and the prompt must agree, or the flag does nothing at all.

    This is the failure mode that produces no error anywhere: the context is
    seeded, returned, and silently ignored, and the caller keeps hearing a
    second greeting.
    """
    from pathlib import Path

    instruction = Path("sd_chat/agent.py").read_text()
    assert "interaction.suppress_initial_greeting" in instruction
    assert "identity_context_tool" in instruction
    # ...and the normal greeting behaviour is still described for chat sessions.
    assert "identity.display_name" in instruction
