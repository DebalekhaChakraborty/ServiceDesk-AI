"""Self-service directory profile lookup.

These tests pin the narrow contract: the caller's own record only, resolved from
the trusted session, with no authorization side effect and no fabricated fields.
"""

import inspect
import json
import os
from types import SimpleNamespace

import pytest

os.environ.setdefault("WINRM_PORT", "5986")

from sd_chat.agent import sd_chat
from sd_chat.tools import aad_tool
from sd_chat.tools import directory_profile_tool as profile
from sd_chat.tools.policy_tool import AAD_MANAGER_LOOKUP_STATE_KEY, check_list

CALLER_UPN = "user@example.com"
CALLER_OID = "caller-object-id"
MANAGER_UPN = "manager@example.com"

PROFILE_PAYLOAD = {
    "id": CALLER_OID,
    "displayName": "Example User",
    "userPrincipalName": CALLER_UPN,
    "mail": "user@example.com",
    "otherMails": ["personal@example.net", "old@example.org"],
    "mobilePhone": "+44 7700 900123",
    "businessPhones": ["+44 20 7946 0000"],
    "department": "Platform Engineering",
    "jobTitle": "Staff Engineer",
}

MANAGER_PAYLOAD = {
    "id": "manager-object-id",
    "displayName": "Morgan Manager",
    "userPrincipalName": MANAGER_UPN,
    "mail": MANAGER_UPN,
}


class _Response:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload) if payload is not None else ""

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def _context(upn=CALLER_UPN, object_id=CALLER_OID, persona=True):
    if not persona:
        return SimpleNamespace(state={}, invocation_id="profile-test")
    record = {
        "displayName": "Example User",
        "userPrincipalName": upn,
        "id": object_id,
        "devices": [],
    }
    return SimpleNamespace(
        state={"persona": record, "user:persona": record},
        invocation_id="profile-test",
    )


def _graph(monkeypatch, profile_payload=PROFILE_PAYLOAD, manager_payload=MANAGER_PAYLOAD,
           profile_status=200, manager_status=200):
    """Route the two expected Graph reads and record every call."""
    calls = []

    def fake_get(path, params=None, extra_headers=None):
        calls.append((path, dict(params or {})))
        if path.endswith("/manager"):
            if manager_status != 200:
                return _Response(manager_status)
            return _Response(200, manager_payload)
        if profile_status != 200:
            return _Response(profile_status)
        return _Response(200, profile_payload)

    monkeypatch.setattr(aad_tool, "_graph_is_configured", lambda: True)
    monkeypatch.setattr(aad_tool, "_graph_get", fake_get)
    return calls


# --- A. manager -------------------------------------------------------------


def test_authenticated_self_gets_fresh_graph_profile_and_manager(monkeypatch):
    calls = _graph(monkeypatch)

    result = profile.get_my_directory_profile.func(_context())

    assert result["status"] == "ok"
    assert result["profile"]["manager"] == {
        "display_name": "Morgan Manager",
        "upn": MANAGER_UPN,
    }
    # Two fresh reads: the caller's own record, then their manager.
    assert [path for path, _ in calls] == [
        f"users/{CALLER_OID}",
        f"users/{CALLER_OID}/manager",
    ]


def test_no_manager_assigned_is_reported_as_none_not_an_error(monkeypatch):
    _graph(monkeypatch, manager_status=404)

    result = profile.get_my_directory_profile.func(_context())

    assert result["status"] == "ok"
    assert result["profile"]["manager"] is None


# --- B/C. contact fields ----------------------------------------------------


def test_secondary_emails_come_from_other_mails(monkeypatch):
    _graph(monkeypatch)

    result = profile.get_my_directory_profile.func(_context())

    assert result["profile"]["primary_email"] == "user@example.com"
    assert result["profile"]["secondary_emails"] == [
        "personal@example.net",
        "old@example.org",
    ]


def test_phone_numbers_are_returned_when_graph_has_them(monkeypatch):
    _graph(monkeypatch)

    result = profile.get_my_directory_profile.func(_context())

    assert result["profile"]["mobile_phone"] == "+44 7700 900123"
    assert result["profile"]["business_phones"] == ["+44 20 7946 0000"]


def test_department_and_job_title_are_returned(monkeypatch):
    _graph(monkeypatch)

    result = profile.get_my_directory_profile.func(_context())

    assert result["profile"]["department"] == "Platform Engineering"
    assert result["profile"]["job_title"] == "Staff Engineer"


# --- D. absent data is absent, never invented -------------------------------


def test_missing_fields_are_null_and_never_fabricated(monkeypatch):
    sparse = {
        "id": CALLER_OID,
        "displayName": "Example User",
        "userPrincipalName": CALLER_UPN,
    }
    _graph(monkeypatch, profile_payload=sparse, manager_status=404)

    result = profile.get_my_directory_profile.func(_context())

    assert result["status"] == "ok"
    assert result["profile"]["mobile_phone"] is None
    assert result["profile"]["business_phones"] == []
    assert result["profile"]["secondary_emails"] == []
    assert result["profile"]["primary_email"] is None
    assert result["profile"]["department"] is None
    assert result["profile"]["job_title"] is None
    assert result["profile"]["manager"] is None


def test_blank_graph_values_are_normalized_to_absent(monkeypatch):
    blank = {
        "id": CALLER_OID,
        "displayName": "Example User",
        "userPrincipalName": CALLER_UPN,
        "mobilePhone": "   ",
        "businessPhones": ["", "  "],
        "otherMails": [],
    }
    _graph(monkeypatch, profile_payload=blank, manager_status=404)

    result = profile.get_my_directory_profile.func(_context())

    assert result["profile"]["mobile_phone"] is None
    assert result["profile"]["business_phones"] == []


# --- E. identity required ---------------------------------------------------


def test_no_identity_context_discloses_no_profile(monkeypatch):
    calls = _graph(monkeypatch)
    monkeypatch.delenv("SD_PERSONA", raising=False)
    monkeypatch.setattr(
        "sd_chat.tools.identity_context_tool.get_env_fallback_persona", lambda: None
    )

    result = profile.get_my_directory_profile.func(_context(persona=False))

    assert result["status"] == "error"
    assert result["code"] == "DIRECTORY_PROFILE_IDENTITY_REQUIRED"
    assert "profile" not in result
    assert calls == []


def test_identity_without_object_id_or_upn_fails_closed(monkeypatch):
    calls = _graph(monkeypatch)
    monkeypatch.setattr(
        "sd_chat.tools.identity_context_tool.get_env_fallback_persona", lambda: None
    )
    record = {"displayName": "Nameless", "devices": []}
    context = SimpleNamespace(
        state={"persona": record, "user:persona": record}, invocation_id="t"
    )

    result = profile.get_my_directory_profile.func(context)

    assert result["status"] == "error"
    assert result["code"] == "DIRECTORY_PROFILE_IDENTITY_REQUIRED"
    assert calls == []


# --- F. self only -----------------------------------------------------------


def test_tool_exposes_no_target_parameter_at_all():
    signature = inspect.signature(profile.get_my_directory_profile.func)

    assert list(signature.parameters) == ["tool_context"]
    declaration = profile.get_my_directory_profile._get_declaration()
    properties = (
        (declaration.parameters.properties or {}) if declaration.parameters else {}
    )
    # No target_upn, object_id, email, employee_id, or user name can be supplied.
    assert properties == {}


def test_graph_is_queried_by_trusted_object_id_not_session_upn(monkeypatch):
    calls = _graph(monkeypatch)

    profile.get_my_directory_profile.func(_context())

    # The immutable object id is preferred over the mutable UPN.
    assert calls[0][0] == f"users/{CALLER_OID}"
    assert CALLER_UPN not in calls[0][0]


def test_upn_is_used_only_when_no_object_id_is_available(monkeypatch):
    calls = _graph(monkeypatch)

    result = profile.get_my_directory_profile.func(_context(object_id=None))

    assert result["status"] == "ok"
    # URL-encoded exactly as the existing Account Access manager read does.
    assert calls[0][0] == "users/user%40example.com"


def test_only_allowlisted_fields_are_selected(monkeypatch):
    calls = _graph(monkeypatch)

    profile.get_my_directory_profile.func(_context())

    selected = set(calls[0][1]["$select"].split(","))
    assert selected == {
        "id",
        "displayName",
        "userPrincipalName",
        "mail",
        "otherMails",
        "mobilePhone",
        "businessPhones",
        "department",
        "jobTitle",
    }
    assert set(calls[1][1]["$select"].split(",")) == {
        "id",
        "displayName",
        "userPrincipalName",
        "mail",
    }


def test_result_returns_no_raw_graph_or_directory_metadata(monkeypatch):
    _graph(monkeypatch)

    result = profile.get_my_directory_profile.func(_context())

    assert set(result["profile"]) == {
        "display_name",
        "upn",
        "primary_email",
        "secondary_emails",
        "mobile_phone",
        "business_phones",
        "department",
        "job_title",
        "manager",
    }
    assert set(result["profile"]["manager"]) == {"display_name", "upn"}
    serialized = json.dumps(result)
    assert CALLER_OID not in serialized
    assert "manager-object-id" not in serialized


def test_unrestricted_directory_lookup_is_still_not_exposed_to_the_model():
    tool_names = {getattr(tool, "name", "") for tool in sd_chat.tools}

    assert "get_my_directory_profile" in tool_names
    assert "aad_user_lookup" not in tool_names
    assert "aad_get_manager" not in tool_names


# --- G/H. no authorization side effect --------------------------------------


def test_profile_lookup_creates_no_account_access_authorization(monkeypatch):
    _graph(monkeypatch)
    context = _context()

    result = profile.get_my_directory_profile.func(context)

    assert result["status"] == "ok"
    assert result["profile"]["manager"]["upn"] == MANAGER_UPN
    # The evidence key check_list consults for caller_is_self_or_manager must be
    # untouched by an informational read.
    assert context.state.get(AAD_MANAGER_LOOKUP_STATE_KEY) is None
    assert not any("offer" in str(key).lower() for key in context.state)


def test_knowing_your_manager_does_not_authorize_acting_on_their_account(monkeypatch):
    """The caller learns their manager's name, then tries to act as them."""
    _graph(monkeypatch)
    context = _context()
    profile.get_my_directory_profile.func(context)

    # Caller is the employee; target is someone the caller is NOT the manager of.
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=CALLER_UPN,
        target_upn="colleague@example.com",
        manager_upn=CALLER_UPN,
        tool_context=context,
    )

    assert policy["status"] == "error"
    assert policy["details"]["caller_is_self_or_manager"]["ok"] is False
    assert (
        policy["details"]["caller_is_self_or_manager"]["manager_lookup_verified"]
        is False
    )


def test_manager_flow_still_requires_its_own_fresh_verification(monkeypatch):
    """A manager who read their profile still gets no free pass downstream."""
    _graph(monkeypatch)
    context = _context()
    profile.get_my_directory_profile.func(context)

    # Even naming the real manager relationship, policy refuses without the
    # protected controller's own fresh Graph manager evidence in state.
    policy = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=MANAGER_UPN,
        target_upn=CALLER_UPN,
        manager_upn=MANAGER_UPN,
        tool_context=context,
    )

    assert policy["status"] == "error"

    # The protected controller supplying its own verified lookup is what passes.
    context.state[AAD_MANAGER_LOOKUP_STATE_KEY] = {
        "target_upn": CALLER_UPN,
        "manager_upn": MANAGER_UPN,
        "source": "microsoft_graph",
    }
    authorized = check_list(
        preconditions=["caller_is_self_or_manager"],
        caller_upn=MANAGER_UPN,
        target_upn=CALLER_UPN,
        manager_upn=MANAGER_UPN,
        tool_context=context,
    )

    assert authorized["status"] == "ok"


def test_manager_read_does_not_call_the_authorization_writing_tool(monkeypatch):
    _graph(monkeypatch)
    called = []
    monkeypatch.setattr(
        aad_tool.aad_get_manager,
        "func",
        lambda *args, **kwargs: called.append(True) or {"ok": True, "manager": None},
    )

    profile.get_my_directory_profile.func(_context())

    assert called == []


# --- I. Graph contradiction fails closed ------------------------------------


def test_graph_returning_a_different_object_id_fails_closed(monkeypatch):
    _graph(
        monkeypatch,
        profile_payload={**PROFILE_PAYLOAD, "id": "someone-else-object-id"},
    )

    result = profile.get_my_directory_profile.func(_context())

    assert result["status"] == "error"
    assert result["code"] == "DIRECTORY_PROFILE_IDENTITY_MISMATCH"
    assert "profile" not in result


def test_graph_returning_a_different_upn_fails_closed(monkeypatch):
    _graph(
        monkeypatch,
        profile_payload={**PROFILE_PAYLOAD, "userPrincipalName": "someone@example.com"},
    )

    result = profile.get_my_directory_profile.func(_context())

    assert result["status"] == "error"
    assert result["code"] == "DIRECTORY_PROFILE_IDENTITY_MISMATCH"


def test_mismatch_is_detected_before_any_manager_read(monkeypatch):
    calls = _graph(
        monkeypatch,
        profile_payload={**PROFILE_PAYLOAD, "id": "someone-else-object-id"},
    )

    profile.get_my_directory_profile.func(_context())

    assert not any(path.endswith("/manager") for path, _ in calls)


def test_missing_profile_record_is_reported_not_invented(monkeypatch):
    _graph(monkeypatch, profile_status=404)

    result = profile.get_my_directory_profile.func(_context())

    assert result["status"] == "error"
    assert result["code"] == "DIRECTORY_PROFILE_NOT_FOUND"
    assert "profile" not in result


def test_graph_not_configured_discloses_nothing(monkeypatch):
    monkeypatch.setattr(aad_tool, "_graph_is_configured", lambda: False)

    result = profile.get_my_directory_profile.func(_context())

    assert result["status"] == "error"
    assert result["code"] == "DIRECTORY_PROFILE_GRAPH_NOT_CONFIGURED"


def test_graph_transport_failure_never_leaks_exception_detail(monkeypatch):
    monkeypatch.setattr(aad_tool, "_graph_is_configured", lambda: True)

    def boom(path, params=None, extra_headers=None):
        raise RuntimeError("token=super-secret-value")

    monkeypatch.setattr(aad_tool, "_graph_get", boom)

    result = profile.get_my_directory_profile.func(_context())

    assert result["status"] == "error"
    assert "super-secret-value" not in json.dumps(result)


# --- module hygiene ---------------------------------------------------------


def test_module_performs_no_mutation_and_logs_no_profile_values():
    source = inspect.getsource(profile)

    for forbidden in ("_graph_patch", "requests.post", "requests.patch", "delete("):
        assert forbidden not in source
    # No print/logging of any kind, so profile values cannot reach logs.
    assert "print(" not in source
    assert AAD_MANAGER_LOOKUP_STATE_KEY not in source
    assert "aad_get_manager" in source  # only in the comment explaining the avoidance
    assert "aad_tool.aad_get_manager(" not in source


def test_agent_instruction_routes_self_profile_questions():
    instruction = sd_chat.instruction

    assert "get_my_directory_profile() with NO arguments" in instruction
    assert "claim you have no way to look this up" in instruction
    assert "authorizes NOTHING" in instruction
    assert "I don't see a mobile number registered in your directory" in instruction
    assert "It takes no target parameter at all" in instruction
