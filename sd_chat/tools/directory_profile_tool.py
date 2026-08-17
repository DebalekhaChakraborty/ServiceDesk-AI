"""Read-only self-service directory profile lookup.

The Service Desk can already enforce manager-controlled remediation, because the
protected Account Access controller reads the manager relationship from Microsoft
Graph as part of authorization.  It could not, however, answer a plain
informational question such as "who is my manager?" - the identity context is
seeded from the session persona rather than a live directory read, and the raw
Graph tools are deliberately not exposed to the model.

This module closes exactly that gap and nothing wider.  It exposes one tool that

* takes no target argument of any kind, so the model cannot aim it at anyone;
* resolves the subject solely from the authenticated session's trusted identity;
* selects a fixed allowlist of profile fields;
* returns a normalized shape, never raw Graph JSON; and
* records no authorization evidence whatsoever.

That last point is the important one.  ``aad_tool.aad_get_manager`` writes
``AAD_MANAGER_LOOKUP_STATE_KEY``, which is precisely the artifact
``policy_tool.check_list`` consumes to satisfy ``caller_is_self_or_manager``.
Reusing that tool here would mean an informational question quietly minted
manager-authorization evidence.  So this module reuses the shared, safe Graph
transport (``aad_tool._graph_get``) - keeping one Graph access path and one
authoritative manager source, live Graph - while never touching that state key.
Telling a caller "your manager is X" grants no remediation authority; the
protected Account Access flows continue to perform their own fresh verification.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from google.adk.tools import FunctionTool, ToolContext

from . import aad_tool
from .identity_context_tool import ensure_identity_context_in_state

# Exactly the fields needed to answer self-profile questions. Group membership,
# tenant metadata, sign-in activity, licences, and directory extensions are all
# deliberately absent.
_PROFILE_SELECT = (
    "id,displayName,userPrincipalName,mail,otherMails,"
    "mobilePhone,businessPhones,department,jobTitle"
)

# The manager is shown by name only. Reading more would not help the caller and
# would widen what one informational question discloses about a third party.
_MANAGER_SELECT = "id,displayName,userPrincipalName,mail"


def _error(code: str, message: str) -> Dict[str, Any]:
    return {"status": "error", "code": code, "message": message}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _clean_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clean_list(value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    cleaned = []
    for item in value:
        text = _clean_str(item)
        if text:
            cleaned.append(text)
    return cleaned


def _trusted_subject(
    tool_context: ToolContext,
) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
    """Resolve who this lookup is about, from the session only.

    Nothing the model or the caller says can influence this. For an external
    voice caller that means no profile disclosure before Duo and Graph have both
    passed, because until then the session carries no trusted identity.
    """
    state = tool_context.state
    if state is None:
        state = {}
        tool_context.state = state

    result = ensure_identity_context_in_state(state)
    if not result.get("ok"):
        return None, _error(
            "DIRECTORY_PROFILE_IDENTITY_REQUIRED",
            "I can only look up your directory profile once your identity is verified.",
        )
    identity = result.get("identity")
    if not isinstance(identity, dict):
        return None, _error(
            "DIRECTORY_PROFILE_IDENTITY_REQUIRED",
            "I can only look up your directory profile once your identity is verified.",
        )

    object_id = _clean_str(identity.get("aad_object_id"))
    upn = _norm(identity.get("upn"))
    if not object_id and not upn:
        return None, _error(
            "DIRECTORY_PROFILE_IDENTITY_REQUIRED",
            "I can only look up your directory profile once your identity is verified.",
        )
    # The object id is immutable and unambiguous, so prefer it. The UPN is a
    # bounded fallback for sessions that never carried one.
    return {
        "object_id": object_id or "",
        "upn": upn,
        "graph_key": object_id or upn,
    }, None


def _graph_json(
    path: str,
    select: str,
    failure_code: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[int], Optional[Dict[str, Any]]]:
    """GET one Graph resource and return (payload, status_code, error)."""
    try:
        response = aad_tool._graph_get(path, params={"$select": select})
    except Exception:
        # The exception text can carry token or request detail, so it is not
        # surfaced and not logged.
        return None, None, _error(
            failure_code,
            "I couldn't reach the directory to read your profile just now.",
        )
    status = response.status_code
    if status == 404:
        return None, status, None
    if status != 200:
        return None, status, _error(
            failure_code,
            "I couldn't read your directory profile just now.",
        )
    try:
        payload = response.json()
    except Exception:
        return None, status, _error(
            failure_code,
            "The directory returned an unreadable profile response.",
        )
    if not isinstance(payload, dict):
        return None, status, _error(
            failure_code,
            "The directory returned an unreadable profile response.",
        )
    return payload, status, None


def _read_own_manager(graph_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Read the caller's own manager for display only.

    Intentionally does not call ``aad_tool.aad_get_manager``: that tool records
    manager-verification evidence for the policy engine, and an informational
    lookup must never produce it.
    """
    payload, _status, error = _graph_json(
        f"users/{quote(graph_id, safe='')}/manager",
        _MANAGER_SELECT,
        "DIRECTORY_PROFILE_MANAGER_LOOKUP_FAILED",
    )
    if error is not None:
        return None, error
    if payload is None:
        # Graph answers 404 when the user simply has no manager assigned. That
        # is an ordinary, truthful answer rather than a failure.
        return None, None
    display_name = _clean_str(payload.get("displayName"))
    upn = _clean_str(payload.get("userPrincipalName")) or _clean_str(payload.get("mail"))
    if not display_name and not upn:
        return None, None
    return {"display_name": display_name, "upn": upn}, None


def get_my_directory_profile(tool_context: ToolContext) -> Dict[str, Any]:
    """Look up the authenticated caller's own directory profile and manager.

    Answers self-service informational questions such as who their manager is,
    what secondary email or phone number the directory holds for them, and their
    department or job title. It reads only the caller's own record: it accepts no
    target argument, so it can never be aimed at another person.
    """
    subject, subject_error = _trusted_subject(tool_context)
    if subject_error is not None or subject is None:
        return subject_error or _error(
            "DIRECTORY_PROFILE_IDENTITY_REQUIRED",
            "I can only look up your directory profile once your identity is verified.",
        )

    if not aad_tool._graph_is_configured():
        return _error(
            "DIRECTORY_PROFILE_GRAPH_NOT_CONFIGURED",
            "The directory connection isn't configured, so I can't read your profile.",
        )

    payload, status, error = _graph_json(
        f"users/{quote(subject['graph_key'], safe='')}",
        _PROFILE_SELECT,
        "DIRECTORY_PROFILE_LOOKUP_FAILED",
    )
    if error is not None:
        return error
    if payload is None or status == 404:
        return _error(
            "DIRECTORY_PROFILE_NOT_FOUND",
            "I couldn't find a directory profile for your account.",
        )

    # Corroborate that Graph answered about the trusted identity and not someone
    # else. A disagreement means the session identity and the directory record
    # have diverged, so disclose nothing.
    returned_id = _clean_str(payload.get("id")) or ""
    returned_upn = _norm(payload.get("userPrincipalName"))
    if subject["object_id"] and returned_id != subject["object_id"]:
        return _error(
            "DIRECTORY_PROFILE_IDENTITY_MISMATCH",
            "I couldn't safely confirm that directory record belongs to you, so I didn't read it.",
        )
    if subject["upn"] and returned_upn and returned_upn != subject["upn"]:
        return _error(
            "DIRECTORY_PROFILE_IDENTITY_MISMATCH",
            "I couldn't safely confirm that directory record belongs to you, so I didn't read it.",
        )
    if not subject["object_id"] and not returned_upn:
        return _error(
            "DIRECTORY_PROFILE_IDENTITY_MISMATCH",
            "I couldn't safely confirm that directory record belongs to you, so I didn't read it.",
        )

    manager, manager_error = _read_own_manager(returned_id or subject["graph_key"])
    if manager_error is not None:
        return manager_error

    profile = {
        "display_name": _clean_str(payload.get("displayName")),
        "upn": _clean_str(payload.get("userPrincipalName")),
        # Same selection semantics as the existing password-reset path: `mail`
        # is the primary address and `otherMails` are the secondary ones. No
        # otherMails entry is promoted to mean anything beyond what Graph says.
        "primary_email": _clean_str(payload.get("mail")),
        "secondary_emails": _clean_list(payload.get("otherMails")),
        "mobile_phone": _clean_str(payload.get("mobilePhone")),
        "business_phones": _clean_list(payload.get("businessPhones")),
        "department": _clean_str(payload.get("department")),
        "job_title": _clean_str(payload.get("jobTitle")),
        "manager": manager,
    }
    return {"status": "ok", "profile": profile}


get_my_directory_profile = FunctionTool(func=get_my_directory_profile)

directory_profile_tools = [get_my_directory_profile]
