import os
import time
import base64
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv
import requests
import re
from google.adk.tools import FunctionTool

load_dotenv()

# --------------------------------------------------------------------
# ServiceNow configuration (all via env)
# --------------------------------------------------------------------
SNOW_INSTANCE_NAME = os.getenv("SNOW_INSTANCE_NAME")
AUTH_MODE = os.getenv("SNOW_AUTH_MODE", "basic").lower()

# Basic auth
SNOW_USER = os.getenv("SNOW_USER")
SNOW_PASSWORD = os.getenv("SNOW_PASSWORD")

# OAuth2 client_credentials
SNOW_CLIENT_ID = os.getenv("SNOW_CLIENT_ID")
SNOW_CLIENT_SECRET = os.getenv("SNOW_CLIENT_SECRET")
SNOW_TOKEN_URL = os.getenv("SNOW_TOKEN_URL", f"https://{SNOW_INSTANCE_NAME}/oauth_token.do")

REQUEST_TIMEOUT = float(os.getenv("SNOW_REQUEST_TIMEOUT", "20"))
RETRIES = int(os.getenv("SNOW_RETRIES", "3"))

INCIDENT_PATTERN = re.compile(r"\bINC\d{7,}\b", re.IGNORECASE)


# ------------------------------------------
# Shared “how to use the tool” instructions
# ------------------------------------------
TOOL_INSTR = """
ServiceNow Incident Toolset (direct REST)

Capabilities:
- Get incident details by sys_id or incident number.
- List/search incidents with a ServiceNow encoded query.
- Create incidents with short_description, description, impact, urgency, etc.
- Update incidents (state, priority, assignment_group, work_notes, etc.).
- Close incidents safely with mandatory Resolution code and Close notes.
- Delete incidents (CRITICAL: only when user explicitly confirms).

When creating incidents:
- Collect short_description and description from the user.
- Deduce impact and urgency from the problem context (1 = high, 3 = low).
- Confirm with the user before actually creating.

When updating:
- Use snow_update_incident for partial updates (adding work notes, changing assignment, priority, etc.).
- Do NOT use snow_update_incident to close tickets. Instead, use snow_close_incident.

When closing:
- Use snow_close_incident when the user explicitly wants to resolve/close an incident.
- Always send clear close_notes. If the user does not specify a close_code, assume a reasonable default.
- Always send clear close_code.

When deleting:
- Ask for sys_id or incident number and confirm the requested deletion explicitly.
- Explain clearly what was updated or deleted in the final answer.
"""

# --------------------------------------------------------------------
# Low-level HTTP helpers
# --------------------------------------------------------------------

_oauth_cache: Dict[str, Any] = {"token": None, "exp": 0.0}


def _get_basic_auth_header() -> Dict[str, str]:
    if not SNOW_USER or not SNOW_PASSWORD:
        raise RuntimeError("SNOW_USER / SNOW_PASSWORD not configured for basic auth.")
    token = base64.b64encode(f"{SNOW_USER}:{SNOW_PASSWORD}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _get_oauth_bearer_header() -> Dict[str, str]:
    """Client Credentials OAuth2 (no browser prompt)."""
    if not SNOW_CLIENT_ID or not SNOW_CLIENT_SECRET:
        raise RuntimeError("SNOW_CLIENT_ID / SNOW_CLIENT_SECRET not configured for OAuth2.")

    now = time.time()
    if _oauth_cache["token"] and now < _oauth_cache["exp"] - 60:
        return {"Authorization": f"Bearer {_oauth_cache['token']}"}

    data = {
        "grant_type": "client_credentials",
        "client_id": SNOW_CLIENT_ID,
        "client_secret": SNOW_CLIENT_SECRET,
    }
    resp = requests.post(SNOW_TOKEN_URL, data=data, timeout=REQUEST_TIMEOUT)
    if resp.status_code >= 400:
        raise RuntimeError(f"ServiceNow OAuth token error: {resp.status_code} {resp.text}")
    tok = resp.json()
    _oauth_cache["token"] = tok["access_token"]
    _oauth_cache["exp"] = now + int(tok.get("expires_in", 1800))
    return {"Authorization": f"Bearer {_oauth_cache['token']}"}


def _snow_headers() -> Dict[str, str]:
    if not SNOW_INSTANCE_NAME:
        raise RuntimeError("SNOW_INSTANCE_NAME is not set (e.g. dev218888.service-now.com).")

    base = {"Accept": "application/json", "Content-Type": "application/json"}
    if AUTH_MODE == "basic":
        base.update(_get_basic_auth_header())
    elif AUTH_MODE == "client_credentials":
        base.update(_get_oauth_bearer_header())
    else:
        raise RuntimeError(f"Unsupported SNOW_AUTH_MODE: {AUTH_MODE}")
    return base


def _snow_request(
    method: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Low-level wrapper around ServiceNow REST with retries and basic error handling."""
    url = f"https://{SNOW_INSTANCE_NAME}{path}"
    last_exc: Optional[Exception] = None

    for attempt in range(1, RETRIES + 1):
        try:
            resp = requests.request(
                method=method.upper(),
                url=url,
                headers=_snow_headers(),
                params=params,
                json=json,
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code < 500:
                # 2xx / 4xx – break retry loop
                break
        except Exception as exc:
            last_exc = exc
            if attempt == RETRIES:
                raise RuntimeError(f"ServiceNow request failed after {RETRIES} attempts: {exc}") from exc
            time.sleep(min(2 ** attempt, 8))
            continue

        if attempt < RETRIES and resp.status_code >= 500:
            time.sleep(min(2 ** attempt, 8))

    if resp.status_code >= 400:
        # Surface SN error body to the agent in a structured way
        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}
        raise RuntimeError(
            f"ServiceNow error {resp.status_code} for {method} {path}: {body}"
        )

    if resp.status_code == 204 or not (resp.text or "").strip():
        return {}

    return resp.json()


# --------------------------------------------------------------------
# Tool functions (these become ADK tools via FunctionTool)
# --------------------------------------------------------------------

def snow_create_incident(
    short_description: str,
    description: str,
    impact: str = "3",
    urgency: str = "3",
    category: Optional[str] = None,
    subcategory: Optional[str] = None,
    assignment_group: str = "Help Desk", ## TODO: Need to introduce a proper assignment group
    caller_id: Optional[str] = None,
    additional_fields_json: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Create a new ServiceNow incident.

    Args:
        short_description: One-line summary of the problem.
        description: Detailed description of the issue.
        impact: Impact code as string ("1","2","3"). 1 = High, 3 = Low.
        urgency: Urgency code as string ("1","2","3"). 1 = High, 3 = Low.
        category: Optional category (e.g., "hardware", "software").
        subcategory: Optional subcategory.
        assignment_group: Optional assignment group name or sys_id.
        caller_id: Optional caller identifier (user id / sys_id).
        additional_fields_json: Extra fields to send to ServiceNow as a JSON object.

    Returns:
        Dict with keys: number, sys_id, and the full result payload.
    """
    payload: Dict[str, Any] = {
        "short_description": short_description,
        "description": description,
        "impact": impact,
        "urgency": urgency,
    }
    if category:
        payload["category"] = category
    if subcategory:
        payload["subcategory"] = subcategory
    if assignment_group:
        payload["assignment_group"] = assignment_group
    if caller_id:
        payload["caller_id"] = caller_id
    if additional_fields_json:
        payload.update(additional_fields_json)

    res = _snow_request("POST", "/api/now/table/incident", json=payload)
    result = res.get("result", {})
    return {
        "number": result.get("number"),
        "sys_id": result.get("sys_id"),
        "result": result,
    }


def snow_get_incident(
    sys_id: Optional[str] = None,
    incident_number: Optional[str] = None,
    fields: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get a single ServiceNow incident by sys_id or incident number.

    Args:
        sys_id: ServiceNow sys_id of the incident.
        incident_number: Incident number (e.g., "INC0012345").
        fields: Optional comma-separated list of fields to return.

    Returns:
        Full incident record as returned by ServiceNow.

    Notes:
        - Prefer sys_id when you have it; it is unique and faster.
        - If both sys_id and incident_number are provided, sys_id wins.
    """
    params: Dict[str, Any] = {}
    if fields:
        params["sysparm_fields"] = fields

    if sys_id:
        res = _snow_request("GET", f"/api/now/table/incident/{sys_id}", params=params)
        return res.get("result", {})

    if incident_number:
        params["sysparm_query"] = f"number={incident_number}"
        params["sysparm_limit"] = "1"
        res = _snow_request("GET", "/api/now/table/incident", params=params)
        items = res.get("result", []) or []
        return items[0] if items else {}

    raise RuntimeError("Either sys_id or incident_number must be provided.")


def snow_list_incidents(
    query: Optional[str] = None,
    limit: int = 20,
    fields: Optional[str] = None,
    page: int = 1,
) -> Dict[str, Any]:
    """
    List or search ServiceNow incidents using an encoded query.

    Args:
        query: ServiceNow encoded query string (e.g., 'state=2^assignment_group=...').
        limit: Max number of items per page (1-100).
        fields: Optional comma-separated list of fields to return.
        page: 1-based page index (used to calculate offset).

    Returns:
        Dict with:
            count: number of items returned
            items: list of incident records
    """
    limit = max(1, min(limit, 100))
    offset = max(page - 1, 0) * limit

    params: Dict[str, Any] = {
        "sysparm_limit": str(limit),
        "sysparm_offset": str(offset),
    }
    if fields:
        params["sysparm_fields"] = fields
    if query:
        params["sysparm_query"] = query

    res = _snow_request("GET", "/api/now/table/incident", params=params)
    items: List[Dict[str, Any]] = res.get("result", []) or []
    return {"count": len(items), "items": items}


def snow_update_incident(
    sys_id: str,
    state: Optional[str] = None,
    priority: Optional[str] = None,
    assignment_group: str = "Help Desk",  ## TODO: Need to introduce a proper assignment group
    work_notes: Optional[str] = None,
    short_description: Optional[str] = None,
    description: Optional[str] = None,
    additional_fields_json: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Update fields on an existing ServiceNow incident (non-closing updates).

    Use this for:
    - Adding work notes / comments
    - Changing assignment group
    - Updating priority, short description, description
    - Minor state transitions that do NOT fully close/resolve the ticket

    Do NOT use this tool to fully resolve/close incidents that require
    Resolution code and Close notes. Use snow_close_incident instead.

    Args:
        sys_id: ServiceNow sys_id of the incident to update.
        state: Optional new state code (non-final).
        priority: Optional new priority.
        assignment_group: Optional assignment group sys_id/name.
        work_notes: Work notes to append.
        short_description: Optional new short description.
        description: Optional new description.
        additional_fields_json: Extra fields to send as JSON.

    Returns:
        Updated incident record (dict).
    """
    payload: Dict[str, Any] = {}

    if state is not None:
        payload["state"] = state
    if priority is not None:
        payload["priority"] = priority
    if assignment_group is not None:
        payload["assignment_group"] = assignment_group
    if work_notes is not None:
        payload["work_notes"] = work_notes
    if short_description is not None:
        payload["short_description"] = short_description
    if description is not None:
        payload["description"] = description

    if additional_fields_json:
        payload.update(additional_fields_json)

    if not payload:
        raise RuntimeError("No fields provided to update.")

    res = _snow_request("PATCH", f"/api/now/table/incident/{sys_id}", json=payload)
    return res.get("result", {})


def snow_close_incident(
    sys_id: Optional[str] = None,
    incident_number: Optional[str] = None,
    close_notes: str = "",
    close_code: str = "",
    state: str = "7",
    work_notes: Optional[str] = None,
    additional_fields_json: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Resolve / close a ServiceNow incident with mandatory Resolution code and Close notes.

    This is the dedicated tool for final closure/resolution, and should be used when
    the user explicitly wants to close or resolve a ticket.

    Behavior:
    - You can provide either sys_id or incident_number (INC...); sys_id is preferred.
    - close_notes is REQUIRED. Use a clear, human-friendly explanation of what was done.
    - close_code is REQUIRED. You must provide a clear resolution code.
    - state defaults to "7" (Closed) but can be overridden if your process uses "6" (Resolved) etc.

    Args:
        sys_id: ServiceNow sys_id of the incident to close.
        incident_number: Incident number (e.g., "INC0012345") if sys_id is not known.
        close_notes: Detailed close notes / resolution details (REQUIRED).
        close_code: Resolution code (REQUIRED).
        state: Final state code, defaults to "7" (Closed).
        work_notes: Optional work notes to add alongside closure.
        additional_fields_json: Extra fields to send as JSON.

    Returns:
        Updated incident record (dict), including number and sys_id where possible.
    """
    if not sys_id and not incident_number:
        raise RuntimeError("Either sys_id or incident_number must be provided to close an incident.")

    if not close_notes or not close_notes.strip():
        raise RuntimeError("close_notes is required when closing an incident.")

    # If only incident_number is provided, resolve it to sys_id
    if not sys_id and incident_number:
        params: Dict[str, Any] = {
            "sysparm_query": f"number={incident_number}",
            "sysparm_limit": "1",
        }
        res_lookup = _snow_request("GET", "/api/now/table/incident", params=params)
        items = res_lookup.get("result", []) or []
        if not items:
            raise RuntimeError(f"No incident found for number={incident_number}")
        sys_id = items[0].get("sys_id")
        if not sys_id:
            raise RuntimeError(f"Incident {incident_number} found but sys_id is missing in response.")

    # At this point sys_id must be set
    assert sys_id is not None

    payload: Dict[str, Any] = {}

    # Final state for closure
    if state:
        payload["state"] = state

    # Close notes are mandatory
    payload["close_notes"] = close_notes

    # Close code: use provided or default
    if not close_code:
        close_code = "Solution provided"  # Default if none provided
    if close_code:
        payload["close_code"] = close_code

    # Optional extra work notes
    if work_notes:
        payload["work_notes"] = work_notes

    if additional_fields_json:
        payload.update(additional_fields_json)

    res = _snow_request("PATCH", f"/api/now/table/incident/{sys_id}", json=payload)
    result = res.get("result", {}) or {}
    return {
        "sys_id": result.get("sys_id", sys_id),
        "number": result.get("number"),
        "close_code": result.get("close_code", close_code),
        "close_notes": result.get("close_notes", close_notes),
        "state": result.get("state", state),
        "result": result,
    }


def snow_add_comment(
    sys_id: str,
    comment: str,
) -> dict:
    """
    Adds a work note / comment to a ServiceNow incident.
    Wraps a minimal PATCH with only work_notes.

    Use this for pure commentary; for broader updates use snow_update_incident.
    """
    payload = {"work_notes": comment}
    res = _snow_request("PATCH", f"/api/now/table/incident/{sys_id}", json=payload)
    return {
        "sys_id": sys_id,
        "comment_added": comment,
        "result": res.get("result", {})
    }


def snow_delete_incident(sys_id: str) -> Dict[str, Any]:
    """
    Delete a ServiceNow incident by sys_id.

    IMPORTANT:
        This is irreversible. Only call after explicit user confirmation.

    Args:
        sys_id: ServiceNow sys_id of the incident.

    Returns:
        Dict with deleted=True and the sys_id.
    """
    _snow_request("DELETE", f"/api/now/table/incident/{sys_id}")
    return {"deleted": True, "sys_id": sys_id}


def snow_find_incident_number(text: str) -> dict:
    """
    Detects an incident number like INC0012345 from user text.
    Returns: {"incident_number": "..."} or {"incident_number": None}
    """
    if not text:
        return {"incident_number": None}

    m = INCIDENT_PATTERN.search(text)
    if not m:
        return {"incident_number": None}

    return {"incident_number": m.group(0).upper()}


# --------------------------------------------------------------------
# ADK tools to register on agent
# --------------------------------------------------------------------

snow_create_incident_tool = FunctionTool(snow_create_incident)
snow_get_incident_tool = FunctionTool(snow_get_incident)
snow_list_incidents_tool = FunctionTool(snow_list_incidents)
snow_update_incident_tool = FunctionTool(snow_update_incident)
snow_close_incident_tool = FunctionTool(snow_close_incident)
snow_add_comment_tool = FunctionTool(snow_add_comment)
snow_delete_incident_tool = FunctionTool(snow_delete_incident)
snow_find_incident_number_tool = FunctionTool(snow_find_incident_number)

# Convenience list to import all at once
snow_incident_tools = [
    snow_create_incident_tool,
    snow_get_incident_tool,
    snow_list_incidents_tool,
    snow_update_incident_tool,
    snow_close_incident_tool,
    snow_add_comment_tool,
    snow_delete_incident_tool,
    snow_find_incident_number_tool,
]
