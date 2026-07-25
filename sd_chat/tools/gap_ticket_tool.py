"""
Simple gap ticket tool (LLM-assisted summary).

This tool DOES NOT call ServiceNow directly. This tool NO LONGER produces Application Integration payloads. (direct ServiceNow REST version)
It prepares a concise human-readable description from the context and error details
and returns a payload for the LLM to send via `snow_connector_tool`.

Inputs:
- short_description: concise subject for the incident
- user_request: the original user text
- context_json: JSON string with any useful fields (e.g., {"target_host":"10.128.0.3", "ticket_id":"INC..."} )
- Optional flat failure_* fields to avoid nested JSON:
    failure_tool, failure_code, failure_stderr, failure_stdout

Instead, it returns a clean argument object for snow_create_incident_tool:
{
    "short_description": "...",
    "description": "...",
    "impact": "3",
    "urgency": "3",
    "category": "Automation",
    "subcategory": "AI Gap",
    "assignment_group": "...",
    "caller_id": "..."
}

The orchestrator should immediately call snow_create_incident_tool(**fields).
"""

import os
import json
from typing import Optional, Dict, Any

# ---- LLM optional imports ---------------------------------------------------
USE_VERTEX = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "false").lower() in ("1", "true", "yes")
GENAI_MODEL = os.getenv("PLANNER_LLM_MODEL", "gemini-2.5-flash")

_GENAI_OK = False
try:
    if USE_VERTEX:
        from vertexai.preview.generative_models import GenerativeModel
        _GENAI_OK = True
    else:
        import google.generativeai as genai # type: ignore
        if os.getenv("GOOGLE_API_KEY"):
            genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
            _GENAI_OK = True
except Exception:
    _GENAI_OK = False


def _llm_summarize(user_request: str, ctx: Dict[str, Any], failure: Dict[str, Any]) -> Optional[str]:
    if not _GENAI_OK:
        return None

    prompt = (
        "Write a concise, professional incident description for a Service Desk ticket.\n"
        "Describe: what the user asked, the target host, what failed, and why.\n"
        "Do NOT mention internal tools, Snow connector, or automation internals.\n\n"
        f"User request:\n{user_request}\n\n"
        f"Context:\n{json.dumps(ctx, indent=2)}\n\n"
        f"Failure details:\n{json.dumps(failure, indent=2)}\n\n"
        "Output only the final description text."
    )

    try:
        if USE_VERTEX:
            resp = GenerativeModel(GENAI_MODEL).generate_content(
                prompt,
                generation_config={"temperature": 0.2, "max_output_tokens": 512},
            )
            return (getattr(resp, "text", "") or "").strip() or None
        else:
            out = genai.GenerativeModel(GENAI_MODEL).generate_content(prompt)  # type: ignore
            return (getattr(out, "text", "") or "").strip() or None
    except Exception:
        return None


def _fallback_description(user_request: str, ctx: Dict[str, Any], failure: Dict[str, Any]) -> str:
    host = ctx.get("target_host") or "N/A"
    fail_tool = failure.get("tool") or "unknown"
    fail_code = failure.get("code") or "N/A"
    fail_stderr = (failure.get("stderr") or "").strip()

    return (
        "Automation failed during execution.\n\n"
        f"User request: {user_request}\n"
        f"Target: {host}\n\n"
        "What happened:\n"
        f"- Action attempted: {fail_tool}\n"
        f"- Result code: {fail_code}\n"
        f"- Error: {fail_stderr or 'None'}\n\n"
        "Next steps:\n"
        "- Please investigate the host, credentials, or connectivity."
    )


# ---------------------------------------------------------------------------

def create_gap_incident(
    short_description: str,
    user_request: str,
    context_json: str,
    category: str = "Automation",
    subcategory: str = "AI Gap",
    impact: str = "3",
    urgency: str = "3",
    # assignment_group: Optional[str] = None,
    assignment_group: str = "Help Desk", ## TODO: Need to introduce a proper assignment group for gaps
    caller_id: Optional[str] = None,

    # flat failure fields
    failure_tool: Optional[str] = None,
    failure_code: Optional[str] = None,
    failure_stderr: Optional[str] = None,
    failure_stdout: Optional[str] = None,
):
    """
    Produces a clean payload for snow_create_incident_tool(**fields).
    """

    try:
        ctx = json.loads(context_json) if context_json else {}
        if not isinstance(ctx, dict):
            ctx = {}
    except Exception:
        ctx = {}

    failure = {}
    if failure_tool is not None: failure["tool"] = failure_tool
    if failure_code is not None: failure["code"] = failure_code
    if failure_stderr is not None: failure["stderr"] = failure_stderr
    if failure_stdout is not None: failure["stdout"] = failure_stdout

    description = _llm_summarize(user_request, ctx, failure) \
                  or _fallback_description(user_request, ctx, failure)

    # ---- RETURN ARGUMENTS for snow_create_incident_tool ----
    fields = {
        "short_description": short_description,
        "description": description,
        "category": category,
        "subcategory": subcategory,
        "impact": impact,
        "urgency": urgency,
        "assignment_group": assignment_group,
        "caller_id": caller_id,
    }

    return {
        "status": "ok",
        "message": "Prepared arguments for snow_create_incident_tool.",
        "create_args": fields,
    }
