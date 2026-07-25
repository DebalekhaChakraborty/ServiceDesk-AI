import os
from typing import Any, Dict, Optional, Tuple

from google.adk.tools import FunctionTool, ToolContext

# Vertex AI (Gemini) multimodal
try:
    import vertexai  # type: ignore
    from vertexai.preview.generative_models import GenerativeModel, Part  # type: ignore
except Exception:
    vertexai = None
    GenerativeModel = None
    Part = None


DEFAULT_VISION_MODEL = os.getenv("VISION_LLM_MODEL", "gemini-2.5-flash")
VERTEX_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("VERTEX_PROJECT")
VERTEX_LOCATION = os.getenv("VERTEX_LOCATION", "us-central1")


def _guess_mime(path: str) -> str:
    p = (path or "").lower()
    if p.endswith(".png"):
        return "image/png"
    if p.endswith(".jpg") or p.endswith(".jpeg"):
        return "image/jpeg"
    if p.endswith(".webp"):
        return "image/webp"
    return "application/octet-stream"


def _resolve_uploaded_file_path(state: Dict[str, Any]) -> Optional[str]:
    """
    Best-effort: find the most recent uploaded file path from common keys.

    Supports patterns like:
      state["last_upload"]["filePath"]
      state["uploaded_file"]["filePath"]
      state["attachments"][-1]["filePath"]
      state["attachment"]["filePath"]
    """
    # 1) direct keys
    for key in ("last_upload", "uploaded_file", "attachment"):
        obj = state.get(key)
        if isinstance(obj, dict):
            fp = obj.get("filePath") or obj.get("path") or obj.get("file_path")
            if isinstance(fp, str) and fp.strip():
                return fp.strip()

    # 2) list of attachments
    attachments = state.get("attachments")
    if isinstance(attachments, list) and attachments:
        last = attachments[-1]
        if isinstance(last, dict):
            fp = last.get("filePath") or last.get("path") or last.get("file_path")
            if isinstance(fp, str) and fp.strip():
                return fp.strip()

    return None


def _read_image_bytes(path: str) -> Tuple[bool, str, bytes]:
    if not path:
        return False, "No file path provided.", b""
    if not os.path.isfile(path):
        return False, f"File not found on server: {path}", b""
    try:
        with open(path, "rb") as f:
            return True, "ok", f.read()
    except Exception as e:
        return False, f"Failed to read image: {e}", b""


def analyze_screenshot_impl(
    tool_context: ToolContext,
    file_path: str = "",
    user_hint: str = "",
) -> Dict[str, Any]:
    """
    Analyze an uploaded screenshot (image) to extract text + interpret the issue.
    This uses Gemini multimodal (Vertex AI).

    Inputs:
      - file_path: absolute path on backend (preferred). If empty, tool will try
        to find the latest uploaded file path from tool_context.state.
      - user_hint: optional short hint ("time sync", "dns error", etc.)

    Returns:
      {
        "status": "ok" | "error",
        "file_path": "...",
        "extracted_text": "...",
        "issue_summary": "...",
        "issue_label": "time_sync" | "dns" | "service" | "disk_cleanup" | "windows_update" | "unknown",
        "confidence": 0.0-1.0,
        "error": "...optional..."
      }
    """
    state: Dict[str, Any] = tool_context.state or {}
    if tool_context.state is None:
        tool_context.state = state

    resolved_path = file_path.strip() if isinstance(file_path, str) else ""
    if not resolved_path:
        resolved_path = _resolve_uploaded_file_path(state) or ""

    ok, msg, img_bytes = _read_image_bytes(resolved_path)
    if not ok:
        return {
            "status": "error",
            "file_path": resolved_path,
            "extracted_text": "",
            "issue_summary": "",
            "issue_label": "unknown",
            "confidence": 0.0,
            "error": msg,
        }

    if vertexai is None or GenerativeModel is None or Part is None:
        return {
            "status": "error",
            "file_path": resolved_path,
            "extracted_text": "",
            "issue_summary": "",
            "issue_label": "unknown",
            "confidence": 0.0,
            "error": "Vertex AI SDK not available in runtime (vertexai import failed).",
        }

    if not VERTEX_PROJECT:
        return {
            "status": "error",
            "file_path": resolved_path,
            "extracted_text": "",
            "issue_summary": "",
            "issue_label": "unknown",
            "confidence": 0.0,
            "error": "Missing GOOGLE_CLOUD_PROJECT (or VERTEX_PROJECT) env var for Vertex AI.",
        }

    try:
        vertexai.init(project=VERTEX_PROJECT, location=VERTEX_LOCATION)
        model = GenerativeModel(DEFAULT_VISION_MODEL)

        mime = _guess_mime(resolved_path)
        image_part = Part.from_data(data=img_bytes, mime_type=mime)

        prompt = f"""
You are an IT service desk assistant analyzing a screenshot from a user.

Tasks:
1) Extract ALL visible text from the screenshot (best-effort).
2) Summarize the user's issue in 1-2 sentences.
3) Classify the issue into ONE label from this fixed list:
   - time_sync
   - dns
   - service
   - disk_cleanup
   - windows_update
   - unknown
4) Provide a confidence score between 0 and 1 for your classification.

Return STRICT JSON only with keys:
{{
  "extracted_text": "...",
  "issue_summary": "...",
  "issue_label": "...",
  "confidence": 0.0
}}

User hint (may be empty): {user_hint}
        """.strip()

        resp = model.generate_content([prompt, image_part])
        text = (getattr(resp, "text", None) or "").strip()

        # We expect JSON. If it isn't JSON, return it but mark unknown.
        # (Keeps tool resilient.)
        import json
        try:
            data = json.loads(text)
        except Exception:
            return {
                "status": "ok",
                "file_path": resolved_path,
                "extracted_text": text,
                "issue_summary": "",
                "issue_label": "unknown",
                "confidence": 0.2,
                "error": "Model did not return strict JSON; returned raw text instead.",
            }

        extracted_text = str(data.get("extracted_text") or "").strip()
        issue_summary = str(data.get("issue_summary") or "").strip()
        issue_label = str(data.get("issue_label") or "unknown").strip()
        try:
            confidence = float(data.get("confidence") or 0.0)
        except Exception:
            confidence = 0.0

        result = {
            "status": "ok",
            "file_path": resolved_path,
            "extracted_text": extracted_text,
            "issue_summary": issue_summary,
            "issue_label": issue_label,
            "confidence": max(0.0, min(1.0, confidence)),
        }

        # Store last analysis in state for reuse
        state["last_screenshot_analysis"] = result
        return result

    except Exception as e:
        return {
            "status": "error",
            "file_path": resolved_path,
            "extracted_text": "",
            "issue_summary": "",
            "issue_label": "unknown",
            "confidence": 0.0,
            "error": f"Screenshot analysis failed: {e}",
        }


screenshot_tool = FunctionTool(func=analyze_screenshot_impl)
