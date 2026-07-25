import os
import json
import re
from typing import Any, Dict, Optional

import vertexai  # type: ignore
from vertexai.preview.generative_models import GenerativeModel  # type: ignore

from google.adk.tools import FunctionTool, ToolContext
from ..config import PROJECT_ID, LOCATION

LANG_MODEL = os.getenv("LANGUAGE_LLM_MODEL", "gemini-2.5-flash")


def _init_vertex() -> Optional[str]:
    if not PROJECT_ID or not LOCATION:
        return "Missing GOOGLE_CLOUD_PROJECT / GOOGLE_CLOUD_LOCATION env vars."
    try:
        vertexai.init(project=PROJECT_ID, location=LOCATION)
        return None
    except Exception as e:
        return f"Vertex init failed: {e}"


def _parse_json_best_effort(raw: str) -> Dict[str, Any]:
    """
    Gemini sometimes wraps JSON in ```json ... ``` or adds extra text.
    This helper tries to extract and parse the first JSON object.
    """
    s = (raw or "").strip()

    # Strip markdown code fences if present
    # e.g. ```json {...} ```
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()

    # If still not pure JSON, try to extract first {...}
    if not s.startswith("{"):
        m = re.search(r"\{.*\}", s, flags=re.DOTALL)
        if m:
            s = m.group(0).strip()

    return json.loads(s)


def detect_and_translate_in_impl(
    tool_context: ToolContext,
    text: str,
    preferred_language: str = "",
) -> Dict[str, Any]:
    """
    Detect language of user input and translate to English for internal processing.

    Args:
      text: user message in any language
      preferred_language: optional override (e.g., "bn", "hi", "es", "en")

    Returns:
      {
        "status": "ok" | "error",
        "detected_language": "bn" | "hi" | "en" | ...,
        "confidence": 0.0-1.0,
        "text_en": "<english translation>",
        "use_language": "<preferred_or_detected>"
      }
    """
    state: Dict[str, Any] = tool_context.state or {}
    if tool_context.state is None:
        tool_context.state = state

    err = _init_vertex()
    if err:
        return {
            "status": "error",
            "error": err,
            "text_en": text,
            "detected_language": "unknown",
            "confidence": 0.0,
            "use_language": "en",
        }

    model = GenerativeModel(LANG_MODEL)

    # If caller already has a preference in state, respect it
    pref = (preferred_language or state.get("preferred_language") or "").strip().lower()

    prompt = f"""
You are a language utility for an IT service desk agent.

Task:
1) Detect the language of the input text (ISO 639-1 where possible, e.g., en, hi, bn, es).
2) If the text is not English, translate it to English.
3) If it is already English, return it as-is.
4) Return strict JSON only (no markdown, no code fences).

Preferred language (may be empty): "{pref}"

Return JSON:
{{
  "detected_language": "<code>",
  "confidence": 0.0,
  "text_en": "<english version>",
  "use_language": "<preferred_or_detected>"
}}

Input text:
{text}
""".strip()

    try:
        resp = model.generate_content(prompt)
        raw = (resp.text or "").strip()
        data = _parse_json_best_effort(raw)

        detected = str(data.get("detected_language") or "unknown").strip().lower()

        # Use preference if provided; otherwise use model's use_language; otherwise fallback to detected
        use_lang = str(data.get("use_language") or "").strip().lower()
        if pref:
            use_lang = pref
        elif not use_lang:
            use_lang = detected if detected else "en"

        try:
            conf = float(data.get("confidence") or 0.0)
        except Exception:
            conf = 0.0

        text_en = str(data.get("text_en") or text).strip()

        # Persist preference:
        # - If user has a pref and it's not English, store it.
        # - Else if detected is non-English, store detected (even if model mistakenly returned "en").
        if pref and pref != "en":
            state["preferred_language"] = pref
        elif detected and detected != "en" and detected != "unknown":
            state["preferred_language"] = detected

        return {
            "status": "ok",
            "detected_language": detected,
            "confidence": max(0.0, min(1.0, conf)),
            "text_en": text_en,
            "use_language": use_lang or "en",
        }

    except Exception as e:
        # Fail open: keep English pipeline running using original text
        # But if we already have a preference in state, keep it.
        fallback_lang = (pref or state.get("preferred_language") or "en")
        return {
            "status": "error",
            "error": f"Language detect/translate failed: {e}",
            "detected_language": "unknown",
            "confidence": 0.0,
            "text_en": text,
            "use_language": str(fallback_lang).strip().lower(),
        }


def translate_out_impl(
    tool_context: ToolContext,
    text_en: str,
    target_language: str = "",
) -> Dict[str, Any]:
    """
    Translate an English response back to the user's preferred language.
    If target_language is empty, uses tool_context.state['preferred_language'].
    """
    state: Dict[str, Any] = tool_context.state or {}
    if tool_context.state is None:
        tool_context.state = state

    err = _init_vertex()
    if err:
        return {
            "status": "error",
            "error": err,
            "text_out": text_en,
            "target_language": "en",
        }

    lang = (target_language or state.get("preferred_language") or "en").strip().lower()
    if not lang or lang == "en":
        return {"status": "ok", "text_out": text_en, "target_language": "en"}

    model = GenerativeModel(LANG_MODEL)

    prompt = f"""
Translate the following IT service desk response from English to "{lang}".
Keep technical terms (service names, commands, error codes, hostnames) unchanged.
Return STRICT JSON only (no markdown, no code fences):

{{
  "text_out": "<translated text>"
}}

Text:
{text_en}
""".strip()

    try:
        resp = model.generate_content(prompt)
        raw = (resp.text or "").strip()
        data = _parse_json_best_effort(raw)
        out = str(data.get("text_out") or text_en).strip()
        return {"status": "ok", "text_out": out, "target_language": lang}
    except Exception as e:
        return {
            "status": "error",
            "error": f"Translate-out failed: {e}",
            "text_out": text_en,
            "target_language": lang,
        }


detect_and_translate_in = FunctionTool(func=detect_and_translate_in_impl)
translate_out = FunctionTool(func=translate_out_impl)

language_tools = [
    detect_and_translate_in,
    translate_out,
]
