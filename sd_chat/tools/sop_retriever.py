"""
SOP Retriever: RAG + LLM steps extractor

Goal:
- Given a user query, fetch the most relevant SOP/KB from Vertex RAG.
- Use LLM to extract MINIMAL ordered procedural steps as short labels.
- Return those steps as `snippets` for propose_plan.

No use-case keywords. Pure semantic retrieval + LLM distillation.
"""

import os
import json
from typing import Dict, List, Any, Optional

from google.adk.tools.tool_context import ToolContext  # type: ignore

from vertexai.preview.generative_models import GenerativeModel  # type: ignore
import vertexai  # type: ignore

__all__ = ["sop_retriever"]

DEFAULT_CORPUS = os.getenv("RAG_CORPUS", "Service_Desk")

# ------------------------------------------------------------------------------
# LLM Vertex Support
# ------------------------------------------------------------------------------
GENAI_AVAILABLE = True
GENAI_MODEL = os.getenv("PLANNER_LLM_MODEL", "gemini-2.5-flash")

# Underlying RAG tool
try:
    from .vertex_rag_tool import vertex_rag_tool  # type: ignore
    _HAS_RAG = True
except Exception:
    vertex_rag_tool = None  # type: ignore
    _HAS_RAG = False


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def _safe_json_extract(s: str) -> Any:
    """Extract JSON object from possibly noisy model response."""
    s = (s or "").strip()
    if not s:
        return {}
    try:
        return json.loads(s)
    except Exception:
        pass

    import re
    m = re.search(r"\{.*\}", s, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            return {}
    return {}


def _llm_extract_steps(user_query: str, sop_markdown: str) -> List[str]:
    """
    Ask the LLM to extract minimal ordered steps as short imperative labels.

    Returns: list of strings like:
      ["Stop the Windows Time Service",
       "Force resynchronize the Windows Time Service",
       "Start the Windows Time Service"]
    """
    if not (GENAI_AVAILABLE and sop_markdown):
        return []

    prompt = (
        "You are an IT operations assistant. You are given:\n"
        f"- A user request: {user_query!r}\n"
        "- A knowledge article in markdown describing how to fix the problem.\n\n"
        "From the article, extract the MINIMAL ordered procedural steps needed to resolve "
        "the issue. Each step should be a short imperative sentence, e.g. "
        "'Stop the Windows Time Service', 'Force resynchronize the Windows Time Service', "
        "'Start the Windows Time Service'.\n\n"
        "RULES:\n"
        "- Do NOT mention JSON, code, or internal implementation.\n"
        "- Only include steps that are part of the remediation procedure.\n"
        "- 3–6 steps is typical; fewer is OK if appropriate.\n"
        "- Output ONLY JSON: {\"steps\": [\"step 1\", \"step 2\", ...]}\n\n"
        "Knowledge article:\n"
        "-----------------\n"
        f"{sop_markdown}\n"
    )

    try:
        # VERTEX-ONLY PATH
        model = GenerativeModel(GENAI_MODEL)  # type: ignore
        resp = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.2,
                "max_output_tokens": 512,
                "response_mime_type": "application/json",
            },
        )
        raw = getattr(resp, "text", "") or ""

        data = _safe_json_extract(raw)
        steps = data.get("steps") if isinstance(data, dict) else None
        if isinstance(steps, list):
            cleaned = [str(s).strip() for s in steps if str(s).strip()]
            return cleaned
        return []
    except Exception:
        return []


# ------------------------------------------------------------------------------
# Main tool
# ------------------------------------------------------------------------------
def sop_retriever(
    query: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """
    SOP retriever for planner:

    - Call Vertex RAG on the given query.
    - Take the best-matching SOP markdown.
    - Use LLM to distill it into a list of short procedural steps.
    - Return those steps as `snippets`.

    The planner (`propose_plan`) will treat `sop_texts` as final step labels.
    """

    if not query or not query.strip():
        return {"status": "error", "error": "empty_query", "snippets": []}

    if not _HAS_RAG or vertex_rag_tool is None:
        return {"status": "error", "error": "rag_tool_missing", "snippets": []}

    if tool_context is None:
        return {"status": "error", "error": "missing_tool_context", "snippets": []}

    # 1) Call RAG exactly like your working test
    try:
        rag_resp = vertex_rag_tool(DEFAULT_CORPUS, query, tool_context)
    except Exception as e:
        return {
            "status": "error",
            "error": "rag_exception",
            "detail": str(e),
            "snippets": [],
        }

    if rag_resp.get("status") == "error":
        return {
            "status": "error",
            "error": "rag_failure",
            "detail": rag_resp.get("message", ""),
            "snippets": [],
        }

    results = rag_resp.get("results", []) or []
    if not results:
        # No SOPs found – not a hard failure, just no extra guidance
        return {
            "status": "ok",
            "snippets": [],
            "meta": {
                "corpus": DEFAULT_CORPUS,
                "results_count": 0,
                "llm_used": False,
            },
        }

    # 2) For now, take the first/best SOP text (your current RAG already returns the correct one)
    top = results[0]
    sop_text = (top.get("text") or "").strip()

    if not sop_text:
        return {
            "status": "ok",
            "snippets": [],
            "meta": {
                "corpus": DEFAULT_CORPUS,
                "results_count": len(results),
                "llm_used": False,
            },
        }

    # 3) LLM: extract steps from the SOP
    steps = _llm_extract_steps(query, sop_text)

    # Fallback: if LLM fails, at least give one generic step
    if not steps:
        steps = ["LLM couldn’t extract procedural steps from the SOP, Please retry."]

    return {
        "status": "ok",
        "snippets": steps,
        "meta": {
            "corpus": DEFAULT_CORPUS,
            "results_count": len(results),
            "llm_used": GENAI_AVAILABLE,
        },
    }
