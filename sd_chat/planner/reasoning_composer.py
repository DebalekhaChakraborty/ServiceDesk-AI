import os
import re
import json
import glob
import difflib
from typing import List, Dict, Any, Tuple, Optional
from vertexai.preview.generative_models import GenerativeModel  # type: ignore
import vertexai  # type: ignore

# --------------------------------------------------------------------------------------
# LLM Vertex Support
# --------------------------------------------------------------------------------------
GENAI_AVAILABLE = True
GENAI_MODEL = os.getenv("PLANNER_LLM_MODEL", "gemini-2.5-flash")
PLAN_CONF_THRESHOLD = 0.4

# --------------------------------------------------------------------------------------
# Registry root (override with env ACTION_REGISTRY_DIR if needed)
# --------------------------------------------------------------------------------------
REG_DIR = os.getenv(
    "ACTION_REGISTRY_DIR",
    os.path.join(os.path.dirname(__file__), "..", "action_registry"),
)

# ======================================================================================
# Registry loader
# ======================================================================================
def _load_registry() -> List[Dict[str, Any]]:
    """
    Load all atomic action definitions from the registry directory.
    Expected fields:
      - id, title, description, inputs, preconditions, effects, tool, action, args_template
    """
    actions: List[Dict[str, Any]] = []
    for path in glob.glob(os.path.join(REG_DIR, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
                if not isinstance(obj, dict):
                    continue
                if not obj.get("id") or not obj.get("tool") or not obj.get("action"):
                    continue
                actions.append(obj)
        except Exception:
            # Ignore malformed registry entries
            continue
    return actions

# ======================================================================================
# Utility
# ======================================================================================
def _safe_json_extract(s: str) -> Any:
    """
    Robustly extract JSON from a model response that might include fences or prose.
    Prefer a top-level JSON array if present, otherwise fall back to an object.
    """
    s = (s or "").strip()
    if not s:
        return {}
    # Try full string first
    try:
        return json.loads(s)
    except Exception:
        pass

    import re

    # 1) Try to extract a JSON array: [...] (our planner mapping usually returns a list)
    m = re.search(r"\[.*\]", s, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass

    # 2) Fall back to first JSON object: {...}
    m = re.search(r"\{.*\}", s, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass

    return {}


# ======================================================================================
# LLM-based step extraction
# ======================================================================================
def _extract_steps_from_llm(user_text: str, sop_snippets: List[str]) -> List[str]:
    """
    Ask the LLM to produce a minimal, ordered list of human-readable steps
    based on the user request + SOP text.

    If LLM is unavailable or fails, we return [] and the caller decides what to do.
    """
    if not GENAI_AVAILABLE:
        return []

    joined_sops = "\n\n".join([f"- {s}" for s in sop_snippets if s])

    system = (
        "You are a remediation step extractor for an IT service desk agent.\n"
        "Given a user request and some SOP text, you must infer the MINIMAL ordered steps\n"
        "needed to resolve the issue, expressed as concise imperative labels.\n\n"
        "RULES:\n"
        "- Steps must be high-level, not tied to any specific tool or function name.\n"
        "- Do not talk about JSON, code, or internal implementation.\n"
        "- Return ONLY compact JSON with keys: steps (array of strings), rationale (string), confidence (0..1).\n"
    )

    user = f"""
            User request:
            \"\"\"{user_text}\"\"\"


            SOP snippets:
            {joined_sops or "(none provided)"}

            Now decide the minimal ordered steps to resolve the issue.

            Return ONLY JSON of the form:
            {{"steps": ["<step1>", "<step2>"], "rationale": "<why>", "confidence": 0.8}}
            """

    try:
        # VERTEX-ONLY PATH
        model = GenerativeModel(GENAI_MODEL)
        resp = model.generate_content(
            system + "\n\n" + user,
            generation_config={
                "temperature": 0.2,
                "max_output_tokens": 512,
                "response_mime_type": "application/json",
            },
        )
        text = getattr(resp, "text", "") or ""

        # If .text is missing/too short, reconstruct from candidates.parts
        if not text or len(text.strip()) < 10:
            try:
                parts_text: List[str] = []
                for c in getattr(resp, "candidates", []) or []:
                    content = getattr(c, "content", None)
                    if not content:
                        continue
                    for p in getattr(content, "parts", []) or []:
                        t = getattr(p, "text", None)
                        if t:
                            parts_text.append(str(t))
                if parts_text:
                    text = "\n".join(parts_text)
            except Exception as e:
                print(f"[planner] error reconstructing Vertex text (steps): {e}")

        data = _safe_json_extract(text)
        if isinstance(data, dict) and isinstance(data.get("steps"), list):
            steps = [str(s).strip() for s in data["steps"] if str(s).strip()]
            return steps
        return []
    except Exception:
        return []

# ======================================================================================
# Fallback: local fuzzy mapping (no LLM)
# ======================================================================================
def _score_against_action(step_text: str, action: Dict[str, Any]) -> float:
    """
    Fuzzy similarity between a step label and a registry action.
    Uses:
      - difflib over full text
      - plus token overlap between the step and (title+description+effects)
    """
    hay_text = " ".join([
        (action.get("title") or ""),
        (action.get("description") or ""),
        " ".join(action.get("effects") or []),
    ]).lower()

    needle = (step_text or "").lower()
    # 1) Original difflib score
    base_score = difflib.SequenceMatcher(a=needle, b=hay_text).ratio()
    # 2) Token overlap score (generic, no hard-coded keywords)
    step_tokens = {t for t in re.findall(r"\w+", needle) if t}
    hay_tokens = {t for t in re.findall(r"\w+", hay_text) if t}

    overlap = step_tokens & hay_tokens
    if step_tokens:
        overlap_score = len(overlap) / len(step_tokens)
    else:
        overlap_score = 0.0

    # 3) Combine: weight base similarity more, but bump when tokens overlap
    return 0.7 * base_score + 0.3 * overlap_score


def _fallback_map_steps_to_actions(
    step_texts: List[str],
    actions: List[Dict[str, Any]],
    threshold: float = PLAN_CONF_THRESHOLD,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Deterministic, semantic-ish mapping using fuzzy similarity.
    No keywords, no hardcoded use cases.
    """
    mapped: List[Dict[str, Any]] = []
    unmapped: List[Dict[str, Any]] = []

    for st in step_texts:
        best = None
        best_s = 0.0
        for a in actions:
            s = _score_against_action(st, a)
            if s > best_s:
                best, best_s = a, s

        if best is not None and best_s >= threshold:
            mapped.append({
                "tool": best.get("tool"),
                "action": best.get("action"),
                "args": best.get("args_template", {}) or {},
                "_match": {"id": best.get("id"), "score": best_s, "source": "fallback"},
            })
        else:
            unmapped.append({
                "name": st,
                "reason": "no matching action (fallback)",
                "confidence": best_s,
            })

    return mapped, unmapped

# ======================================================================================
# LLM-based mapping: steps -> registry actions
# ======================================================================================
def _llm_map_steps_to_actions(
    step_texts: List[str],
    actions: List[Dict[str, Any]],
    min_confidence: float = 0.5,
) -> Optional[Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]]:
    """
    Use the LLM to semantically map SOP step labels to registry actions.

    Returns:
        (mapped, unmapped) on success, OR
        None if LLM is unavailable / unusable so that caller can fallback.
    """
    if not (GENAI_AVAILABLE and step_texts and actions):
        return None

    # Slim view for the LLM
    action_summaries: List[Dict[str, Any]] = []
    for a in actions:
        aid = a.get("id")
        tool = a.get("tool")
        act_name = a.get("action")
        if not (aid and tool and act_name):
            continue
        action_summaries.append(
            {
                "id": aid,
                "tool": tool,
                "action": act_name,
                "title": a.get("title"),
                "description": a.get("description"),
                "effects": a.get("effects", []),
            }
        )

    if not action_summaries:
        return None

    system = (
        "You are mapping SOP steps to automation actions in an IT service desk platform.\n"
        "Each action has an id, tool, action, title, description, and effects.\n"
        "For each step text, choose AT MOST ONE best matching action.id, or null if no action fits.\n"
        "Base your decisions on semantics, not exact string matching.\n"
        "Return ONLY JSON:\n"
        "[\n"
        '  {"step": "<step text>", "action_id": "<action id or null>", "confidence": 0.0-1.0},\n'
        "  ...\n"
        "]"
    )

    user = json.dumps(
        {
            "steps": step_texts,
            "actions": action_summaries,
        },
        indent=2,
    )

    try:
        # VERTEX-ONLY PATH
        model = GenerativeModel(GENAI_MODEL)
        resp = model.generate_content(
            system + "\n\nUSER:\n" + user,
            generation_config={
                "temperature": 0.1,
                "max_output_tokens": 8192,  # increase output size to reduce truncation
                "response_mime_type": "application/json",
            },
        )
        raw_text = getattr(resp, "text", "") or ""

        # Optional: still write for debug; if it's empty, that's fine.
        # try:
        #     with open("/tmp/llm_raw_mapping.json", "w", encoding="utf-8") as f:
        #         f.write(raw_text)
        # except Exception:
        #     pass

        data = _safe_json_extract(raw_text)
    except Exception:
        # Total LLM failure → let caller use fallback
        return None

    # --- Handle possible JSON shapes from the LLM --- #
    if isinstance(data, dict) and isinstance(data.get("mappings"), list):
        entries = data["mappings"]
    elif isinstance(data, list):
        entries = data
    else:
        # Parsed, but not in any expected shape → let caller fallback
        return None

    registry_by_id = {a.get("id"): a for a in actions if a.get("id")}
    mapped: List[Dict[str, Any]] = []
    unmapped: List[Dict[str, Any]] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        step = entry.get("step")
        aid = entry.get("action_id")
        try:
            conf = float(entry.get("confidence", 0.0) or 0.0)
        except Exception:
            conf = 0.0

        if not step:
            continue

        if aid and aid in registry_by_id and conf >= min_confidence:
            act = registry_by_id[aid]
            mapped.append(
                {
                    "tool": act.get("tool"),
                    "action": act.get("action"),
                    "args": act.get("args_template", {}) or {},
                    "_match": {"id": aid, "score": conf, "source": "llm"},
                }
            )
        else:
            unmapped.append(
                {
                    "name": step,
                    "reason": "no matching action (llm)",
                    "confidence": conf,
                }
            )

    # If nothing was mapped at all, treat this as "LLM not useful" → return None
    # so that propose_plan can fall back to fuzzy mapping.
    if not mapped:
        return None

    return mapped, unmapped


def _dedupe_mapped_actions(mapped: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Collapse duplicate tool+action+args entries into a single call.

    Example:
      3 steps -> all map to win_tool.time_resync with same args_template
      => we keep just ONE entry, keeping the best (max) score.
    """
    by_key = {}
    order: List[tuple] = []

    for m in mapped:
        tool = m.get("tool")
        action = m.get("action")
        args = m.get("args", {}) or {}
        key = (tool, action, json.dumps(args, sort_keys=True))

        if key not in by_key:
            by_key[key] = m
            order.append(key)
        else:
            # Keep the higher score if present
            prev = by_key[key]
            prev_score = (prev.get("_match", {}) or {}).get("score", 0.0)
            new_score = (m.get("_match", {}) or {}).get("score", 0.0)
            if new_score > prev_score:
                # Update only the score/meta, keep same tool/action/args
                prev["_match"] = prev.get("_match", {})
                prev["_match"]["score"] = new_score

    return [by_key[k] for k in order]


# ======================================================================================
# Main dynamic planner (LLM first, safe fallback)
# ======================================================================================
def propose_plan(
    user_text: str,
    ctx_vars: List[str],
    sop_texts: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Dynamic, multi-step plan builder.

    - If sop_texts are provided (from sop_retriever), treat them as already distilled step labels.
    - Otherwise, ask the LLM to extract steps from (user_text + SOP snippets).
    - Try LLM-based mapping steps -> actions.
    - If LLM mapping fails, fallback to local fuzzy mapping.
    """
    actions = _load_registry()
    sop_texts = sop_texts or []

    if not user_text and not sop_texts:
        return {
            "status": "no_match",
            "plan": {
                "required_inputs": [],
                "preconditions": [],
                "tool_sequence": [],
                "unmapped": [],
                "can_execute_fully": False,
                "must_validate_preconditions": True,
                "confidence": 0.0,
            },
        }
    
    # --- 1. Steps --- #
    if sop_texts:
        # From sop_retriever: already simple step labels
        step_texts = [s for s in sop_texts if isinstance(s, str) and s.strip()]
    else:
        # Let LLM extract from user_text + (optional) SOP text
        step_texts = _extract_steps_from_llm(user_text, sop_texts)

    if not step_texts:
        return {
            "status": "llm_error_steps",
            "plan": {
                "required_inputs": [],
                "preconditions": [],
                "tool_sequence": [],
                "unmapped": [],
                "can_execute_fully": False,
                "must_validate_preconditions": True,
                "confidence": 0.0,
            },
        }

    # --- 2. Mapping: LLM first, then fallback --- #
    mapped: List[Dict[str, Any]]
    unmapped: List[Dict[str, Any]]

    # 2a) Mapping: LLM first, then fallback
    llm_result = _llm_map_steps_to_actions(step_texts, actions)

    if llm_result is not None:
        mapped, unmapped = llm_result
    else:
        # LLM unavailable or failed → fallback matcher
        mapped, unmapped = _fallback_map_steps_to_actions(step_texts, actions)

    # 2b) Collapse duplicate actions (same tool + action + args)
    mapped = _dedupe_mapped_actions(mapped)

    # --- 3. Aggregate inputs & preconditions --- #
    inputs: set = set()
    preconds: set = set()
    for m in mapped:
        act = next(
            (a for a in actions if a.get("tool") == m["tool"] and a.get("action") == m["action"]),
            None,
        )
        if act:
            inputs |= set(act.get("inputs", []) or [])
            preconds |= set(act.get("preconditions", []) or [])

    missing = sorted([v for v in inputs if v not in (ctx_vars or [])])

    # Confidence: average of scores (either LLM or fallback) for mapped steps
    confidence = 0.0
    if mapped:
        scores = [m.get("_match", {}).get("score", 0.0) for m in mapped]
        if scores:
            confidence = sum(scores) / len(scores)

    # --- Expose mapping source (llm / fallback / None) --- #
    if mapped:
        sources = [
            (m.get("_match") or {}).get("source")
            for m in mapped
            if m.get("_match") is not None
        ]
        mapping_source = sources[0] if sources else None
    else:
        mapping_source = None

    # --- Confidence gate for auto-remediation --- #
    low_confidence = confidence < PLAN_CONF_THRESHOLD

    plan = {
        "required_inputs": missing,
        "preconditions": sorted(preconds),
        "preconditions_source": "planner",
        "tool_sequence": [
            {"tool": m["tool"], "action": m["action"], "args": m["args"], "action_id": (m.get("_match") or {}).get("id"),} for m in mapped
        ],
        "unmapped": unmapped,
        # Only allow auto-execution if:
        #   - we have mapped steps
        #   - nothing is unmapped
        #   - AND confidence is above threshold
        "can_execute_fully": (len(unmapped) == 0 and len(mapped) > 0 and not low_confidence),
        "must_validate_preconditions": True,
        "confidence": confidence,
        "low_confidence": low_confidence,
        "mapping_source": mapping_source
    }

    status = "ok" if (mapped or unmapped) else "no_match"
    return {"status": status, "plan": plan}

