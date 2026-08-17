from typing import Any, Dict, List, Optional, Set

from google.adk.tools import FunctionTool, ToolContext
from sd_chat.config import get_env_fallback_persona


def _extract_persona_from_state(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Helper to extract persona from multiple possible locations in the ADK state.

    We support:
    - Top-level:   state["persona"]
    - Alias:       state["user:persona"]
    - Nested:      state["session"]["state"]["persona"]  (what the ADK portal sends)
    """
    # Top-level first
    if "persona" in state and isinstance(state["persona"], dict):
        return state["persona"]

    if "user:persona" in state and isinstance(state["user:persona"], dict):
        return state["user:persona"]

    # Nested session.state.persona
    session = state.get("session") or {}
    if not isinstance(session, dict):
        return None

    session_state = session.get("state") or {}
    if not isinstance(session_state, dict):
        return None

    persona = session_state.get("persona")
    if isinstance(persona, dict):
        return persona

    return None


def _extract_interaction_context(state: Dict[str, Any]) -> Dict[str, Any]:
    """Read the server-seeded interaction context, from the same places as persona.

    Only ever read from session state, which is written by the trusted server at
    session-creation time. There is no path by which a user message, a tool
    argument or a model output reaches this.
    """
    for key in ("interaction_context", "user:interaction_context"):
        value = state.get(key)
        if isinstance(value, dict):
            return value

    session = state.get("session") or {}
    if isinstance(session, dict):
        session_state = session.get("state") or {}
        if isinstance(session_state, dict):
            value = session_state.get("interaction_context")
            if isinstance(value, dict):
                return value
    return {}


def _normalize_host(value: Any) -> Optional[str]:
    """
    Normalize host/device identifiers into a stable hostname token.
    - Lowercase
    - Strip whitespace
    - Remove trailing dot
    - Remove protocol prefixes if any
    """
    if value is None:
        return None
    if not isinstance(value, str):
        # Some payloads could be numbers/bools; ignore them
        return None

    s = value.strip().lower()
    if not s:
        return None

    # Strip common prefixes that might sneak in
    for prefix in ("http://", "https://", "\\\\"):
        if s.startswith(prefix):
            s = s[len(prefix):]

    # If there's a path or port, keep only host part
    # e.g. "host:5985" -> "host", "host.domain/path" -> "host.domain"
    s = s.split("/")[0]
    s = s.split(":")[0]

    # Remove trailing dot (FQDN sometimes ends with ".")
    if s.endswith("."):
        s = s[:-1]

    return s or None


def _extract_allowed_hosts_from_devices(devices: Any) -> List[str]:
    """
    Extract a list of allowed hostnames from a persona "devices" field.

    Supports:
    - devices as list of dicts
    - devices as list of strings
    - devices as single dict or string (caller wraps into list)
    """
    candidates: Set[str] = set()

    if not devices:
        return []

    if not isinstance(devices, list):
        devices = [devices]

    for d in devices:
        if isinstance(d, str):
            h = _normalize_host(d)
            if h:
                candidates.add(h)
            continue

        if isinstance(d, dict):
            # Try a few common fields AD/Graph/portal might use
            for key in (
                "hostname",
                "hostName",
                "deviceName",
                "displayName",
                "dnsHostName",
                "dnsHostname",
                "fqdn",
                "name",
            ):
                if key in d:
                    h = _normalize_host(d.get(key))
                    if h:
                        candidates.add(h)

            # Some portals pack it in nested structures; best-effort
            # Example: {"properties": {"dnsHostName": "..."}}
            props = d.get("properties")
            if isinstance(props, dict):
                for key in ("dnsHostName", "dnsHostname", "fqdn", "deviceName", "displayName", "hostname"):
                    if key in props:
                        h = _normalize_host(props.get(key))
                        if h:
                            candidates.add(h)

            continue

        # Unknown type -> ignore

    # Stable order for deterministic UX/logging
    return sorted(candidates)


def ensure_identity_context_in_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Core identity logic that can be reused from both:
    - the identity_context_tool (when called as a tool)
    - the before_agent_callback (ensure_persona) in agent.py

    It:
    - Finds persona from multiple locations
    - Falls back to env persona if needed
    - Promotes persona to top-level state["persona"] / ["user:persona"]
    - Builds state["identity_context"]
    - Also derives state["allowed_hosts"] (from persona["devices"] when present)
    - Returns a small result dict {ok, source, identity?}
    """
    if state is None:
        state = {}

    # -------------------------------------------------------------------------
    # 1) Try to pull persona from any known location in state
    # -------------------------------------------------------------------------
    persona = _extract_persona_from_state(state)
    source = "session"

    if persona:
        # Promote to top-level so other code can consistently use state["persona"]
        if "persona" not in state:
            state["persona"] = persona
        if "user:persona" not in state:
            state["user:persona"] = persona
    else:
        # ---------------------------------------------------------------------
        # 2) No persona in session → try env fallback
        # ---------------------------------------------------------------------
        env_persona = get_env_fallback_persona()
        if env_persona:
            persona = env_persona
            state["persona"] = env_persona
            state["user:persona"] = env_persona
            state["identity_source"] = "env_fallback"
            source = "env_fallback"

    # -------------------------------------------------------------------------
    # 3) Still nothing → we have no identity info
    # -------------------------------------------------------------------------
    if not persona:
        return {
            "ok": False,
            "source": "none",
            "reason": (
                "No persona found in session (persona/user:persona/session.state.persona) "
                "and no env fallback persona configured."
            ),
        }

    # -------------------------------------------------------------------------
    # 4) Build a normalized identity_context structure
    # -------------------------------------------------------------------------

    # Common Graph / portal fields we may see
    display_name = (
        persona.get("displayName")
        or persona.get("name")
        or persona.get("givenName")
        or persona.get("user_principal_name")
        or persona.get("userPrincipalName")
        or persona.get("upn")
        or persona.get("email")
        or persona.get("mail")
    )

    # IMPORTANT: primary_email should be a *real* email address if we have one,
    # and NOT silently fall back to UPN.
    primary_email = (
        persona.get("mail")
        or persona.get("email")
    )

    # UPN / login identity: prefer the UPN-style fields, then (only if missing)
    # fall back to primary_email.
    upn = (
        persona.get("user_principal_name")
        or persona.get("userPrincipalName")
        or persona.get("upn")
        or primary_email
    )

    aad_id = (
        persona.get("id")
        or persona.get("objectId")
        or persona.get("aad_object_id")
        or persona.get("oid")
    )

    department = persona.get("department")
    job_title = persona.get("jobTitle") or persona.get("title")

    # Manager (if Graph / portal attached it)
    manager_info = persona.get("manager") or {}
    manager_name = None
    manager_email = None
    if isinstance(manager_info, dict):
        manager_name = (
            manager_info.get("displayName")
            or manager_info.get("name")
        )
        manager_email = (
            manager_info.get("mail")
            or manager_info.get("email")
            or manager_info.get("userPrincipalName")
        )

    # Groups (list of ids / displayNames, depending on what portal sent)
    groups = persona.get("groups") or []
    if not isinstance(groups, list):
        groups = [groups]

    # Devices (if portal injected)
    devices = persona.get("devices") or []
    if not isinstance(devices, list):
        devices = [devices]

    # -------------------------------------------------------------------------
    # 4.1) Derive allowed hosts from devices and store in state
    # -------------------------------------------------------------------------
    allowed_hosts = _extract_allowed_hosts_from_devices(devices)

    # Store in state so orchestrator/policy/tools can enforce host authorization
    # (Do NOT auto-set target_host here to avoid behavior changes; orchestrator can decide.)
    state["allowed_hosts"] = allowed_hosts

    identity: Dict[str, Any] = {
        "display_name": display_name,
        "primary_email": primary_email,  # now *only* mail/email
        "upn": upn,                      # login identity
        "aad_object_id": aad_id,
        "department": department,
        "job_title": job_title,
        "groups": groups,
        "devices": devices,
        "allowed_hosts": allowed_hosts,  # NEW: derived from devices
        "manager": {
            "name": manager_name,
            "email": manager_email,
        },
        "source": source,
    }

    # 5) Store the normalized version in state for other tools / agent logic
    state["identity_context"] = identity

    # -------------------------------------------------------------------------
    # 5.1) Presentation-only interaction context
    # -------------------------------------------------------------------------
    # Seeded server-side when a session is created (today: the voice gateway,
    # after Duo AND Graph have both passed). It answers exactly one question the
    # model cannot otherwise know: has this person already been talking to us?
    #
    # A voice caller states their problem, is taken through identity
    # verification, and only then does their ORIGINAL sentence arrive here as
    # the first message of a brand-new ADK session. To this agent that looks
    # like the start of a conversation, so it introduces itself - and the caller
    # hears a second greeting from what is supposed to be one continuous Service
    # Desk. The alternative fixes are worse: faking a prior exchange would put
    # words in the user's mouth that were never said, and re-using one session
    # across callers is not something an identity boundary can survive.
    #
    # This is PRESENTATION STATE AND NOTHING ELSE. It is surfaced here rather
    # than in `identity` so it cannot be mistaken for part of the identity, and
    # it is deliberately incapable of carrying authority: it establishes no
    # identity, selects no account or target, grants no permission, and is not
    # consulted by any policy or tool. Its effect is limited to whether the
    # agent says hello, and to resolving a caller's own vague "this portal"
    # wording back to the system they are actually calling about.
    # identity_context_tool is still called first, every time.
    #
    # `entrypoint` / `current_application` are read-through the same way as the
    # greeting fields: only a plain string survives, anything else becomes
    # None, so a malformed or hostile value degrades to "no context" rather
    # than reaching the model as free-form data.
    interaction = _extract_interaction_context(state)
    entrypoint = interaction.get("entrypoint")
    current_application = interaction.get("current_application")
    result_interaction = {
        "channel": interaction.get("channel") or "chat",
        # True only for a conversation that was already under way elsewhere.
        "continuation": bool(interaction.get("continuation")),
        "suppress_initial_greeting": bool(interaction.get("suppress_initial_greeting")),
        "entrypoint": entrypoint if isinstance(entrypoint, str) and entrypoint else None,
        "current_application": (
            current_application
            if isinstance(current_application, str) and current_application
            else None
        ),
    }
    state["interaction_context"] = result_interaction

    # DEBUG LOGGING: see what we really got from AD / portal
    try:
        print("[identity_context_tool] Raw persona from state:", persona)
        print("[identity_context_tool] Normalized identity_context:", identity)
        print("[identity_context_tool] Derived allowed_hosts:", allowed_hosts)
    except Exception:
        # Don't let logging break the tool in production
        pass

    return {
        "ok": True,
        "source": source,
        "identity": identity,
        # Presentation only. Never merged into `identity`.
        "interaction": result_interaction,
    }


def resolve_identity_context(tool_context: ToolContext) -> Dict[str, Any]:
    """
    Tool wrapper that delegates to ensure_identity_context_in_state, using tool_context.state.
    """
    state: Dict[str, Any] = tool_context.state or {}
    if tool_context.state is None:
        tool_context.state = state

    return ensure_identity_context_in_state(state)


identity_context_tool = FunctionTool(func=resolve_identity_context)
