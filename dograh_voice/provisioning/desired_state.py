"""Declarative desired state for the ServiceDesk voice agent.

Every shape here was taken from the running deployment's own
/api/v1/openapi.json, not from memory.
"""

from __future__ import annotations

import os
from typing import Any

GCP_PROJECT_ID = os.getenv("VERTEX_PROJECT_ID", "ai-and-automation-coe")

# The realtime and auxiliary models live in DIFFERENT locations. Both values
# below were measured against Vertex from inside dograh_voice-api-1, not
# assumed:
#
#   google/gemini-live-2.5-flash-native-audio
#       global      -> 1008 "Publisher model ... not found"
#       us-central1 -> CONNECTED, 41834 audio bytes, voice Charon
#       us-east4    -> CONNECTED, 37994 audio bytes
#
#   gemini-3.5-flash (generateContent)
#       global      -> HTTP 200
#       us-central1 -> HTTP 404 publisher model not found
#       us-east4    -> HTTP 404 publisher model not found
#
# us-central1 is chosen for realtime over the equally-working us-east4 because
# this VM lives in us-central1-c, so the media path stays in-region.
#
# NOTE: Dograh falls back to "us-east4" when location is empty
# (service_factory.py: `location or "us-east4"`), which would 404 the
# auxiliary model. Both locations are therefore always sent explicitly.
VERTEX_REALTIME_LOCATION = os.getenv("VERTEX_REALTIME_LOCATION", "us-central1")
VERTEX_LLM_LOCATION = os.getenv("VERTEX_LLM_LOCATION", "global")

TOOL_NAME = "servicedesk_voice_turn"
GATEWAY_URL = os.getenv("VOICE_GATEWAY_URL", "http://172.18.0.1:8010/voice/turn")

# ServiceDesk turns observed at 2-6s and can run longer when the agent uses
# tools. HttpApiConfig.timeout_ms defaults to 5000, which WOULD cut real turns
# off mid-flight, so it is set explicitly.
TOOL_TIMEOUT_MS = int(os.getenv("SERVICEDESK_TOOL_TIMEOUT_MS", "120000"))

TOOL_DESCRIPTION = (
    "Send the caller's exact words to the Service Desk and get the official "
    "reply. Call this for EVERY caller utterance without exception. The Service "
    "Desk is the only authority on IT questions, troubleshooting, account "
    "access, and incidents. Never answer from your own knowledge."
)

AGENT_PROMPT = """You are the voice channel for the Service Desk. You are ears and mouth only \
- you do not reason about IT problems yourself.

Open the call with exactly: "Welcome to ServiceDesk. How can I help you today?"

That is a greeting, not a question you answer. Do NOT ask the caller for an \
employee ID, an email address, a mobile number, or any other identifier, and do \
NOT assume the call is about a password or a locked account. The Service Desk \
decides what to ask for and when; it will tell you, through the tool, if it \
needs the caller to identify themselves.

For EVERY utterance the caller makes, call the tool `servicedesk_voice_turn`, \
passing the caller's current words verbatim as `text`.

The tool returns the Service Desk's official response. Treat that returned text \
as authoritative and final:
  - Speak it back faithfully and completely.
  - Do not summarise it, shorten it, embellish it, or reinterpret it.
  - Do not add remediation steps, advice, or troubleshooting of your own.
  - Do not answer any Service Desk question from your own knowledge, even if you \
are confident you know the answer.

You have no infrastructure tools of your own and must never attempt account \
changes, password resets, or ticket operations directly.

If the tool returns an error message, read that message to the caller as-is and \
wait for their reply."""


def desired_tool_payload() -> dict[str, Any]:
    """CreateToolRequest / UpdateToolRequest body.

    Exactly one parameter. No `voice_session_id`: the gateway owns the session
    server-side, so asking the model for an id would invite it to invent one.
    """
    return {
        "name": TOOL_NAME,
        "description": TOOL_DESCRIPTION,
        "category": "http_api",
        "definition": {
            "schema_version": 1,
            "type": "http_api",
            "config": {
                "method": "POST",
                "url": GATEWAY_URL,
                "headers": {"Content-Type": "application/json"},
                "timeout_ms": TOOL_TIMEOUT_MS,
                # SERVER-RESOLVED, never LLM-filled. The namespaced form
                # {{initial_context.x}} is used deliberately: Dograh's render
                # context is {**initial_context, **gathered_context,
                # "initial_context": ..., "gathered_context": ...}, so the bare
                # {{call_id}} would be SHADOWED by a gathered_context variable
                # of the same name — and gathered_context is influenced by the
                # LLM. The namespaced path cannot be overridden that way.
                "preset_parameters": [
                    {
                        "name": "call_id",
                        "type": "string",
                        "value_template": "{{initial_context.call_id}}",
                        "required": True,
                    },
                    {
                        "name": "voice_identity_token",
                        "type": "string",
                        "value_template": "{{initial_context.voice_identity_token}}",
                        "required": True,
                    },
                ],
                "parameters": [
                    {
                        "name": "text",
                        "type": "string",
                        "required": True,
                        "description": (
                            "The caller's current utterance, transcribed verbatim. "
                            "Do not summarise, correct, translate, or rephrase it. "
                            "Send only what the caller just said."
                        ),
                    }
                ],
            },
        },
    }


def desired_model_config() -> dict[str, Any]:
    """OrganizationAIModelConfigurationV2 selecting BYOK realtime on Vertex.

    Envelope shape is the live schema of this deployment, not a guess:
        OrganizationAIModelConfigurationV2 {version, mode: dograh|byok, byok}
        BYOKAIModelConfiguration          {mode: pipeline|realtime, realtime}
        BYOKRealtimeAIModelConfiguration  {realtime, llm}   # both required

    `credentials` and `api_key` are deliberately omitted from both services.
    That omission is exactly what makes pipecat fall through to Application
    Default Credentials — see
    site-packages/pipecat/services/google/gemini_live/vertex/llm.py
    ``_get_credentials``: json string -> file path -> ``default(scopes=...)``.
    In this deployment ADC resolves to the read-only mounted user credential,
    so no service-account JSON key exists anywhere.

    Model ids are this build's schema defaults, verified live against Vertex:
      GoogleVertexRealtimeLLMConfiguration.model = google/gemini-live-2.5-flash-native-audio
      GoogleVertexLLMConfiguration.model         = gemini-3.5-flash
    """
    return {
        "version": 2,
        "mode": "byok",
        "byok": {
            "mode": "realtime",
            "realtime": {
                "realtime": {
                    "provider": "google_vertex_realtime",
                    "model": os.getenv(
                        "VERTEX_REALTIME_MODEL",
                        "google/gemini-live-2.5-flash-native-audio",
                    ),
                    "voice": os.getenv("VERTEX_VOICE", "Charon"),
                    "language": "en",
                    "project_id": GCP_PROJECT_ID,
                    "location": VERTEX_REALTIME_LOCATION,
                },
                "llm": {
                    "provider": "google_vertex",
                    "model": os.getenv("VERTEX_LLM_MODEL", "gemini-3.5-flash"),
                    "project_id": GCP_PROJECT_ID,
                    "location": VERTEX_LLM_LOCATION,
                },
            },
        },
    }


def vertex_services(config: dict[str, Any]) -> list[dict[str, Any]]:
    """The two service blocks inside a desired/actual V2 byok-realtime config."""
    realtime = ((config.get("byok") or {}).get("realtime") or {})
    return [s for s in (realtime.get("realtime"), realtime.get("llm")) if isinstance(s, dict)]


# Any provider value that would route inference back through Dograh's managed
# service and consume credits.
DOGRAH_PROVIDER_MARKERS = {"dograh", "dograh_realtime"}


def find_dograh_providers(config: Any) -> list[str]:
    """Return every path in a config whose provider is Dograh-managed.

    Used to fail closed: if this is non-empty after a switch, inference would
    still be billed to Dograh credits.
    """
    found: list[str] = []

    def walk(node: Any, path: str) -> None:
        def label(field: str, value: str) -> str:
            return f"{path}.{field}={value}" if path else f"{field}={value}"

        if isinstance(node, dict):
            if node.get("mode") in DOGRAH_PROVIDER_MARKERS:
                found.append(label("mode", node["mode"]))
            provider = node.get("provider")
            if isinstance(provider, str) and provider.lower() in DOGRAH_PROVIDER_MARKERS:
                found.append(label("provider", provider))
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(config, "")
    return found
