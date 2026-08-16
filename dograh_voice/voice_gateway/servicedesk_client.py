"""Thin client for the EXISTING ServiceDesk ADK REST API.

Contract discovered read-only from the running server's /openapi.json:

    POST /apps/{app}/users/{user}/sessions/{session_id}   create with our own id
    GET  /apps/{app}/users/{user}/sessions/{session_id}    existence check
    POST /run                                              non-streaming turn
    GET  /health

Nothing under sd_chat/ is imported, patched, or modified.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx


class ServiceDeskError(Exception):
    """Base failure. `code` is the stable value returned to the caller."""

    code = "SERVICEDESK_ERROR"
    public_text = "The Service Desk service could not complete that request."


class ServiceDeskUnavailable(ServiceDeskError):
    code = "SERVICEDESK_UNAVAILABLE"
    public_text = "The Service Desk service is temporarily unavailable."


class ServiceDeskTimeout(ServiceDeskError):
    code = "SERVICEDESK_TIMEOUT"
    public_text = "The Service Desk service took too long to respond."


class ServiceDeskBadStatus(ServiceDeskError):
    code = "SERVICEDESK_BAD_STATUS"
    public_text = "The Service Desk service returned an unexpected result."


class ServiceDeskMalformed(ServiceDeskError):
    code = "SERVICEDESK_MALFORMED_RESPONSE"
    public_text = "The Service Desk service returned an unreadable result."


class ServiceDeskSessionMissing(ServiceDeskError):
    """The referenced ADK session no longer exists downstream.

    Deliberately narrow: raised ONLY for 404 from /run. Every other non-200
    stays ServiceDeskBadStatus, so a 400, 403, 429 or 500 can never be
    mistaken for session loss and silently retried.
    """

    code = "SERVICEDESK_SESSION_LOST"
    public_text = "The Service Desk conversation could not be resumed."


def extract_final_text(events: Any) -> Optional[str]:
    """Pull the assistant's reply out of an ADK /run event list.

    A turn comes back as several events — tool calls, tool responses, then the
    model's text. Observed shape for one greeting:

        [0] role=model  parts=[functionCall]       resolve_identity_context
        [1] role=user   parts=[functionResponse]
        [2] role=model  parts=[text]               <- the reply

    Note event[1] carries role "user" despite being a tool result, so filtering
    on role alone is not enough; we take the LAST event that is both role=model
    and has non-empty text.
    """
    if not isinstance(events, list):
        return None

    final: Optional[str] = None
    for event in events:
        if not isinstance(event, dict):
            continue
        content = event.get("content") or {}
        if content.get("role") != "model":
            continue
        parts = content.get("parts") or []
        if not isinstance(parts, list):
            continue
        text = "".join(
            p.get("text", "")
            for p in parts
            if isinstance(p, dict) and isinstance(p.get("text"), str)
        )
        if text.strip():
            final = text
    return final


class ServiceDeskClient:
    def __init__(
        self,
        base_url: str,
        app_name: str,
        user_id: str,
        timeout_seconds: float = 120.0,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.app_name = app_name
        self.user_id = user_id
        self.timeout_seconds = timeout_seconds
        self._client = client
        self._owns_client = client is None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout_seconds)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    def _session_url(self, adk_session_id: str) -> str:
        return (
            f"{self.base_url}/apps/{self.app_name}"
            f"/users/{self.user_id}/sessions/{adk_session_id}"
        )

    async def health(self) -> bool:
        try:
            client = await self._get_client()
            resp = await client.get(f"{self.base_url}/health", timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False

    async def session_exists(self, adk_session_id: str) -> bool:
        client = await self._get_client()
        try:
            resp = await client.get(self._session_url(adk_session_id))
        except httpx.TimeoutException as exc:
            raise ServiceDeskTimeout() from exc
        except httpx.HTTPError as exc:
            raise ServiceDeskUnavailable() from exc
        return resp.status_code == 200

    async def create_session(
        self, adk_session_id: str, persona: Optional[dict] = None
    ) -> None:
        """Create the session, optionally seeding a VERIFIED persona.

        With persona=None the state stays empty, so identity_context_tool
        reports ok=false exactly as it does for an anonymous caller. A persona
        is passed ONLY after a portal-signed identity token has been verified;
        it is never built from anything the browser or the LLM supplied.

        The ADK create endpoint treats the request body AS the session state
        (verified against the running server: posting {"state": {...}} nests a
        literal "state" key and identity_context_tool then finds no persona).
        """
        client = await self._get_client()
        body = {"persona": persona} if persona else {}
        try:
            resp = await client.post(self._session_url(adk_session_id), json=body)
        except httpx.TimeoutException as exc:
            raise ServiceDeskTimeout() from exc
        except httpx.HTTPError as exc:
            raise ServiceDeskUnavailable() from exc

        # A concurrent turn may have created it first; that is success for us.
        if resp.status_code in (200, 201):
            return
        if resp.status_code in (400, 409) and await self.session_exists(adk_session_id):
            return
        raise ServiceDeskBadStatus()

    async def run_turn(self, adk_session_id: str, text: str) -> str:
        """Send one user turn to the existing agent and return its reply text."""
        client = await self._get_client()
        payload = {
            "appName": self.app_name,
            "userId": self.user_id,
            "sessionId": adk_session_id,
            "newMessage": {"role": "user", "parts": [{"text": text}]},
            "streaming": False,
        }
        try:
            resp = await client.post(f"{self.base_url}/run", json=payload)
        except httpx.TimeoutException as exc:
            raise ServiceDeskTimeout() from exc
        except httpx.HTTPError as exc:
            raise ServiceDeskUnavailable() from exc

        # /run is a known-good route on a healthy server, and the only resource
        # its payload addresses is the session — so a 404 here means the session
        # is gone (ADK replies `{"detail": "Session not found: ..."}`). This can
        # happen whenever something outside this process removes the session:
        # an operator cleanup, an ADK restart with in-memory session storage, or
        # a session TTL. It is recoverable; nothing else is.
        if resp.status_code == 404:
            raise ServiceDeskSessionMissing()
        if resp.status_code != 200:
            raise ServiceDeskBadStatus()

        try:
            events = resp.json()
        except ValueError as exc:
            raise ServiceDeskMalformed() from exc

        reply = extract_final_text(events)
        if reply is None or not reply.strip():
            raise ServiceDeskMalformed()
        return reply
