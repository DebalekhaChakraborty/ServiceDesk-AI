"""Voice Gateway — the only bridge between Dograh and the existing ServiceDesk.

Deliberately narrow. It exposes exactly one functional route, forwards the
caller's text to the already-running sd_chat agent over its standard ADK REST
API, and returns the reply verbatim. It holds no conversation state, makes no
decisions, and has no privileged tools.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .config import Settings, load_settings
from .models import HealthResponse, VoiceTurnError, VoiceTurnRequest, VoiceTurnResponse
from .servicedesk_client import (
    ServiceDeskClient,
    ServiceDeskError,
    ServiceDeskSessionMissing,
)
from .session import SessionRegistry, adk_session_id, redact_session_id

logger = logging.getLogger("voice_gateway")


def _configure_logging() -> None:
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)


def create_app(
    settings: Settings | None = None,
    client: ServiceDeskClient | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    _configure_logging()

    sd = client or ServiceDeskClient(
        base_url=settings.servicedesk_base_url,
        app_name=settings.app_name,
        user_id=settings.user_id,
        timeout_seconds=settings.timeout_seconds,
    )
    registry = SessionRegistry()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        if client is None:
            await sd.aclose()

    app = FastAPI(
        title="Dograh -> ServiceDesk Voice Gateway",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.servicedesk = sd
    app.state.registry = registry

    # PoC single-session mode shares ONE ServiceDesk conversation across every
    # request, so a second concurrent caller would be spliced into the first
    # caller's conversation. This lock makes that impossible: overlapping turns
    # are refused outright rather than merged.
    turn_lock = asyncio.Lock()
    app.state.turn_lock = turn_lock

    if settings.poc_single_session:
        logger.warning(
            "POC SINGLE SESSION MODE ACTIVE - all turns share one ServiceDesk "
            "conversation. Single tester only; NOT safe for multi-caller use "
            "and NOT permitted for privileged operations."
        )

    def _error(code: str, text: str, http_status: int) -> JSONResponse:
        return JSONResponse(
            status_code=http_status,
            content=VoiceTurnError(code=code, text=text).model_dump(),
        )

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        downstream = "reachable" if await sd.health() else "unreachable"
        return HealthResponse(
            status="ok",
            servicedesk=downstream,
            poc_single_session=settings.poc_single_session,
        )

    @app.post("/voice/turn")
    async def voice_turn(req: VoiceTurnRequest):
        started = time.monotonic()

        # Resolve the conversation id SERVER-SIDE. In PoC mode the caller does
        # not supply one at all, which is the point: Dograh v1.45 can only fill
        # tool parameters via the LLM, and an LLM must never choose the session
        # a conversation belongs to.
        if settings.poc_single_session:
            voice_session_id = settings.poc_session_id
        elif req.voice_session_id:
            voice_session_id = req.voice_session_id
        else:
            return _error(
                "MISSING_VOICE_SESSION_ID",
                "The request could not be processed.",
                422,
            )

        handle = redact_session_id(voice_session_id)

        text = req.text.strip()
        if not text:
            logger.info("turn session=%s rejected=EMPTY_UTTERANCE", handle)
            return _error(
                "EMPTY_UTTERANCE", "I did not catch that. Could you repeat it?", 400
            )
        if len(text) > settings.max_text_chars:
            logger.info("turn session=%s rejected=UTTERANCE_TOO_LONG", handle)
            return _error(
                "UTTERANCE_TOO_LONG", "That request was too long to process.", 400
            )

        # Phase 3 does no caller verification. Any verified_upn supplied by the
        # voice channel is an unverified assertion, so it is dropped here rather
        # than forwarded — ServiceDesk continues to see an anonymous caller.
        if req.verified_upn:
            logger.warning(
                "turn session=%s ignoring unverified identity assertion", handle
            )

        sd_session = adk_session_id(voice_session_id)

        # Fail closed on overlap rather than interleaving two callers into one
        # conversation. Non-blocking: a second concurrent turn is rejected, not
        # queued behind the first.
        if turn_lock.locked():
            logger.warning(
                "turn session=%s rejected=CONCURRENT_TURN_REJECTED", handle
            )
            return _error(
                "CONCURRENT_TURN_REJECTED",
                "The Service Desk is already handling another request. "
                "Please try again in a moment.",
                409,
            )

        async def ensure_session() -> None:
            """Make sure the ADK session exists, skipping the check when known."""
            if registry.is_known(sd_session):
                return
            if not await sd.session_exists(sd_session):
                await sd.create_session(sd_session)
            registry.mark_known(sd_session)

        try:
            async with turn_lock:
                await ensure_session()
                try:
                    reply = await sd.run_turn(sd_session, text)
                except ServiceDeskSessionMissing:
                    # The registry is only a cache, and it can go stale whenever
                    # something outside this process removes the session. Drop
                    # the stale entry, rebuild the session, and retry EXACTLY
                    # once — a second failure propagates rather than looping.
                    logger.warning(
                        "turn session=%s downstream session missing; "
                        "invalidating registry and retrying once",
                        handle,
                    )
                    registry.forget(sd_session)
                    await ensure_session()
                    reply = await sd.run_turn(sd_session, text)
        except ServiceDeskError as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            logger.warning(
                "turn session=%s status=error code=%s duration_ms=%d",
                handle,
                exc.code,
                duration_ms,
            )
            return _error(exc.code, exc.public_text, 502)
        except Exception:
            duration_ms = int((time.monotonic() - started) * 1000)
            # Log without the traceback so nothing internal reaches the caller
            # or the log stream.
            logger.error(
                "turn session=%s status=error code=GATEWAY_ERROR duration_ms=%d",
                handle,
                duration_ms,
            )
            return _error(
                "GATEWAY_ERROR", "The Service Desk service is unavailable.", 502
            )

        duration_ms = int((time.monotonic() - started) * 1000)
        logger.info(
            "turn session=%s status=ok duration_ms=%d reply_chars=%d",
            handle,
            duration_ms,
            len(reply),
        )
        if settings.log_utterances:  # opt-in only; off by default
            logger.debug("turn session=%s utterance=%r", handle, text)

        return VoiceTurnResponse(
            voice_session_id=voice_session_id, text=reply
        ).model_dump()

    return app


app = create_app()


def main() -> None:
    import uvicorn

    settings = load_settings()
    if not settings.is_private_bind():
        raise SystemExit(
            f"refusing to bind {settings.host!r}: the voice gateway must never be "
            "reachable beyond loopback or a private bridge address"
        )
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
