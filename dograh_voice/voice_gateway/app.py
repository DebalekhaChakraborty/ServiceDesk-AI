"""Voice Gateway — the only bridge between Dograh and the existing ServiceDesk.

Deliberately narrow. It exposes exactly one functional route, forwards the
caller's text to the already-running sd_chat agent over its standard ADK REST
API, and returns the reply verbatim. It holds no conversation state, makes no
decisions, and has no privileged tools.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

from .config import Settings, load_settings
from .identity import (
    IdentityTokenError,
    verify_recovery_bootstrap,
    load_signing_secret,
    persona_from_claims,
    redact_token,
    verify as verify_identity_token,
)
from .models import (
    DuoEnrollBeginRequest,
    DuoEnrollBeginResponse,
    DuoEnrollStatusResponse,
    HealthResponse,
    RecoveryEnrollBeginRequest,
    RecoveryEnrollBeginResponse,
    RecoveryEnrollConfirmRequest,
    RecoveryStartRequest,
    VoiceTurnError,
    VoiceTurnRequest,
    VoiceTurnResponse,
)
from .duo_recovery import DuoRecoveryManager
from .duo_provider import DuoRecoveryProvider, load_duo_config
from .graph_corroboration import load_corroborator
from .identifiers import IdentifierError, normalize_upn
from .identity_map import EmployeeIdentityMap
from .mfa_provider import MfaProviderError
from .recovery import RecoveryManager, RecoveryState, recovery_persona
from .totp import DIGITS, PERIOD_SECONDS
from .servicedesk_client import (
    ServiceDeskClient,
    ServiceDeskError,
    ServiceDeskSessionMissing,
)
from .totp import SpokenCodeError, parse_spoken_code
from .recovery import PROMPT_FOR_OTP
from .duo_recovery import IDENTIFIER_PROMPT as DUO_IDENTIFIER_PROMPT
from .recovery_store import enrollment_admin_key
from .recovery_store import redact_account as _redact_account
from .session import (
    SessionRegistry,
    adk_session_id,
    auth_session_id,
    redact_call_id,
    redact_session_id,
)

logger = logging.getLogger("voice_gateway")


def _configure_logging() -> None:
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)


def _build_recovery(settings: Settings):
    """Construct the ACTIVE recovery provider, or return None.

    Duo is the only provider built by default. `/auth/v2/check` is called here,
    at startup, because a Duo integration that cannot authenticate must leave
    recovery switched OFF rather than fail one caller at a time — a half-working
    MFA path is worse than none, since it looks like a recovery route and is not
    one.

    The retired self-hosted TOTP verifier is reachable only by setting
    RECOVERY_PROVIDER=totp explicitly.
    """
    provider_name = (settings.recovery_provider or "duo").lower()

    if provider_name == "totp":
        try:
            manager = RecoveryManager()
            logger.warning(
                "recovery provider=totp ENABLED - the retired self-hosted "
                "verifier. Duo is the supported provider."
            )
            return manager
        except Exception as exc:           # missing key, or secret collision
            logger.warning("recovery DISABLED: %s", type(exc).__name__)
            return None

    if provider_name != "duo":
        logger.warning("recovery DISABLED: unknown provider %r", provider_name)
        return None

    config = load_duo_config()
    if config is None:
        logger.warning("recovery DISABLED: Duo is not configured")
        return None

    try:
        provider = DuoRecoveryProvider(config)
        check = provider.check()
    except MfaProviderError as exc:
        logger.warning("recovery DISABLED: Duo configuration rejected (%s)", exc.code)
        return None
    if not check.ok:
        logger.warning("recovery DISABLED: Duo /check failed (%s)", check.reason)
        return None

    try:
        identity_map = EmployeeIdentityMap()
    except Exception as exc:
        logger.warning("recovery DISABLED: identity map unavailable (%s)",
                       type(exc).__name__)
        return None

    corroborator = load_corroborator()
    logger.info(
        "recovery provider=duo ENABLED config=%s corroboration=%s",
        config.redacted(), type(corroborator).__name__,
    )
    return DuoRecoveryManager(identity_map, provider, corroborator)


def create_app(
    settings: Settings | None = None,
    client: ServiceDeskClient | None = None,
    recovery: "RecoveryManager | DuoRecoveryManager | None" = None,
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

    # Load the signing secret once at startup so a missing secret is a loud
    # boot failure rather than a per-call 401 that looks like a caller problem.
    signing_secret: str | None = None
    if settings.require_authenticated_identity:
        signing_secret = load_signing_secret()
        logger.info("authenticated identity mode ACTIVE")
    elif not settings.poc_single_session and not settings.allow_legacy_unauthenticated:
        # Refuse the one genuinely unsafe combination: no authentication AND no
        # single-tester containment.
        raise RuntimeError(
            "VOICE_GATEWAY_REQUIRE_AUTH=false is only permitted together with "
            "VOICE_GATEWAY_POC_SINGLE_SESSION=true. There is no anonymous "
            "multi-caller configuration."
        )
    elif settings.allow_legacy_unauthenticated:
        logger.warning(
            "LEGACY UNAUTHENTICATED MODE ACTIVE - caller-supplied session ids "
            "with no identity proof. Tests and local experiments only."
        )
    app.state.authenticated_mode = settings.require_authenticated_identity

    # Recovery is only constructed when its provider is fully configured AND
    # reachable, so a deployment with half-configured MFA has no recovery path
    # rather than a broken one.
    if recovery is None:
        recovery = _build_recovery(settings)
    else:
        logger.info("recovery ENABLED (injected: %s)", type(recovery).__name__)
    app.state.recovery = recovery

    if settings.poc_single_session:
        logger.warning(
            "POC SINGLE SESSION MODE ACTIVE - all turns share one ServiceDesk "
            "conversation. Single tester only; NOT safe for multi-caller use "
            "and NOT permitted for privileged operations."
        )

    # One message for every authentication failure, whatever the cause.
    _AUTH_FAILED_TEXT = (
        "I could not verify who you are, so I cannot continue. "
        "Please start a new session from the employee portal."
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

    def _enrollment_authorised(admin_key: str | None) -> bool:
        """Only the portal may enroll. See enrollment_admin_key for why.

        The key is derived from the recovery-store key file, which predates Duo.
        Keeping one derivation means one secret to rotate; if that file is
        removed, every enrollment call fails closed with 403 rather than
        becoming open.
        """
        if recovery is None:
            return False
        try:
            expected = enrollment_admin_key()
        except Exception:
            return False
        return bool(admin_key) and hmac.compare_digest(admin_key, expected)

    # --- Duo enrollment (ACTIVE provider) --------------------------------
    #
    # Both endpoints are portal-only. The portal holds the live Entra session,
    # and the identity it sends is matched against the existing map row before
    # anything is bound, so a form-supplied identity can never enroll a Duo
    # credential against somebody else's record.

    def _duo(manager) -> "DuoRecoveryManager | None":
        return manager if isinstance(manager, DuoRecoveryManager) else None

    def _matched_record(manager: DuoRecoveryManager, req: DuoEnrollBeginRequest):
        """The map row for this session identity, or None.

        Requires tenant, object id AND UPN to agree. The object id alone would
        be enough to identify the row; demanding all three means a stale row
        that no longer matches the signed-in employee refuses to enroll instead
        of quietly binding Duo to the wrong alias.
        """
        record = manager.identity_map.by_object_id(req.tenant_id, req.object_id)
        if record is None:
            return None
        try:
            if record.upn != normalize_upn(req.upn):
                return None
        except IdentifierError:
            return None
        return record

    @app.post("/recovery/enroll/duo/begin", response_model=DuoEnrollBeginResponse)
    async def duo_enroll_begin(
        req: DuoEnrollBeginRequest,
        x_recovery_admin_key: str | None = Header(default=None),
    ):
        """Create a PENDING Duo enrollment and return its activation QR."""
        manager = _duo(recovery)
        if manager is None:
            return _error("RECOVERY_UNAVAILABLE", "Recovery is not configured.", 503)
        if not _enrollment_authorised(x_recovery_admin_key):
            logger.warning("duo enroll begin rejected=UNAUTHORISED")
            return _error("NOT_AUTHORISED", "Not authorised.", 403)

        record = _matched_record(manager, req)
        if record is None:
            logger.warning("duo enroll begin rejected=NO_MAP_RECORD")
            return _error(
                "ENROLLMENT_UNAVAILABLE",
                "Recovery enrollment is not available for this account.", 404,
            )

        try:
            ticket = manager.provider.enroll()
        except MfaProviderError as exc:
            logger.warning("duo enroll begin failed code=%s", exc.code)
            return _error("ENROLLMENT_UNAVAILABLE",
                          "Recovery enrollment is not available right now.", 502)

        # PENDING only. Rendering a QR proves nothing about whether anyone
        # scanned it, so recovery stays switched off for this employee until
        # Duo itself reports activation.
        manager.identity_map.bind_duo_user(
            record.employee_id, ticket.user_id, ticket.username,
            ticket.activation_code,
        )
        logger.info("duo enroll begin account=%s status=pending", record.redacted())

        qr_data_uri = None
        if ticket.activation_barcode_url:
            try:
                content_type, image = manager.provider.fetch_activation_qr(
                    ticket.activation_barcode_url
                )
                qr_data_uri = (
                    f"data:{content_type};base64,"
                    + base64.b64encode(image).decode("ascii")
                )
            except MfaProviderError as exc:
                # The activation code alone is still usable in Duo Mobile.
                logger.warning("duo activation qr unavailable code=%s", exc.code)

        return DuoEnrollBeginResponse(
            activation_code=ticket.activation_code,
            qr_data_uri=qr_data_uri,
            expires_at=ticket.expires_at,
        )

    @app.post("/recovery/enroll/duo/status", response_model=DuoEnrollStatusResponse)
    async def duo_enroll_status(
        req: DuoEnrollBeginRequest,
        x_recovery_admin_key: str | None = Header(default=None),
    ):
        """Ask Duo whether the employee actually activated Duo Mobile."""
        manager = _duo(recovery)
        if manager is None:
            return _error("RECOVERY_UNAVAILABLE", "Recovery is not configured.", 503)
        if not _enrollment_authorised(x_recovery_admin_key):
            logger.warning("duo enroll status rejected=UNAUTHORISED")
            return _error("NOT_AUTHORISED", "Not authorised.", 403)

        record = _matched_record(manager, req)
        if record is None or not record.duo_user_id or not record.duo_activation_code:
            return _error("ENROLLMENT_NOT_CONFIRMED",
                          "Enrollment has not been started.", 400)

        try:
            status = manager.provider.enroll_status(
                record.duo_user_id, record.duo_activation_code
            )
        except MfaProviderError as exc:
            logger.warning("duo enroll status failed code=%s", exc.code)
            return _error("ENROLLMENT_UNAVAILABLE",
                          "Recovery enrollment is not available right now.", 502)

        if status.state == "success":
            # The ONLY path that switches recovery on for an employee.
            manager.identity_map.activate_duo(record.employee_id)
            logger.info("duo enroll status account=%s status=active", record.redacted())
            return DuoEnrollStatusResponse(status="active")

        logger.info("duo enroll status account=%s status=%s",
                    record.redacted(), status.state)
        return DuoEnrollStatusResponse(
            status="waiting" if status.state == "waiting" else "invalid"
        )

    # --- TOTP enrollment (retired provider, reachable only via RECOVERY_PROVIDER=totp)

    @app.post("/recovery/enroll/begin", response_model=RecoveryEnrollBeginResponse)
    async def recovery_enroll_begin(
        req: RecoveryEnrollBeginRequest,
        x_recovery_admin_key: str | None = Header(default=None),
    ):
        """Mint a pending enrollment. Portal-only; it holds the Entra session."""
        if not isinstance(recovery, RecoveryManager):
            return _error("RECOVERY_UNAVAILABLE", "Recovery is not configured.", 503)
        if not _enrollment_authorised(x_recovery_admin_key):
            logger.warning("recovery enroll begin rejected=UNAUTHORISED")
            return _error("NOT_AUTHORISED", "Not authorised.", 403)
        seed, uri = recovery.store.begin_enrollment(
            req.upn, req.display_name, req.object_id
        )
        logger.info("recovery enroll begin account=%s", _redact_account(req.upn))
        return RecoveryEnrollBeginResponse(
            secret=seed, otpauth_uri=uri, digits=DIGITS, period_seconds=PERIOD_SECONDS
        )

    @app.post("/recovery/enroll/confirm")
    async def recovery_enroll_confirm(
        req: RecoveryEnrollConfirmRequest,
        x_recovery_admin_key: str | None = Header(default=None),
    ):
        """Activate only on proof of a working authenticator."""
        if not isinstance(recovery, RecoveryManager):
            return _error("RECOVERY_UNAVAILABLE", "Recovery is not configured.", 503)
        if not _enrollment_authorised(x_recovery_admin_key):
            logger.warning("recovery enroll confirm rejected=UNAUTHORISED")
            return _error("NOT_AUTHORISED", "Not authorised.", 403)
        try:
            code = parse_spoken_code(req.code)
        except SpokenCodeError:
            return _error("ENROLLMENT_NOT_CONFIRMED",
                          "That code was not accepted. Please try again.", 400)
        ok = recovery.store.activate(req.upn, code)
        logger.info("recovery enroll confirm account=%s result=%s",
                    _redact_account(req.upn), "active" if ok else "rejected")
        if not ok:
            return _error("ENROLLMENT_NOT_CONFIRMED",
                          "That code was not accepted. Please try again.", 400)
        return {"status": "active"}

    @app.post("/recovery/start")
    async def recovery_start(req: RecoveryStartRequest):
        """Begin a recovery call. Deliberately reveals nothing about enrollment."""
        if recovery is None:
            return _error("RECOVERY_UNAVAILABLE", "Recovery is not configured.", 503)
        try:
            verify_recovery_bootstrap(req.recovery_token, signing_secret, req.call_id)
        except IdentityTokenError as exc:
            logger.warning("recovery start rejected reason=%s", exc.reason)
            return _error("IDENTITY_REJECTED", _AUTH_FAILED_TEXT, 401)

        if isinstance(recovery, DuoRecoveryManager):
            # Under Duo the caller identifies themselves by voice, so no
            # identifier is accepted here at all and any claimed_upn on the wire
            # is discarded rather than stored.
            recovery.start(req.call_id)
            return {"status": "ok", "prompt": DUO_IDENTIFIER_PROMPT}

        recovery.start(req.call_id, req.claimed_upn or "")
        # Identical response whether or not the account is enrolled.
        return {"status": "ok", "prompt": PROMPT_FOR_OTP}

    @app.post("/voice/turn")
    async def voice_turn(req: VoiceTurnRequest):
        started = time.monotonic()

        # Resolve the conversation id SERVER-SIDE. In PoC mode the caller does
        # not supply one at all, which is the point: Dograh v1.45 can only fill
        # tool parameters via the LLM, and an LLM must never choose the session
        # a conversation belongs to.
        persona = None

        # --- RECOVERY INTERCEPT ------------------------------------------
        # A recovery call is handled entirely here until TOTP succeeds. While
        # WAITING_FOR_OTP the utterance carries the spoken code, so it is
        # consumed by the state machine and NEVER forwarded to sd_chat.
        recovery_call = (
            recovery.get(req.call_id.strip())
            if (recovery is not None and req.call_id) else None
        )
        if recovery_call is not None:
            call_id = req.call_id.strip()
            handle = redact_call_id(call_id)
            outcome = recovery.handle_turn(call_id, req.text)
            # Read from the session AFTER the turn, so the log always shows the
            # state actually reached. Never includes a Duo transaction id.
            state_value = (outcome.state or recovery_call.state).value

            if not outcome.forward:
                # Consumed by the state machine: no ServiceDesk contact at all.
                # This is what keeps a spoken passcode out of sd_chat entirely.
                logger.info(
                    "turn call=%s recovery_state=%s forwarded=false",
                    handle, state_value,
                )
                return VoiceTurnResponse(
                    voice_session_id=call_id, text=outcome.speak or ""
                ).model_dump()

            # Verified: identity comes from the MAPPED RECORD bound to the
            # provider's user id, never from the caller and never from the LLM.
            identity = outcome.identity or {}
            persona = recovery.persona_for(identity)
            voice_session_id = call_id
            sd_session = auth_session_id(call_id)
            logger.info(
                "turn call=%s recovery_state=%s forwarded=true auth_method=%s",
                handle, state_value, identity.get("auth_method"),
            )

        elif settings.require_authenticated_identity:
            # Every failure below returns the SAME generic message and code.
            # Which check failed is written to the local log only; telling the
            # caller would hand an attacker a verification oracle.
            call_id = (req.call_id or "").strip()
            token = req.voice_identity_token or ""
            if not call_id or not token:
                logger.warning(
                    "turn rejected=IDENTITY_REQUIRED missing=%s",
                    "call_id" if not call_id else "token",
                )
                return _error("IDENTITY_REQUIRED", _AUTH_FAILED_TEXT, 401)
            try:
                claims = verify_identity_token(token, signing_secret, call_id)
            except IdentityTokenError as exc:
                logger.warning(
                    "turn call=%s token=%s rejected=IDENTITY_REJECTED reason=%s",
                    redact_call_id(call_id),
                    redact_token(token),
                    exc.reason,
                )
                return _error("IDENTITY_REJECTED", _AUTH_FAILED_TEXT, 401)

            # Only now is an identity trusted, and it comes from the verified
            # claims — never from req.verified_upn.
            persona = persona_from_claims(claims)
            voice_session_id = call_id
            sd_session = auth_session_id(call_id)
            handle = redact_call_id(call_id)
        elif settings.poc_single_session:
            voice_session_id = settings.poc_session_id
            sd_session = adk_session_id(voice_session_id)
            handle = redact_session_id(voice_session_id)
        elif req.voice_session_id:
            voice_session_id = req.voice_session_id
            sd_session = adk_session_id(voice_session_id)
            handle = redact_session_id(voice_session_id)
        else:
            return _error(
                "MISSING_VOICE_SESSION_ID",
                "The request could not be processed.",
                422,
            )

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

        # A verified_upn on the wire is ALWAYS an unverified assertion, in every
        # mode. It is dropped, never compared against the token and never
        # forwarded: the only identity that reaches ServiceDesk is the persona
        # built from verified token claims above. Dropping it silently (rather
        # than erroring) also denies a prober any signal that the field exists.
        if req.verified_upn:
            logger.warning(
                "turn session=%s discarding browser-supplied identity assertion",
                handle,
            )

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
                # The persona must be in state BEFORE the first user turn so the
                # existing identity_context_tool - which the agent is instructed
                # to call first - sees it. Nothing here bypasses that tool or
                # hard-codes a persona response.
                await sd.create_session(sd_session, persona=persona)
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
