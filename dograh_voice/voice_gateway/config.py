"""Gateway configuration. Everything is env-overridable; defaults are the safe ones."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

# The ServiceDesk ADK app name. Discovered from the running server's /list-apps.
DEFAULT_APP_NAME = "sd_chat"

# ADK user_id namespace for the voice channel.
#
# This is a CHANNEL NAMESPACE, not an identity claim. There is no caller
# verification yet, so the gateway must never place a real UPN here, and never
# seeds session state with a persona. resolve_identity_context therefore
# continues to report ok=false exactly as it does for an unauthenticated caller.
DEFAULT_USER_ID = "voice-channel"

DEFAULT_POC_SESSION_ID = "dograh-poc-voice"

# Session id prefix for authenticated calls, kept distinct from the PoC prefix
# so the two can never collide in the ADK session namespace.
AUTH_SESSION_PREFIX = "voice-auth-"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    servicedesk_base_url: str
    app_name: str
    user_id: str
    timeout_seconds: float
    max_text_chars: int
    log_utterances: bool
    poc_single_session: bool
    poc_session_id: str
    require_authenticated_identity: bool
    identity_token_max_ttl_seconds: int
    # Which MFA provider performs recovery authentication. "duo" is the only
    # supported value; "totp" selects the retired self-hosted verifier and is
    # kept solely so the pre-Duo path can be re-enabled during acceptance.
    recovery_provider: str = "duo"
    # ESCAPE HATCH — tests and local experiments only. Permits the retired
    # pre-Phase-5 behaviour where the caller supplies its own voice_session_id
    # with no identity proof. Never set by any launch script or deployment.
    allow_legacy_unauthenticated: bool = False

    def is_loopback_bind(self) -> bool:
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return self.host == "localhost"

    def is_private_bind(self) -> bool:
        """True only when the bind address cannot be reached from the internet.

        Uses real address classification rather than string prefixes: "172." is
        NOT a reliable private marker (172.32.0.0/12 upward is public), and an
        unspecified address such as 0.0.0.0 must always be rejected.
        """
        if self.host == "localhost":
            return True
        try:
            addr = ipaddress.ip_address(self.host)
        except ValueError:
            return False
        if addr.is_unspecified:  # 0.0.0.0 / ::
            return False
        return addr.is_loopback or addr.is_private


def load_settings() -> Settings:
    return Settings(
        # Default is loopback. For the Dograh container to reach the gateway this
        # is set to the VERIFIED docker bridge gateway address (see README).
        # app.py refuses to start on anything non-private.
        host=os.getenv("VOICE_GATEWAY_HOST", "127.0.0.1"),
        port=int(os.getenv("VOICE_GATEWAY_PORT", "8010")),
        servicedesk_base_url=os.getenv(
            "SERVICEDESK_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/"),
        app_name=os.getenv("SERVICEDESK_APP_NAME", DEFAULT_APP_NAME),
        user_id=os.getenv("SERVICEDESK_USER_ID", DEFAULT_USER_ID),
        timeout_seconds=float(os.getenv("SERVICEDESK_TIMEOUT_SECONDS", "120")),
        max_text_chars=int(os.getenv("VOICE_GATEWAY_MAX_TEXT_CHARS", "4000")),
        # Off by default: caller utterances are not written to logs.
        log_utterances=_env_bool("VOICE_GATEWAY_LOG_UTTERANCES", False),
        # PoC SINGLE SESSION MODE — single tester only. See README warning.
        poc_single_session=_env_bool("VOICE_GATEWAY_POC_SINGLE_SESSION", False),
        poc_session_id=os.getenv("VOICE_GATEWAY_POC_SESSION_ID", DEFAULT_POC_SESSION_ID),
        # AUTHENTICATED MODE (default ON). Every turn must carry a call_id and a
        # portal-signed identity token. Turning this off drops the gateway back
        # to the unauthenticated PoC behaviour and is refused whenever
        # poc_single_session is also off, so there is no anonymous multi-caller
        # configuration.
        require_authenticated_identity=_env_bool(
            "VOICE_GATEWAY_REQUIRE_AUTH", True
        ),
        identity_token_max_ttl_seconds=int(
            os.getenv("VOICE_GATEWAY_IDENTITY_MAX_TTL", "900")
        ),
        allow_legacy_unauthenticated=_env_bool(
            "VOICE_GATEWAY_ALLOW_LEGACY_UNAUTHENTICATED", False
        ),
        recovery_provider=os.getenv("RECOVERY_PROVIDER", "duo").strip().lower(),
    )
