"""The narrow MFA contract the recovery state machine is allowed to use.

Deliberately a small, closed set of named operations rather than a general
"call the MFA API" method. The gateway is reachable from the Dograh container,
which runs LLM-driven tool code; a generic request method there would be an
arbitrary-API primitive one prompt injection away from being used. Every
operation below is one this flow actually needs, with a fixed shape.

The abstraction also keeps the state machine testable without a Duo tenant, and
keeps a future provider swap from touching the state machine at all.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

# Duo capability strings, quoted so a typo is a NameError rather than a silent
# "this device cannot push".
CAP_PUSH = "push"
CAP_MOBILE_OTP = "mobile_otp"

# Duo preauth results.
PREAUTH_AUTH = "auth"        # proceed to a factor
PREAUTH_ALLOW = "allow"      # policy bypass - NOT accepted for recovery
PREAUTH_DENY = "deny"
PREAUTH_ENROLL = "enroll"    # no Duo enrollment

# Duo auth / auth_status results.
RESULT_ALLOW = "allow"
RESULT_DENY = "deny"
RESULT_WAITING = "waiting"


class MfaProviderError(RuntimeError):
    """A provider call failed. `code` is coarse and safe to log.

    Provider messages can echo request parameters - including a username - so
    only the code is ever carried into logs or responses.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProviderCheck:
    ok: bool
    reason: str = ""


@dataclass(frozen=True)
class EnrollmentTicket:
    """One pending enrollment. The barcode URL is Duo's own QR endpoint."""
    user_id: str
    activation_code: str
    activation_barcode_url: Optional[str] = None
    expires_at: Optional[int] = None
    username: Optional[str] = None


@dataclass(frozen=True)
class EnrollmentStatus:
    # "success" | "waiting" | "invalid"
    state: str


@dataclass(frozen=True)
class Device:
    device_id: str
    display_name: str = ""
    device_type: str = ""
    capabilities: frozenset[str] = field(default_factory=frozenset)

    def can_push(self) -> bool:
        return CAP_PUSH in self.capabilities

    def can_passcode(self) -> bool:
        return CAP_MOBILE_OTP in self.capabilities


@dataclass(frozen=True)
class PreauthResult:
    result: str
    devices: tuple[Device, ...] = ()

    def push_device(self) -> Optional[Device]:
        """First push-capable device, or None.

        Capability comes from THIS live preauth response, never from the local
        map: a stale local record must not decide what factors are available.
        """
        return next((d for d in self.devices if d.can_push()), None)

    def has_passcode_device(self) -> bool:
        return any(d.can_passcode() for d in self.devices)


@dataclass(frozen=True)
class PushHandle:
    """Server-side handle for an async push. Never leaves the gateway."""
    txid: str


@dataclass(frozen=True)
class AuthResult:
    result: str            # allow | deny | waiting
    status: str = ""       # provider status token, safe to log


class RecoveryMfaProvider(ABC):
    """Everything the recovery state machine may ask an MFA provider to do."""

    name: str = "abstract"

    @abstractmethod
    def check(self) -> ProviderCheck:
        """Connectivity and credential validation. Recovery stays off if false."""

    @abstractmethod
    def enroll(self, valid_secs: int = 3600,
               username: Optional[str] = None) -> EnrollmentTicket:
        """Create a pending enrollment and return its activation material."""

    @abstractmethod
    def enroll_status(self, user_id: str, activation_code: str) -> EnrollmentStatus:
        """Has the employee actually activated the app? Authoritative answer."""

    @abstractmethod
    def preauth(self, user_id: str) -> PreauthResult:
        """Current device inventory and capabilities for one bound user."""

    @abstractmethod
    def start_push(self, user_id: str, device_id: str) -> PushHandle:
        """Send an async push. Returns the transaction handle."""

    @abstractmethod
    def poll_push(self, txid: str) -> AuthResult:
        """One bounded poll of an outstanding push transaction."""

    @abstractmethod
    def verify_passcode(self, user_id: str, passcode: str) -> AuthResult:
        """Verify a passcode. The passcode is never logged by any implementation."""
