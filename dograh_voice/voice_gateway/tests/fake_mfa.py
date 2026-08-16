"""In-memory MFA provider for tests. NOT importable from the running gateway.

Lives under tests/ on purpose. A fake that always allows would be a complete
authentication bypass if it were ever reachable from production code, so it is
kept outside the `voice_gateway` package entirely — nothing in the shipped
package can import it.

It records every call so tests can assert on what the state machine actually
asked the provider to do, including the arguments it must never pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from voice_gateway.mfa_provider import (
    AuthResult,
    CAP_MOBILE_OTP,
    CAP_PUSH,
    Device,
    EnrollmentStatus,
    EnrollmentTicket,
    MfaProviderError,
    PREAUTH_AUTH,
    PreauthResult,
    ProviderCheck,
    PushHandle,
    RecoveryMfaProvider,
)


@dataclass
class FakeMfaProvider(RecoveryMfaProvider):
    name: str = "fake"

    check_ok: bool = True
    check_reason: str = ""

    # Enrollment
    enroll_user_id: str = "duo-user-fake-1"
    enroll_activation_code: str = "activation-code-1"
    enroll_barcode: Optional[str] = "https://api-fake0001.duosecurity.com/frame/qr?value=x"
    enroll_status_state: str = "waiting"

    # Preauth
    preauth_result: str = PREAUTH_AUTH
    devices: tuple[Device, ...] = (
        Device(device_id="DEV1", display_name="iPhone",
               capabilities=frozenset({CAP_PUSH, CAP_MOBILE_OTP})),
    )

    # Auth outcomes. `push_results` is consumed one poll at a time so a test can
    # spell out "waiting, waiting, allow".
    push_results: list[str] = field(default_factory=lambda: ["allow"])
    passcode_result: str = "allow"
    raise_on: Optional[str] = None

    calls: list[tuple] = field(default_factory=list)
    _txid_counter: int = 0

    def _maybe_raise(self, operation: str) -> None:
        if self.raise_on == operation:
            raise MfaProviderError("DUO_UNREACHABLE", operation)

    def check(self) -> ProviderCheck:
        self.calls.append(("check",))
        return ProviderCheck(ok=self.check_ok, reason=self.check_reason)

    def enroll(self, valid_secs: int = 3600,
               username: Optional[str] = None) -> EnrollmentTicket:
        self.calls.append(("enroll", valid_secs, username))
        self._maybe_raise("enroll")
        return EnrollmentTicket(
            user_id=self.enroll_user_id,
            activation_code=self.enroll_activation_code,
            activation_barcode_url=self.enroll_barcode,
            expires_at=1_800_000_000,
        )

    def enroll_status(self, user_id: str, activation_code: str) -> EnrollmentStatus:
        self.calls.append(("enroll_status", user_id, activation_code))
        self._maybe_raise("enroll_status")
        return EnrollmentStatus(state=self.enroll_status_state)

    def preauth(self, user_id: str) -> PreauthResult:
        self.calls.append(("preauth", user_id))
        self._maybe_raise("preauth")
        return PreauthResult(result=self.preauth_result, devices=self.devices)

    def start_push(self, user_id: str, device_id: str) -> PushHandle:
        self.calls.append(("start_push", user_id, device_id))
        self._maybe_raise("start_push")
        self._txid_counter += 1
        return PushHandle(txid=f"txid-secret-{self._txid_counter}")

    def poll_push(self, txid: str) -> AuthResult:
        self.calls.append(("poll_push", txid))
        self._maybe_raise("poll_push")
        result = self.push_results[0] if len(self.push_results) == 1 else (
            self.push_results.pop(0) if self.push_results else "waiting"
        )
        return AuthResult(result=result, status=result)

    def verify_passcode(self, user_id: str, passcode: str) -> AuthResult:
        self.calls.append(("verify_passcode", user_id, passcode))
        self._maybe_raise("verify_passcode")
        return AuthResult(result=self.passcode_result, status=self.passcode_result)

    def fetch_activation_qr(self, barcode_url: str) -> tuple[str, bytes]:
        self.calls.append(("fetch_activation_qr", barcode_url))
        self._maybe_raise("fetch_activation_qr")
        return "image/png", b"\x89PNG\r\n\x1a\nFAKE"

    # -- helpers for assertions -------------------------------------------
    def called(self, operation: str) -> list[tuple]:
        return [c for c in self.calls if c[0] == operation]
