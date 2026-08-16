"""Encrypted store for pre-enrolled TOTP recovery credentials.

A TOTP seed is a permanent bearer credential for an identity: anyone holding it
can mint valid codes forever. It is therefore encrypted at rest with a
dedicated key, is never returned by any read path once enrollment completes,
and never reaches a log, Dograh, ServiceDesk, or a browser.

The store also owns the two properties that make a one-time code actually
one-time:

  * `last_timestep` - a consumed timestep can never be replayed, even while it
    is still inside its validity window.
  * failure counters - a wrong code costs the attacker attempts, and attempts
    are limited per window.

Storage is a single JSON file of per-account records, each with its own
encrypted seed. Fine for a PoC with designated test employees; a real
deployment wants a KMS-backed secret per employee and row-level access
control.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

STORE_ENV = "RECOVERY_STORE_PATH"
KEY_ENV = "RECOVERY_STORE_KEY"
DEFAULT_STORE = Path(__file__).resolve().parents[1] / "runtime" / "recovery_store.json"
KEY_FILE = Path(__file__).resolve().parents[1] / "runtime" / ".recovery_store_key"

# Rate limiting. Deliberately counted per ACCOUNT, not per call: starting a new
# recovery call must not hand an attacker a fresh budget.
MAX_FAILURES = 5
FAILURE_WINDOW_SECONDS = 600
LOCKOUT_SECONDS = 900

# Escalating delay applied after each failure, indexed by failure count.
BACKOFF_SECONDS = (0, 0, 1, 3, 8)


class RecoveryStoreError(RuntimeError):
    pass


class SecretCollision(RecoveryStoreError):
    """The recovery key is shared with another secret. Fail closed."""


@dataclass
class EnrollmentRecord:
    upn: str
    display_name: str
    object_id: Optional[str]
    encrypted_seed: str
    status: str = "pending"          # pending -> active (never back)
    created_at: float = field(default_factory=time.time)
    activated_at: Optional[float] = None
    last_timestep: Optional[int] = None
    failures: list[float] = field(default_factory=list)
    locked_until: Optional[float] = None

    def is_active(self) -> bool:
        return self.status == "active"


def account_key(upn: str) -> str:
    """Normalised lookup key. Case-insensitive, since UPNs are."""
    return (upn or "").strip().lower()


def redact_account(upn: str) -> str:
    """Log-safe handle for an account. The UPN itself is never logged."""
    return "acct:" + hashlib.sha256(account_key(upn).encode()).hexdigest()[:12]


def load_key() -> bytes:
    """Dedicated recovery-store key. Fails closed if it collides with another."""
    raw = os.getenv(KEY_ENV, "").strip()
    if not raw and KEY_FILE.exists():
        raw = KEY_FILE.read_text().strip()
    if not raw:
        raise RecoveryStoreError(
            f"no recovery store key: set {KEY_ENV} or create {KEY_FILE} (mode 0600)"
        )
    _assert_no_collision(raw)
    return raw.encode()


def _assert_no_collision(candidate: str) -> None:
    """Refuse to run if the recovery key equals any other secret we hold.

    Reusing one secret across two systems means a leak in either compromises
    both, and rotating one silently breaks the other.
    """
    runtime = Path(__file__).resolve().parents[1] / "runtime"
    others: dict[str, str] = {}
    for name, path in (
        ("voice identity signing secret", runtime / ".voice_identity_secret"),
        ("Dograh API key", runtime / ".dograh_api_key"),
        ("portal session secret",
         Path(__file__).resolve().parents[2] / "employee_access_portal" / "runtime" / ".portal_session_secret"),
    ):
        if path.exists():
            others[name] = path.read_text().strip()

    env_file = runtime / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" not in line or line.strip().startswith("#"):
                continue
            key, _, value = line.partition("=")
            if key.strip() in {"TURN_SECRET", "OSS_JWT_SECRET", "POSTGRES_PASSWORD",
                               "REDIS_PASSWORD", "MINIO_ROOT_PASSWORD"}:
                others[key.strip()] = value.strip()

    for name, value in others.items():
        if value and value == candidate:
            raise SecretCollision(
                f"the recovery store key is identical to the {name}. "
                "Each secret must be independent; refusing to start."
            )


def generate_key() -> str:
    return Fernet.generate_key().decode()


def enrollment_admin_key(key: Optional[bytes] = None) -> str:
    """Key that authorises ENROLLMENT calls, derived from the store key.

    Why this exists: the gateway listens on the Docker bridge so the Dograh
    container can reach /voice/turn. That same address is reachable by every
    container on the host - including Dograh, which executes LLM-driven tool
    calls. Without this check, anything on the bridge could enroll a recovery
    credential for an arbitrary UPN and then "recover" as that person.

    A derived subkey rather than a new secret file: same pattern the portal
    already uses to split its session and transaction keys, so there is one
    secret to rotate rather than two that can drift apart.
    """
    material = key or load_key()
    return base64.urlsafe_b64encode(
        hashlib.blake2b(material, key=b"enrollment-admin", digest_size=32).digest()
    ).decode().rstrip("=")


class RecoveryStore:
    """Thread-safe, file-backed store. Seeds are only ever decrypted in memory."""

    def __init__(self, path: Optional[Path] = None, key: Optional[bytes] = None) -> None:
        self.path = Path(path or os.getenv(STORE_ENV) or DEFAULT_STORE)
        self._fernet = Fernet(key or load_key())
        self._lock = threading.Lock()

    # -- persistence -------------------------------------------------------
    def _read(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text() or "{}")

    def _write(self, data: dict[str, dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.chmod(0o600)
        tmp.replace(self.path)
        self.path.chmod(0o600)

    def _get(self, upn: str) -> Optional[EnrollmentRecord]:
        raw = self._read().get(account_key(upn))
        return EnrollmentRecord(**raw) if raw else None

    def _put(self, record: EnrollmentRecord) -> None:
        data = self._read()
        data[account_key(record.upn)] = asdict(record)
        self._write(data)

    # -- enrollment --------------------------------------------------------
    def begin_enrollment(self, upn: str, display_name: str,
                         object_id: Optional[str] = None) -> tuple[str, str]:
        """Create a PENDING enrollment and return (seed, otpauth_uri).

        This is the ONLY moment the seed leaves the store. It is shown once so
        the employee can add it to an authenticator app, and never again.
        """
        from .totp import generate_seed, provisioning_uri

        with self._lock:
            seed = generate_seed()
            record = EnrollmentRecord(
                upn=upn.strip(),
                display_name=display_name or upn,
                object_id=object_id,
                encrypted_seed=self._fernet.encrypt(seed.encode()).decode(),
                status="pending",
            )
            self._put(record)
            return seed, provisioning_uri(seed, upn.strip())

    def activate(self, upn: str, code: str, now: Optional[float] = None) -> bool:
        """Activate only on proof of a working authenticator.

        An enrollment nobody can generate codes for is worse than none: it
        looks like a recovery path and is not one.
        """
        from .totp import find_matching_timestep

        with self._lock:
            record = self._get(upn)
            if record is None or record.status not in ("pending", "active"):
                return False
            seed = self._decrypt(record)
            step = find_matching_timestep(seed, code, now)
            if step is None:
                return False
            record.status = "active"
            record.activated_at = time.time()
            record.last_timestep = step      # proof code is itself consumed
            self._put(record)
            return True

    def _decrypt(self, record: EnrollmentRecord) -> str:
        try:
            return self._fernet.decrypt(record.encrypted_seed.encode()).decode()
        except InvalidToken as exc:
            raise RecoveryStoreError("recovery seed could not be decrypted") from exc

    # -- verification ------------------------------------------------------
    def status_for(self, upn: str) -> Optional[str]:
        record = self._get(upn)
        return record.status if record else None

    def verify(self, upn: str, code: str, now: Optional[float] = None) -> tuple[bool, str]:
        """Verify one spoken code. Returns (ok, category).

        Category is coarse and for local logs only; every caller-visible
        message must be identical so an un-enrolled account cannot be
        distinguished from a wrong code.
        """
        from .totp import find_matching_timestep

        moment = now if now is not None else time.time()
        with self._lock:
            record = self._get(upn)

            # Unknown account: same shape and cost as a wrong code.
            if record is None or not record.is_active():
                return False, "not_enrolled"

            if record.locked_until and moment < record.locked_until:
                return False, "locked"

            seed = self._decrypt(record)
            step = find_matching_timestep(seed, code, moment)

            if step is None:
                self._record_failure(record, moment)
                return False, "bad_code"

            # One-time use: a timestep already consumed can never be reused,
            # even though it is still inside its validity window. This is what
            # makes an overheard or recorded code useless.
            if record.last_timestep is not None and step <= record.last_timestep:
                self._record_failure(record, moment)
                return False, "replayed"

            record.last_timestep = step
            record.failures = []
            record.locked_until = None
            self._put(record)
            return True, "ok"

    def _record_failure(self, record: EnrollmentRecord, moment: float) -> None:
        window_start = moment - FAILURE_WINDOW_SECONDS
        # Only failures inside the window count, but a NEW code being generated
        # never clears them: the counter tracks attacker effort, not code age.
        record.failures = [f for f in record.failures if f >= window_start]
        record.failures.append(moment)
        if len(record.failures) >= MAX_FAILURES:
            record.locked_until = moment + LOCKOUT_SECONDS
        self._put(record)

    def backoff_seconds(self, upn: str) -> float:
        """Escalating delay after repeated failures."""
        record = self._get(upn)
        if record is None or not record.failures:
            return 0.0
        index = min(len(record.failures), len(BACKOFF_SECONDS)) - 1
        return float(BACKOFF_SECONDS[index])

    def identity_for(self, upn: str) -> Optional[dict[str, Any]]:
        """Trusted identity from the ENROLLMENT RECORD, never from the caller."""
        record = self._get(upn)
        if record is None or not record.is_active():
            return None
        return {
            "upn": record.upn,
            "display_name": record.display_name,
            "object_id": record.object_id,
        }
