"""Local employee identity map: spoken identifiers -> corporate + Duo identity.

This database answers exactly one question: *which single employee record, if
any, does this identifier select?* It is not an authentication store. Nothing
in it is a factor. `employee_id`, `upn`, `mobile_e164` and `display_name` are
aliases a caller may speak; Duo decides whether the caller is that person.

Two canonical keys anchor everything:

    corporate identity   entra_tenant_id + entra_object_id
    Duo binding          duo_user_id

Both are stable. A UPN is not - people marry, teams rename domains, and an
employee ID can be reissued in some HR systems. Binding authentication to the
UPN would mean a rename silently retargets a recovery call, so the UPN is
stored as an alias and the object id stays canonical.

Every lookup fails CLOSED. Zero matches and two matches produce the same
outcome, and the caller hears the same sentence either way, so probing this
database cannot reveal who is enrolled.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .identifiers import (
    IdentifierKind,
    SpokenIdentifier,
    mobile_candidates,
    normalize_employee_id,
    normalize_mobile,
    normalize_upn,
)

SCHEMA_VERSION = 1

DB_ENV = "RECOVERY_IDENTITY_DB"
RUNTIME = Path(__file__).resolve().parents[1] / "runtime"
DEFAULT_DB = RUNTIME / "recovery_identity.db"

# Enrollment lifecycle. Only ACTIVE, together with recovery_enabled, permits a
# recovery call to proceed.
STATUS_NONE = "NONE"
STATUS_PENDING = "PENDING"
STATUS_ACTIVE = "ACTIVE"

# Failure policy, counted per ACCOUNT rather than per call: starting a fresh
# recovery call must never hand an attacker a fresh budget.
MAX_FAILURES = 5
FAILURE_WINDOW_SECONDS = 600
LOCKOUT_SECONDS = 900


class IdentityMapError(RuntimeError):
    pass


class AmbiguousIdentifier(IdentityMapError):
    """More than one record matched. Never resolved by guessing."""


@dataclass
class EmployeeRecord:
    employee_id: str
    entra_tenant_id: str
    entra_object_id: str
    upn: str
    mobile_e164: Optional[str] = None
    display_name: Optional[str] = None
    duo_user_id: Optional[str] = None
    duo_username: Optional[str] = None
    duo_enrollment_status: str = STATUS_NONE
    duo_enrolled_at: Optional[str] = None
    duo_activation_code: Optional[str] = None
    recovery_enabled: int = 0
    recovery_failures: str = "[]"
    locked_until: Optional[float] = None
    created_at: str = ""
    updated_at: str = ""

    def recovery_ready(self) -> bool:
        return bool(
            self.recovery_enabled
            and self.duo_enrollment_status == STATUS_ACTIVE
            and self.duo_user_id
        )

    def redacted(self) -> str:
        """Log-safe handle. No UPN, no employee id, no mobile number."""
        return f"emp:{self.entra_object_id[:8]} duo:{(self.duo_user_id or '-')[:8]}"

    def failures(self) -> list[float]:
        try:
            data = json.loads(self.recovery_failures or "[]")
            return [float(x) for x in data] if isinstance(data, list) else []
        except (ValueError, TypeError):
            return []


_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS employee_identity_map (
    employee_id           TEXT PRIMARY KEY,
    entra_tenant_id       TEXT NOT NULL,
    entra_object_id       TEXT NOT NULL UNIQUE,
    upn                   TEXT NOT NULL UNIQUE,
    mobile_e164           TEXT UNIQUE,
    display_name          TEXT,
    duo_user_id           TEXT UNIQUE,
    duo_username          TEXT,
    duo_enrollment_status TEXT NOT NULL DEFAULT 'NONE',
    duo_enrolled_at       TEXT,
    duo_activation_code   TEXT,
    recovery_enabled      INTEGER NOT NULL DEFAULT 0,
    recovery_failures     TEXT NOT NULL DEFAULT '[]',
    locked_until          REAL,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);
"""

_COLUMNS = (
    "employee_id", "entra_tenant_id", "entra_object_id", "upn", "mobile_e164",
    "display_name", "duo_user_id", "duo_username", "duo_enrollment_status",
    "duo_enrolled_at", "duo_activation_code", "recovery_enabled",
    "recovery_failures", "locked_until", "created_at", "updated_at",
)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _default_calling_code() -> Optional[str]:
    """Environment first, then a runtime file, matching every other setting.

    Resolvable without an exported environment so one documented command starts
    the gateway. It is deliberately NOT defaulted in code: a wrong country code
    would silently make a caller's spoken mobile number match nobody, and
    guessing one is exactly what normalize_mobile refuses to do.
    """
    value = os.getenv("RECOVERY_DEFAULT_CALLING_CODE", "").strip()
    if value:
        return value.lstrip("+") or None
    path = RUNTIME / ".recovery_default_calling_code"
    if path.exists():
        return path.read_text().strip().lstrip("+") or None
    return None


class EmployeeIdentityMap:
    """File-backed map. One connection per operation, guarded by a lock."""

    def __init__(self, path: Optional[Path] = None,
                 default_calling_code: Optional[str] = None) -> None:
        self.path = Path(path or os.getenv(DB_ENV) or DEFAULT_DB)
        self.default_calling_code = default_calling_code or _default_calling_code()
        self._lock = threading.Lock()
        self._migrate()

    # -- schema ------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if not existed:
            # Owner-only from the moment the file exists. This database maps a
            # spoken digit run to a corporate identity; it is not secret in the
            # cryptographic sense, but it is a ready-made target list.
            os.chmod(self.path, 0o600)
        return conn

    def _migrate(self) -> None:
        """Create the schema deterministically and record its version."""
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)
            row = conn.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version (version) VALUES (?)",
                             (SCHEMA_VERSION,))
            elif int(row["version"]) > SCHEMA_VERSION:
                raise IdentityMapError(
                    f"identity map schema v{row['version']} is newer than this "
                    f"code (v{SCHEMA_VERSION}); refusing to open it"
                )
        os.chmod(self.path, 0o600)

    def schema_version(self) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT version FROM schema_version").fetchone()
            return int(row["version"]) if row else 0

    # -- writes ------------------------------------------------------------
    def upsert_employee(
        self,
        employee_id: str,
        entra_tenant_id: str,
        entra_object_id: str,
        upn: str,
        mobile: Optional[str] = None,
        display_name: Optional[str] = None,
    ) -> EmployeeRecord:
        """Provision or correct one mapping row. Administrative path only.

        Values are normalised HERE so the stored form and the lookup form are
        produced by the same code; a mismatch between the two would silently
        make an employee unreachable by recovery.
        """
        employee_id = normalize_employee_id(employee_id)
        upn = normalize_upn(upn)
        mobile_e164 = normalize_mobile(mobile, self.default_calling_code) if mobile else None
        tenant = str(entra_tenant_id or "").strip().lower()
        oid = str(entra_object_id or "").strip().lower()
        if not tenant or not oid:
            raise IdentityMapError("entra_tenant_id and entra_object_id are required")

        now = _now_iso()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO employee_identity_map
                    (employee_id, entra_tenant_id, entra_object_id, upn,
                     mobile_e164, display_name, duo_enrollment_status,
                     recovery_enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                ON CONFLICT(employee_id) DO UPDATE SET
                    entra_tenant_id = excluded.entra_tenant_id,
                    entra_object_id = excluded.entra_object_id,
                    upn             = excluded.upn,
                    mobile_e164     = excluded.mobile_e164,
                    display_name    = excluded.display_name,
                    updated_at      = excluded.updated_at
                """,
                (employee_id, tenant, oid, upn, mobile_e164, display_name,
                 STATUS_NONE, now, now),
            )
        record = self.get(employee_id)
        assert record is not None
        return record

    def bind_duo_user(self, employee_id: str, duo_user_id: str,
                      duo_username: Optional[str] = None,
                      activation_code: Optional[str] = None) -> None:
        """Record a PENDING Duo binding. Never marks the employee recoverable.

        Enrollment is not complete until Duo itself reports activation, so this
        deliberately leaves recovery_enabled at 0.

        `activation_code` is TEMPORARY enrollment material and is the only
        secret-like value this table ever holds. It is written here because the
        status poll must present it back to Duo, and it is destroyed the moment
        enrollment reaches a terminal state - see `activate_duo` and
        `invalidate_duo_enrollment`. `duo_user_id`, by contrast, is the
        permanent binding and outlives every enrollment attempt.
        """
        if not duo_user_id:
            raise IdentityMapError("duo_user_id is required")
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE employee_identity_map
                      SET duo_user_id = ?, duo_username = ?,
                          duo_activation_code = ?,
                          duo_enrollment_status = ?, recovery_enabled = 0,
                          updated_at = ?
                    WHERE employee_id = ?""",
                (duo_user_id, duo_username, activation_code, STATUS_PENDING,
                 _now_iso(), normalize_employee_id(employee_id)),
            )

    def activate_duo(self, employee_id: str) -> None:
        """Mark enrollment ACTIVE. Only ever called on a Duo "success" result.

        The activation code is destroyed in the SAME statement that flips the
        status, so there is no window in which an activated row still carries
        live enrollment material. It has served its only purpose by this point:
        Duo has confirmed the app was activated, and authentication from here
        on is by push or passcode against `duo_user_id`.
        """
        now = _now_iso()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE employee_identity_map
                      SET duo_enrollment_status = ?, duo_enrolled_at = ?,
                          duo_activation_code = NULL,
                          recovery_enabled = 1, updated_at = ?
                    WHERE employee_id = ? AND duo_user_id IS NOT NULL""",
                (STATUS_ACTIVE, now, now, normalize_employee_id(employee_id)),
            )

    def invalidate_duo_enrollment(self, employee_id: str) -> None:
        """Enrollment failed terminally: destroy the activation code.

        Duo reported the activation code as invalid — spent, expired, or never
        valid. It can never succeed now, so leaving it at rest would keep a dead
        secret in the database for no reason at all; the next enrollment mints a
        fresh one.

        `duo_user_id` is deliberately NOT cleared. It is the permanent Duo
        binding, and dropping it here would orphan the Duo-side user while the
        row silently became a candidate for a brand-new binding. The status
        returns to NONE and recovery_enabled to 0, so `recovery_ready()` is
        false and a recovery call for this employee gets the same generic
        sentence as an unknown one.
        """
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE employee_identity_map
                      SET duo_activation_code = NULL,
                          duo_enrollment_status = ?,
                          recovery_enabled = 0, updated_at = ?
                    WHERE employee_id = ?""",
                (STATUS_NONE, _now_iso(), normalize_employee_id(employee_id)),
            )

    def set_recovery_enabled(self, employee_id: str, enabled: bool) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE employee_identity_map SET recovery_enabled = ?, updated_at = ? "
                "WHERE employee_id = ?",
                (1 if enabled else 0, _now_iso(), normalize_employee_id(employee_id)),
            )

    # -- reads -------------------------------------------------------------
    def _row(self, conn: sqlite3.Connection, where: str,
             params: Iterable[Any]) -> list[EmployeeRecord]:
        rows = conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM employee_identity_map WHERE {where}",
            tuple(params),
        ).fetchall()
        return [EmployeeRecord(**dict(row)) for row in rows]

    def get(self, employee_id: str) -> Optional[EmployeeRecord]:
        with self._lock, self._connect() as conn:
            found = self._row(conn, "employee_id = ?", (str(employee_id).strip(),))
            return found[0] if found else None

    def by_object_id(self, entra_tenant_id: str, entra_object_id: str) -> Optional[EmployeeRecord]:
        """Canonical corporate lookup: tenant + object id."""
        with self._lock, self._connect() as conn:
            found = self._row(
                conn, "entra_tenant_id = ? AND entra_object_id = ?",
                (str(entra_tenant_id or "").strip().lower(),
                 str(entra_object_id or "").strip().lower()),
            )
            return found[0] if found else None

    def by_duo_user_id(self, duo_user_id: str) -> Optional[EmployeeRecord]:
        """Canonical Duo lookup - the ONLY identity source after Duo allows.

        Post-authentication identity is read through this method and no other.
        Deriving it from anything the caller spoke would make the whole Duo
        exchange decorative.
        """
        if not duo_user_id:
            return None
        with self._lock, self._connect() as conn:
            found = self._row(conn, "duo_user_id = ?", (str(duo_user_id).strip(),))
            return found[0] if found else None

    def lookup(self, identifier: SpokenIdentifier) -> Optional[EmployeeRecord]:
        """Select at most one candidate. Raises AmbiguousIdentifier on several.

        Returns None for "no match", which the caller must render identically
        to every other failure.
        """
        kind, value = identifier.kind, identifier.value
        with self._lock, self._connect() as conn:
            if kind is IdentifierKind.EMPLOYEE_ID:
                found = self._row(conn, "employee_id = ?", (value,))
            elif kind is IdentifierKind.UPN:
                found = self._row(conn, "upn = ?", (value,))
            elif kind is IdentifierKind.MOBILE:
                forms = mobile_candidates(value, self.default_calling_code)
                if not forms:
                    return None
                placeholders = ",".join("?" * len(forms))
                found = self._row(conn, f"mobile_e164 IN ({placeholders})", forms)
            else:
                # No cue word: the digits could be either kind. Both are tried
                # exactly; two different people matching is a hard failure.
                forms = mobile_candidates(value, self.default_calling_code)
                placeholders = ",".join("?" * len(forms)) if forms else "NULL"
                found = self._row(
                    conn,
                    f"employee_id = ? OR mobile_e164 IN ({placeholders})",
                    [value, *forms],
                )

        unique = {r.employee_id: r for r in found}
        if len(unique) > 1:
            raise AmbiguousIdentifier(
                f"{len(unique)} records match this identifier; refusing to guess"
            )
        return next(iter(unique.values()), None)

    # -- failure accounting ------------------------------------------------
    def is_locked(self, employee_id: str, now: Optional[float] = None) -> bool:
        record = self.get(employee_id)
        moment = now if now is not None else time.time()
        return bool(record and record.locked_until and moment < record.locked_until)

    def record_failure(self, employee_id: str, now: Optional[float] = None) -> bool:
        """Count one failed authentication. Returns True if now locked out.

        A newly generated passcode never clears the counter: it tracks attacker
        effort, not code freshness.
        """
        moment = now if now is not None else time.time()
        record = self.get(employee_id)
        if record is None:
            return False
        failures = [f for f in record.failures() if f >= moment - FAILURE_WINDOW_SECONDS]
        failures.append(moment)
        locked = record.locked_until
        if len(failures) >= MAX_FAILURES:
            locked = moment + LOCKOUT_SECONDS
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE employee_identity_map SET recovery_failures = ?, "
                "locked_until = ?, updated_at = ? WHERE employee_id = ?",
                (json.dumps(failures), locked, _now_iso(), record.employee_id),
            )
        return bool(locked and moment < locked)

    def clear_failures(self, employee_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE employee_identity_map SET recovery_failures = '[]', "
                "locked_until = NULL, updated_at = ? WHERE employee_id = ?",
                (_now_iso(), normalize_employee_id(employee_id)),
            )
