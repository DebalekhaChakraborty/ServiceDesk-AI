"""Administrative CLI for the local employee identity map.

Deliberately a separate entry point rather than an HTTP endpoint. Writing a row
here is what makes an employee eligible for voice recovery at all, so it needs a
shell on the host — not a route reachable from the Docker bridge that the Dograh
container shares.

    python -m voice_gateway.identity_map_admin upsert \
        --employee-id 1798283 \
        --tenant <tenant-guid> --object-id <oid> \
        --upn person@example.com --mobile +14155550123 \
        --display-name "Test Employee"

    python -m voice_gateway.identity_map_admin show --employee-id 1798283
    python -m voice_gateway.identity_map_admin list
    python -m voice_gateway.identity_map_admin disable --employee-id 1798283

`show` and `list` print REDACTED rows: enough to confirm a mapping exists and
what state its enrollment is in, without dumping a directory of employee ids,
UPNs and mobile numbers to a terminal or a log.
"""

from __future__ import annotations

import argparse
import sys

from .identifiers import IdentifierError
from .identity_map import EmployeeIdentityMap, IdentityMapError


def _mask(value: str | None, keep: int = 2) -> str:
    if not value:
        return "-"
    return value[:keep] + "…" + value[-keep:] if len(value) > keep * 2 else "…"


def _render(record) -> str:
    return (
        f"employee={_mask(record.employee_id)} "
        f"oid={record.entra_object_id[:8]} "
        f"upn={_mask(record.upn, 3)} "
        f"mobile={_mask(record.mobile_e164, 3)} "
        f"duo_user={_mask(record.duo_user_id, 3)} "
        f"status={record.duo_enrollment_status} "
        f"recovery_enabled={bool(record.recovery_enabled)}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity_map_admin")
    sub = parser.add_subparsers(dest="command", required=True)

    upsert = sub.add_parser("upsert", help="create or correct one mapping row")
    upsert.add_argument("--employee-id", required=True)
    upsert.add_argument("--tenant", required=True)
    upsert.add_argument("--object-id", required=True)
    upsert.add_argument("--upn", required=True)
    upsert.add_argument("--mobile")
    upsert.add_argument("--display-name")

    show = sub.add_parser("show", help="print one redacted row")
    show.add_argument("--employee-id", required=True)

    sub.add_parser("list", help="print all redacted rows")

    disable = sub.add_parser("disable", help="switch recovery off for one employee")
    disable.add_argument("--employee-id", required=True)

    args = parser.parse_args(argv)
    identity_map = EmployeeIdentityMap()

    try:
        if args.command == "upsert":
            record = identity_map.upsert_employee(
                employee_id=args.employee_id,
                entra_tenant_id=args.tenant,
                entra_object_id=args.object_id,
                upn=args.upn,
                mobile=args.mobile,
                display_name=args.display_name,
            )
            print(f"upserted: {_render(record)}")
            print(f"database: {identity_map.path} (schema v{identity_map.schema_version()})")
            return 0

        if args.command == "show":
            record = identity_map.get(args.employee_id)
            if record is None:
                print("no such employee", file=sys.stderr)
                return 1
            print(_render(record))
            return 0

        if args.command == "list":
            # Reads through the public API rather than a raw SELECT *, so this
            # cannot become the "log the whole map" path the design forbids.
            with identity_map._lock, identity_map._connect() as conn:  # noqa: SLF001
                ids = [r[0] for r in conn.execute(
                    "SELECT employee_id FROM employee_identity_map ORDER BY employee_id"
                ).fetchall()]
            for employee_id in ids:
                record = identity_map.get(employee_id)
                if record:
                    print(_render(record))
            print(f"{len(ids)} row(s)")
            return 0

        if args.command == "disable":
            identity_map.set_recovery_enabled(args.employee_id, False)
            print("recovery disabled")
            return 0
    except (IdentityMapError, IdentifierError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
