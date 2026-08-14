#!/usr/bin/env python3
"""
Operator CLI for the controlled lab network fault (PoC demonstration only).

    sudo python3 scripts/gcp_vdi_demo_netfaultctl.py up
    sudo python3 scripts/gcp_vdi_demo_netfaultctl.py enable --delay-ms 250
         python3 scripts/gcp_vdi_demo_netfaultctl.py status
    sudo python3 scripts/gcp_vdi_demo_netfaultctl.py disable

`enable` is rejected by the daemon unless the calling peer is root, which is
what keeps the unprivileged ServiceDesk backend structurally unable to create
the impairment. `status` and `disable` work unprivileged for the backend group.

This is a PoC demonstration mechanism, not the customer's production network
control plane.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys

SOCKET_PATH = "/run/servicedesk-vdi-demo/netfault.sock"


def call(payload: dict, socket_path: str = SOCKET_PATH) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(15)
        sock.connect(socket_path)
        sock.sendall(json.dumps(payload).encode("utf-8"))
        return json.loads(sock.recv(8192).decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=SOCKET_PATH)
    sub = parser.add_subparsers(dest="action", required=True)

    sub.add_parser("status", help="read controlled fault status")
    sub.add_parser("up", help="create the isolated demo namespace (no impairment)")
    sub.add_parser("teardown", help="operator only: remove namespace and all scoped rules")

    enable = sub.add_parser("enable", help="operator only: apply controlled impairment")
    enable.add_argument("--delay-ms", type=int, default=250)
    enable.add_argument("--ttl-seconds", type=int, default=15 * 60)

    disable = sub.add_parser("disable", help="remove controlled impairment")
    disable.add_argument("--fault-id", default=None)

    args = parser.parse_args()

    if args.action == "status":
        payload = {"command": "status"}
    elif args.action == "up":
        # `up` is expressed as an enable/disable pair so the daemon remains the
        # only component that ever touches privileged networking.
        payload = {"command": "enable", "delay_ms": 50, "ttl_seconds": 60}
        result = call(payload, args.socket)
        if not result.get("ok"):
            print(json.dumps(result, indent=2))
            return 1
        payload = {"command": "disable"}
    elif args.action == "enable":
        payload = {
            "command": "enable",
            "delay_ms": args.delay_ms,
            "ttl_seconds": args.ttl_seconds,
        }
    elif args.action == "teardown":
        payload = {"command": "teardown"}
    else:
        payload = {"command": "disable"}
        if args.fault_id:
            payload["fault_id"] = args.fault_id

    try:
        result = call(payload, args.socket)
    except FileNotFoundError:
        print(f"control socket not found at {args.socket}; is the daemon running?", file=sys.stderr)
        return 2
    except PermissionError:
        print(f"permission denied on {args.socket}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
