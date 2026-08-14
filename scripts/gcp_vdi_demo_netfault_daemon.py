#!/usr/bin/env python3
"""
CONTROLLED LAB NETWORK FAULT DAEMON — PoC DEMONSTRATION MECHANISM ONLY.

This daemon owns the ONLY privileged operation in the GCP virtual-desktop PoC
latency demonstration: applying and removing a bounded netem delay on an
isolated network namespace that carries nothing except the demo RDP proxy.

It is NOT the customer's production network control plane. In production the
Session Network Recovery action would integrate with the customer's authorized
network automation platform instead of this daemon.

Security model
--------------
* Fixed JSON command schema. No shell, no command, no qdisc, no interface,
  no IP, no port, and no free-form argument is ever accepted from a client.
* `enable` requires peer UID 0 (kernel-enforced via SO_PEERCRED). The
  ServiceDesk backend runs unprivileged and is therefore structurally unable
  to create the fault, which is the security boundary the PoC requires.
* `status` and `disable` are available to the backend group so the agent can
  observe and remove — but never create — the controlled impairment.
* The impairment lives inside a dedicated network namespace. Host traffic
  (ServiceDesk backend, frontend, Google APIs, WinRM, SSH/IAP) traverses the
  primary interface and is physically unaffected by the namespace qdisc.

Fail-safe
---------
The fault carries a hard expiry (default 15 minutes, ceiling 30 minutes). A
watchdog thread removes it on expiry, and the daemon removes it on shutdown.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pwd
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Fixed configuration. None of these are client-supplied.
# ---------------------------------------------------------------------------

NETNS = "sdvdi-demo"
VETH_HOST = "sdvdi-h"
VETH_NS = "sdvdi-n"
HOST_ADDR = "10.99.99.1"
NS_ADDR = "10.99.99.2"
SUBNET = "10.99.99.0/30"
PREFIX = 30

RUN_DIR = "/run/servicedesk-vdi-demo"
SOCKET_PATH = os.path.join(RUN_DIR, "netfault.sock")
STATE_PATH = os.path.join(RUN_DIR, "state.json")

DEFAULT_DELAY_MS = 250
MIN_DELAY_MS = 50
MAX_DELAY_MS = 600

DEFAULT_TTL_SECONDS = 15 * 60
MAX_TTL_SECONDS = 30 * 60

STATE_DISABLED = "DISABLED"
STATE_HEALTHY = "HEALTHY"
STATE_FAULT_ACTIVE = "FAULT_ACTIVE"
STATE_RECOVERING = "RECOVERING"

IP = "/sbin/ip"
TC = "/sbin/tc"
IPTABLES = "/sbin/iptables"
SYSCTL = "/sbin/sysctl"

LOG = logging.getLogger("netfaultd")


# ---------------------------------------------------------------------------
# Privileged primitives. Every argv is a fixed list; shell is never used.
# ---------------------------------------------------------------------------


def _run(argv: List[str], check: bool = True) -> subprocess.CompletedProcess:
    LOG.debug("exec %s", " ".join(argv))
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(argv)}: {proc.stderr.strip()}")
    return proc


def _in_ns(argv: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return _run([IP, "netns", "exec", NETNS] + argv, check=check)


def _netns_exists() -> bool:
    proc = _run([IP, "netns", "list"], check=False)
    return any(line.split()[0] == NETNS for line in proc.stdout.splitlines() if line.strip())


def _netem_present() -> bool:
    if not _netns_exists():
        return False
    proc = _in_ns([TC, "qdisc", "show", "dev", VETH_NS], check=False)
    return "netem" in proc.stdout


def _masquerade_rule() -> List[str]:
    return ["-t", "nat", "-s", SUBNET, "-o", _uplink(), "-j", "MASQUERADE"]


_UPLINK_CACHE: Optional[str] = None


def _uplink() -> str:
    """Resolve the default-route interface once; never client-supplied."""
    global _UPLINK_CACHE
    if _UPLINK_CACHE:
        return _UPLINK_CACHE
    proc = _run([IP, "-o", "route", "get", "8.8.8.8"], check=True)
    parts = proc.stdout.split()
    _UPLINK_CACHE = parts[parts.index("dev") + 1]
    return _UPLINK_CACHE


def _masq_exists() -> bool:
    proc = _run([IPTABLES, "-t", "nat", "-C", "POSTROUTING", "-s", SUBNET, "-o", _uplink(), "-j", "MASQUERADE"], check=False)
    return proc.returncode == 0


# The host FORWARD policy is DROP. These two rules are the minimum needed for
# the namespace to reach the trusted workstation, and they are scoped to the
# /30 veth subnet only. They open no inbound access and are removed on teardown.
def _forward_rules() -> List[List[str]]:
    uplink = _uplink()
    return [
        ["FORWARD", "-s", SUBNET, "-o", uplink, "-j", "ACCEPT"],
        ["FORWARD", "-d", SUBNET, "-i", uplink, "-m", "conntrack",
         "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]


def _rule_exists(rule: List[str]) -> bool:
    return _run([IPTABLES, "-C"] + rule, check=False).returncode == 0


def harness_up() -> None:
    """Create the isolated namespace that carries only the demo proxy."""
    if not _netns_exists():
        _run([IP, "netns", "add", NETNS])
        LOG.info("created netns %s", NETNS)

    existing = _run([IP, "-o", "link", "show"], check=False).stdout
    if VETH_HOST not in existing:
        _run([IP, "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS])
        _run([IP, "link", "set", VETH_NS, "netns", NETNS])
        _run([IP, "addr", "add", f"{HOST_ADDR}/{PREFIX}", "dev", VETH_HOST])
        _run([IP, "link", "set", VETH_HOST, "up"])
        _in_ns([IP, "addr", "add", f"{NS_ADDR}/{PREFIX}", "dev", VETH_NS])
        _in_ns([IP, "link", "set", VETH_NS, "up"])
        _in_ns([IP, "link", "set", "lo", "up"])
        _in_ns([IP, "route", "add", "default", "via", HOST_ADDR])
        LOG.info("created veth pair %s <-> %s", VETH_HOST, VETH_NS)

    if not _masq_exists():
        _run([IPTABLES, "-t", "nat", "-A", "POSTROUTING", "-s", SUBNET, "-o", _uplink(), "-j", "MASQUERADE"])
        LOG.info("added scoped MASQUERADE for %s via %s", SUBNET, _uplink())

    for rule in _forward_rules():
        if not _rule_exists(rule):
            _run([IPTABLES, "-A"] + rule)
            LOG.info("added scoped FORWARD rule: %s", " ".join(rule))


def harness_down() -> None:
    """Remove the namespace and the single scoped NAT rule we added."""
    remove_delay()
    for rule in _forward_rules():
        while _rule_exists(rule):
            _run([IPTABLES, "-D"] + rule, check=False)
            LOG.info("removed scoped FORWARD rule: %s", " ".join(rule))
    if _masq_exists():
        _run([IPTABLES, "-t", "nat", "-D", "POSTROUTING", "-s", SUBNET, "-o", _uplink(), "-j", "MASQUERADE"], check=False)
        LOG.info("removed scoped MASQUERADE")
    if _netns_exists():
        _run([IP, "netns", "del", NETNS], check=False)
        LOG.info("removed netns %s", NETNS)
    existing = _run([IP, "-o", "link", "show"], check=False).stdout
    if VETH_HOST in existing:
        _run([IP, "link", "del", VETH_HOST], check=False)


def apply_delay(delay_ms: int) -> None:
    """Apply netem INSIDE the namespace. Cannot touch host interfaces."""
    if _netem_present():
        _in_ns([TC, "qdisc", "change", "dev", VETH_NS, "root", "netem", "delay", f"{delay_ms}ms"])
    else:
        _in_ns([TC, "qdisc", "add", "dev", VETH_NS, "root", "netem", "delay", f"{delay_ms}ms"])
    LOG.info("netem delay %sms applied on %s inside %s", delay_ms, VETH_NS, NETNS)


def remove_delay() -> None:
    if _netem_present():
        _in_ns([TC, "qdisc", "del", "dev", VETH_NS, "root"], check=False)
        LOG.info("netem delay removed from %s inside %s", VETH_NS, NETNS)


# ---------------------------------------------------------------------------
# Daemon state
# ---------------------------------------------------------------------------


class FaultState:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.fault_id: Optional[str] = None
        self.delay_ms: Optional[int] = None
        self.enabled_at: Optional[float] = None
        self.expires_at: Optional[float] = None
        self.state: str = STATE_DISABLED
        self.refresh()

    def refresh(self) -> None:
        with self._lock:
            if not _netns_exists():
                self.state = STATE_DISABLED
            elif _netem_present():
                self.state = STATE_FAULT_ACTIVE
            else:
                self.state = STATE_HEALTHY
                self.fault_id = None
                self.delay_ms = None
                self.enabled_at = None
                self.expires_at = None

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            self.refresh()
            now = time.time()
            return {
                "state": self.state,
                "fault_id": self.fault_id,
                "delay_ms": self.delay_ms,
                "enabled_at": self.enabled_at,
                "expires_at": self.expires_at,
                "seconds_remaining": (
                    max(0, int(self.expires_at - now)) if self.expires_at else None
                ),
                "netns": NETNS,
                "isolation": "network_namespace",
                "mechanism": "controlled_lab_poc",
            }

    def enable(self, delay_ms: int, ttl_seconds: int) -> Dict[str, Any]:
        with self._lock:
            harness_up()
            apply_delay(delay_ms)
            # Idempotent: re-enabling refreshes the window but keeps one fault id.
            if self.state != STATE_FAULT_ACTIVE or not self.fault_id:
                self.fault_id = f"fault-{uuid.uuid4()}"
                self.enabled_at = time.time()
            self.delay_ms = delay_ms
            self.expires_at = time.time() + ttl_seconds
            self.state = STATE_FAULT_ACTIVE
            self._persist()
            return self.snapshot()

    def disable(self, fault_id: Optional[str]) -> Tuple[bool, str, Dict[str, Any]]:
        with self._lock:
            self.refresh()
            if self.state != STATE_FAULT_ACTIVE:
                # Idempotent: nothing to remove is a success, not an error.
                return True, "no_active_fault", self.snapshot()
            if fault_id is not None and fault_id != self.fault_id:
                return False, "fault_id_mismatch", self.snapshot()
            self.state = STATE_RECOVERING
            remove_delay()
            self.fault_id = None
            self.delay_ms = None
            self.enabled_at = None
            self.expires_at = None
            self.state = STATE_HEALTHY
            self._persist()
            return True, "fault_removed", self.snapshot()

    def _persist(self) -> None:
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w") as handle:
            json.dump(self.snapshot(), handle)
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_PATH)


# ---------------------------------------------------------------------------
# Control socket
# ---------------------------------------------------------------------------


def _peer_credentials(conn: socket.socket) -> Tuple[int, int, int]:
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", creds)
    return pid, uid, gid


def _handle(payload: Dict[str, Any], peer_uid: int, state: FaultState) -> Dict[str, Any]:
    command = payload.get("command")

    if command == "status":
        return {"ok": True, "command": "status", **state.snapshot()}

    if command == "enable":
        # SECURITY BOUNDARY: only a root peer may create the impairment.
        # The unprivileged ServiceDesk backend is structurally excluded here.
        if peer_uid != 0:
            LOG.warning("rejected enable from non-root uid=%s", peer_uid)
            return {
                "ok": False,
                "command": "enable",
                "error": "operator_only",
                "detail": "enable requires an operator (root) peer; the agent may only read status or disable",
            }
        delay_ms = payload.get("delay_ms", DEFAULT_DELAY_MS)
        ttl_seconds = payload.get("ttl_seconds", DEFAULT_TTL_SECONDS)
        if not isinstance(delay_ms, int) or not (MIN_DELAY_MS <= delay_ms <= MAX_DELAY_MS):
            return {"ok": False, "command": "enable", "error": "delay_out_of_range"}
        if not isinstance(ttl_seconds, int) or not (60 <= ttl_seconds <= MAX_TTL_SECONDS):
            return {"ok": False, "command": "enable", "error": "ttl_out_of_range"}
        snap = state.enable(delay_ms, ttl_seconds)
        return {"ok": True, "command": "enable", **snap}

    if command == "disable":
        fault_id = payload.get("fault_id")
        if fault_id is not None and not isinstance(fault_id, str):
            return {"ok": False, "command": "disable", "error": "invalid_fault_id"}
        ok, reason, snap = state.disable(fault_id)
        return {"ok": ok, "command": "disable", "reason": reason, **snap}

    if command == "teardown":
        # Operator-only: removes the namespace and every scoped rule we added.
        if peer_uid != 0:
            return {"ok": False, "command": "teardown", "error": "operator_only"}
        harness_down()
        state.refresh()
        return {"ok": True, "command": "teardown", **state.snapshot()}

    return {"ok": False, "error": "unknown_command"}


def _serve(state: FaultState, group: Optional[str]) -> None:
    os.makedirs(RUN_DIR, mode=0o750, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(8)

    if group:
        import grp

        gid = grp.getgrnam(group).gr_gid
        os.chown(RUN_DIR, 0, gid)
        os.chmod(RUN_DIR, 0o750)
        os.chown(SOCKET_PATH, 0, gid)
        os.chmod(SOCKET_PATH, 0o660)
        LOG.info("control socket group=%s mode=0660", group)
    else:
        os.chmod(SOCKET_PATH, 0o600)

    LOG.info("listening on %s", SOCKET_PATH)

    while True:
        try:
            conn, _ = server.accept()
        except OSError:
            break
        with conn:
            try:
                conn.settimeout(10)
                raw = conn.recv(4096)
                if not raw:
                    continue
                pid, uid, _gid = _peer_credentials(conn)
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    conn.sendall(json.dumps({"ok": False, "error": "invalid_json"}).encode())
                    continue
                if not isinstance(payload, dict):
                    conn.sendall(json.dumps({"ok": False, "error": "invalid_payload"}).encode())
                    continue
                try:
                    user = pwd.getpwuid(uid).pw_name
                except KeyError:
                    user = str(uid)
                LOG.info("command=%s peer_uid=%s peer_user=%s peer_pid=%s",
                         payload.get("command"), uid, user, pid)
                response = _handle(payload, uid, state)
                conn.sendall(json.dumps(response).encode())
            except Exception as exc:  # never let one client kill the daemon
                LOG.exception("client error: %s", exc)
                try:
                    conn.sendall(json.dumps({"ok": False, "error": "internal_error"}).encode())
                except OSError:
                    pass


def _watchdog(state: FaultState) -> None:
    """Fail-safe: the controlled impairment can never outlive its window."""
    while True:
        time.sleep(5)
        try:
            snap = state.snapshot()
            if snap["state"] == STATE_FAULT_ACTIVE and snap["expires_at"]:
                if time.time() >= snap["expires_at"]:
                    LOG.warning("fault expired; removing automatically")
                    state.disable(None)
        except Exception:
            LOG.exception("watchdog iteration failed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", default=None,
                        help="unix group granted status/disable access (backend group)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if os.geteuid() != 0:
        LOG.error("must run as root")
        return 1

    state = FaultState()

    def _shutdown(signum, _frame):
        LOG.info("signal %s; removing controlled fault before exit", signum)
        try:
            state.disable(None)
        finally:
            try:
                os.unlink(SOCKET_PATH)
            except OSError:
                pass
            sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    threading.Thread(target=_watchdog, args=(state,), daemon=True).start()
    _serve(state, args.group)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
