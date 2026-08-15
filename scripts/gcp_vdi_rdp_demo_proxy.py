#!/usr/bin/env python3
"""
Fixed RDP TCP demo proxy for the GCP shared-workstation PoC.

Runs inside the isolated `sdvdi-demo` network namespace so that the controlled
latency impairment applies to this RDP path and to nothing else on the host.

    sudo ip netns exec sdvdi-demo \
        /home/AI_POC/venvs/debalekha/bin/python \
        scripts/gcp_vdi_rdp_demo_proxy.py --target-host <private-ip>

Deliberate constraints
----------------------
* Destination port is fixed to TCP 3389. It is not configurable.
* Destination host comes from the operator's command line or the private
  mapping file. It is never supplied by the model or by chat input.
* The proxy is a transparent bidirectional byte pump. It never inspects,
  parses, decrypts, or logs RDP payload, keystrokes, clipboard, or credentials.
* Logging is bounded to connection lifecycle and byte counts.
* The proxy handles no credentials of any kind.

This is a PoC demonstration mechanism, not the customer's production network
control plane.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import selectors
import socket
import threading
from typing import Optional

RDP_PORT = 3389  # fixed; intentionally not configurable
DEFAULT_BIND_HOST = "10.99.99.2"  # namespace-side veth address; host-internal only
DEFAULT_BIND_PORT = 13389
BUFFER = 65536

LOG = logging.getLogger("rdp-demo-proxy")


def _resolve_target_from_mapping(mapping_path: str) -> Optional[str]:
    """
    Resolve the destination from the trusted private mapping only.

    Never accepts chat/model input. Accepts an explicit `private_ip` when the
    mapping carries one; otherwise resolves the mapped project/zone/instance
    through the Compute Engine API, which is the same trusted source the
    ServiceDesk controller uses.

    Note: when the proxy is launched inside the namespace under `sudo`, the
    API lookup runs as root and will not see the operator's user-level
    application default credentials. In that case pass --target-host, which the
    operator resolves from this same mapping.
    """
    try:
        with open(mapping_path) as handle:
            mapping = json.load(handle)
    except (OSError, ValueError) as exc:
        LOG.error("cannot read trusted mapping: %s", exc)
        return None
    if len(mapping) != 1:
        LOG.error("mapping must contain exactly one PoC entry; found %d", len(mapping))
        return None

    entry = next(iter(mapping.values()))
    if entry.get("private_ip"):
        return entry["private_ip"]

    project, zone, instance = (entry.get("project_id"), entry.get("zone"),
                               entry.get("instance_name"))
    if not (project and zone and instance):
        LOG.error("mapping lacks private_ip and a complete project/zone/instance triple")
        return None

    import subprocess

    try:
        proc = subprocess.run(
            ["gcloud", "compute", "instances", "describe", instance,
             "--zone", zone, "--project", project,
             "--format=value(networkInterfaces[0].networkIP)"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        LOG.error("Compute Engine lookup failed: %s", exc)
        return None
    if proc.returncode != 0:
        LOG.error("Compute Engine lookup failed for mapped instance: %s",
                  proc.stderr.strip()[:200])
        return None

    resolved = proc.stdout.strip()
    if not resolved:
        LOG.error("mapped instance returned no private IP")
        return None
    LOG.info("resolved trusted mapped instance %s to its private endpoint", instance)
    return resolved


def _pump(src: socket.socket, dst: socket.socket) -> int:
    """Transparent byte forwarding. Payload is never inspected or logged."""
    total = 0
    try:
        while True:
            chunk = src.recv(BUFFER)
            if not chunk:
                break
            dst.sendall(chunk)
            total += len(chunk)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    return total


def _handle(client: socket.socket, peer: str, target_host: str) -> None:
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.settimeout(15)
    try:
        upstream.connect((target_host, RDP_PORT))
    except OSError as exc:
        LOG.warning("upstream connect failed for %s: %s", peer, exc)
        client.close()
        upstream.close()
        return
    upstream.settimeout(None)
    client.settimeout(None)
    LOG.info("session open peer=%s -> %s:%d", peer, target_host, RDP_PORT)

    sent = [0]

    def _up() -> None:
        sent[0] = _pump(client, upstream)

    thread = threading.Thread(target=_up, daemon=True)
    thread.start()
    received = _pump(upstream, client)
    thread.join(timeout=10)

    client.close()
    upstream.close()
    LOG.info("session closed peer=%s bytes_to_target=%d bytes_to_client=%d",
             peer, sent[0], received)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind-host", default=DEFAULT_BIND_HOST)
    parser.add_argument("--bind-port", type=int, default=DEFAULT_BIND_PORT)
    parser.add_argument("--target-host", default=None,
                        help="trusted shared-workstation private IP (operator supplied)")
    parser.add_argument("--mapping-path", default=os.getenv("GCP_VDI_MAPPING_PATH"),
                        help="fallback: read private_ip from the trusted mapping")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    target = args.target_host
    if not target and args.mapping_path:
        target = _resolve_target_from_mapping(args.mapping_path)
    if not target:
        LOG.error("no trusted target resolved; supply --target-host or a mapping with private_ip")
        return 2

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind_host, args.bind_port))
    listener.listen(8)
    LOG.info("listening on %s:%d -> %s:%d (payload never inspected or logged)",
             args.bind_host, args.bind_port, target, RDP_PORT)

    sel = selectors.DefaultSelector()
    sel.register(listener, selectors.EVENT_READ)

    try:
        while True:
            for _key, _mask in sel.select(timeout=1.0):
                conn, addr = listener.accept()
                peer = f"{addr[0]}:{addr[1]}"
                threading.Thread(target=_handle, args=(conn, peer, target), daemon=True).start()
    except KeyboardInterrupt:
        LOG.info("shutting down")
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
