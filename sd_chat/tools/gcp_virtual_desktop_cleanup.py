"""Bounded guest execution for the GCP VDI lab cleanup profile.

This module is deliberately not an ADK tool.  The only caller is the retained
offer controller in :mod:`gcp_virtual_desktop_tool`, which supplies a trusted
mapping and a fixed command.  It never accepts a hostname, project, command, or
credential from chat. The mapped VM's private address is resolved through
Compute Engine and the existing ServiceDesk WinRM transport performs execution.
"""

from __future__ import annotations

import json
import ipaddress
from typing import Any, Dict, Mapping

from . import win_tool


_TRANSPORT = "private_winrm"
_GUEST_SCRIPT = r"C:\ProgramData\ServiceDeskVDI\Invoke-ServiceDeskVdiLabCleanup.ps1"
_PROFILE = "KB screenshot-visible PoC cleanup profile"
_PROFILE_ID = 9144
_APPROVED_CATEGORIES = {
    "Downloaded Program Files",
    "Temporary Internet Files",
}
_RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _error(code: str, message: str) -> Dict[str, Any]:
    return {"status": "error", "code": code, "message": message}


def _demo_result() -> Dict[str, Any]:
    """Return explicitly synthetic execution evidence for presentation rehearsal."""
    return {
        "status": "ok",
        "backend": "demo",
        "transport": "deterministic_demo",
        "profile": _PROFILE,
        "profile_id": _PROFILE_ID,
        "selected_categories": sorted(_APPROVED_CATEGORIES),
        "command_exit_code": 0,
        "free_disk_bytes_before": None,
        "free_disk_bytes_after": None,
        "bytes_reclaimed": None,
        "started_at": None,
        "completed_at": None,
        "verification": "demo_cleanup_completed",
    }


def _parse_guest_result(stdout: str) -> Dict[str, Any]:
    """Accept only the one safe JSON record emitted by the installed guest script."""
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        selected = value.get("selected_categories")
        if (
            value.get("status") != "ok"
            or value.get("profile") != _PROFILE
            or value.get("profile_id") != _PROFILE_ID
            or value.get("command_exit_code") != 0
            or value.get("verification") != "native_disk_cleanup_completed"
            or not isinstance(selected, list)
            or not selected
            or not set(selected).issubset(_APPROVED_CATEGORIES)
        ):
            continue
        return {
            "status": "ok",
            "backend": "gcp",
            "transport": _TRANSPORT,
            "profile": value["profile"],
            "profile_id": value["profile_id"],
            "selected_categories": list(selected),
            "command_exit_code": value["command_exit_code"],
            "free_disk_bytes_before": value.get("free_disk_bytes_before"),
            "free_disk_bytes_after": value.get("free_disk_bytes_after"),
            "bytes_reclaimed": value.get("bytes_reclaimed"),
            "started_at": value.get("started_at"),
            "completed_at": value.get("completed_at"),
            "verification": value.get("verification"),
        }
    return _error(
        "GCP_VDI_CLEANUP_VERIFICATION_INVALID",
        "The lab cleanup did not return valid completion evidence.",
    )


def _resolve_private_target(mapping: Mapping[str, str]) -> str:
    """Resolve only the mapped Compute Engine VM's RFC1918 interface address."""
    from google.cloud import compute_v1

    instance = compute_v1.InstancesClient().get(
        project=str(mapping["project_id"]),
        zone=str(mapping["zone"]),
        instance=str(mapping["instance_name"]),
    )
    if str(getattr(instance, "name", "") or "") != str(mapping["instance_name"]):
        raise ValueError("mapped_instance_mismatch")
    if str(getattr(instance, "status", "") or "") != "RUNNING":
        raise ValueError("mapped_instance_not_running")
    addresses = [
        str(
            getattr(interface, "network_i_p", None)
            or getattr(interface, "network_ip", None)
            or ""
        )
        for interface in list(getattr(instance, "network_interfaces", []) or [])
    ]
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.version == 4 and any(
            parsed in network for network in _RFC1918_NETWORKS
        ):
            return address
    raise ValueError("mapped_instance_private_address_unavailable")


def execute_system_file_cleanup(
    mapping: Mapping[str, str],
    backend: str,
) -> Dict[str, Any]:
    """Run the fixed lab profile over the existing private WinRM transport."""
    if backend == "demo":
        return _demo_result()
    if backend != "gcp":
        return _error("GCP_VDI_CLEANUP_BACKEND_INVALID", "Cleanup is not available.")
    try:
        target_host = _resolve_private_target(mapping)
    except Exception:
        return _error(
            "GCP_VDI_CLEANUP_PRIVATE_TARGET_UNAVAILABLE",
            "The mapped GCP virtual desktop private endpoint could not be verified; cleanup was not run.",
        )

    # Both the private host and this PowerShell are controller-owned. The ADK
    # model supplies neither value, and no arbitrary execution tool is exposed.
    executed = win_tool.execute_winrm_ps(
        target_host,
        rf'''$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath "{_GUEST_SCRIPT}")) {{
    throw "The approved ServiceDesk VDI lab cleanup profile is not installed."
}}
& "{_GUEST_SCRIPT}"
''',
    )
    if executed.get("status") != "success":
        return _error(
            "GCP_VDI_CLEANUP_EXECUTION_FAILED",
            "The existing private WinRM transport could not verify the lab cleanup.",
        )
    result = _parse_guest_result(str(executed.get("stdout") or ""))
    if result.get("status") != "ok":
        return result
    return result
