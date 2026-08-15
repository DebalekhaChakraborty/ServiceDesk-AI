"""Bounded interactive cleanup for the mapped GCP shared workstation.

This module is deliberately not an ADK tool. The retained offer controller
supplies a trusted mapping and an internal offer UUID. It resolves the mapped
VM's private address and reuses ``win_tool.execute_winrm_ps`` for short control
calls. One fixed guest worker validates the active session, registers its own
fixed interactive task, runs cleanup, and publishes bounded status evidence.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import time
import uuid
from collections.abc import Mapping
from typing import Any

from . import win_tool

_TRANSPORT = "private_winrm"
_GUEST_SCRIPT = r"C:\ProgramData\ServiceDeskVDI\run_cleanup_9144.ps1"
_TASK_FOLDER = r"\ServiceDeskVDI"
_TASK_PREFIX = "SystemFileCleanup9144-"
_APPROVED_CATEGORIES = {
    "Downloaded Program Files",
    "Temporary Internet Files",
}
_POLL_INTERVAL_SECONDS = 3.0
_CONTROLLER_TIMEOUT_SECONDS = 210.0
_WINDOWS_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,20}$")
_RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _error(code: str, message: str) -> dict[str, Any]:
    return {"status": "error", "code": code, "message": message}


def _demo_result() -> dict[str, Any]:
    """Return explicitly synthetic execution evidence for presentation rehearsal."""
    return {
        "status": "ok",
        "backend": "demo",
        "transport": "deterministic_demo",
        "selected_categories": sorted(_APPROVED_CATEGORIES),
        "categories": {
            "Downloaded Program Files": {
                "status": "COMPLETED_NO_ELIGIBLE_ITEMS",
                "before_count": 0,
                "before_bytes": 0,
                "deleted_count": 0,
                "failed_or_locked_count": 0,
                "remaining_target_count": 0,
            },
            "Temporary Internet Files": {
                "status": "COMPLETED_NO_ELIGIBLE_ITEMS",
                "before_count": 0,
                "before_bytes": 0,
                "deleted_count": 0,
                "failed_or_locked_count": 0,
                "remaining_target_count": 0,
                "cookies_deleted": 0,
                "history_deleted": 0,
            },
        },
        "command_exit_code": 0,
        "free_disk_bytes_before": None,
        "free_disk_bytes_after": None,
        "bytes_reclaimed": None,
        "started_at": None,
        "completed_at": None,
        "verification": "demo_cleanup_completed",
    }


def _json_record(stdout: str) -> dict[str, Any] | None:
    for line in reversed(str(stdout or "").splitlines()):
        try:
            value = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            return value
    return None


def _valid_category_result(value: Any, *, internet_cache: bool) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("status") not in {
        "COMPLETED",
        "COMPLETED_NO_ELIGIBLE_ITEMS",
    }:
        return False
    for name in (
        "before_count",
        "before_bytes",
        "deleted_count",
        "failed_or_locked_count",
        "remaining_target_count",
    ):
        item = value.get(name)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            return False
    if value.get("failed_or_locked_count") != 0 or value.get("remaining_target_count") != 0:
        return False
    if internet_cache and (
        value.get("cookies_deleted") != 0 or value.get("history_deleted") != 0
    ):
        return False
    return True


def _parse_guest_result(
    value: Mapping[str, Any],
    *,
    invocation_id: str,
    expected_session_id: int,
    expected_username: str,
) -> dict[str, Any]:
    """Accept only completion evidence from the fixed worker and bound task."""
    selected = value.get("selected_categories")
    categories = value.get("categories")
    run_as = str(value.get("run_as") or "")
    expected_run_as_suffix = rf"\{expected_username}".casefold()
    if (
        value.get("status") != "ok"
        or value.get("phase") != "completed"
        or value.get("code") != "SYSTEM_FILE_CLEANUP_COMPLETED"
        or value.get("invocation_id") != invocation_id
        or value.get("task_name") != f"{_TASK_PREFIX}{invocation_id}"
        or value.get("command_exit_code") != 0
        or value.get("verification") != "deterministic_fixed_cleanup_completed"
        or not isinstance(value.get("worker_pid"), int)
        or value.get("worker_pid") <= 0
        or value.get("interactive_session_id") != expected_session_id
        or not (
            run_as.casefold() == expected_username.casefold()
            or run_as.casefold().endswith(expected_run_as_suffix)
        )
        or not isinstance(selected, list)
        or len(selected) != len(_APPROVED_CATEGORIES)
        or set(selected) != _APPROVED_CATEGORIES
        or not isinstance(categories, Mapping)
        or set(categories) != _APPROVED_CATEGORIES
        or not _valid_category_result(
            categories.get("Downloaded Program Files"), internet_cache=False
        )
        or not _valid_category_result(
            categories.get("Temporary Internet Files"), internet_cache=True
        )
    ):
        return _error(
            "GCP_VDI_CLEANUP_VERIFICATION_INVALID",
            "System File Cleanup returned invalid completion evidence.",
        )
    return {
        "status": "ok",
        "backend": "gcp",
        "transport": _TRANSPORT,
        "selected_categories": list(selected),
        "categories": {
            name: dict(categories[name]) for name in sorted(_APPROVED_CATEGORIES)
        },
        "command_exit_code": value["command_exit_code"],
        "free_disk_bytes_before": value.get("free_disk_bytes_before"),
        "free_disk_bytes_after": value.get("free_disk_bytes_after"),
        "bytes_reclaimed": value.get("bytes_reclaimed"),
        "started_at": value.get("started_at"),
        "completed_at": value.get("completed_at"),
        "elapsed_seconds": value.get("elapsed_seconds"),
        "interactive_session_id": value.get("interactive_session_id"),
        "worker_pid": value.get("worker_pid"),
        "task_logon_type": 3,
        "task_run_level": 1,
        "task_run_flags": 4,
        "verification": value.get("verification"),
    }


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


def _prepare_task_script(invocation_id: str, expected_username: str) -> str:
    """Invoke only the controller mode of the installed fixed worker."""
    return rf'''$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath "{_GUEST_SCRIPT}" -PathType Leaf)) {{
    [ordered]@{{status="error";code="GCP_VDI_CLEANUP_WORKER_MISSING";message="The fixed System File Cleanup worker is not installed."}} | ConvertTo-Json -Compress | Write-Output
    exit 0
}}
& "{_GUEST_SCRIPT}" -Controller -InvocationId "{invocation_id}" -ExpectedUser "{expected_username}"
'''


def _poll_script(invocation_id: str) -> str:
    task_name = f"{_TASK_PREFIX}{invocation_id}"
    return rf'''$ErrorActionPreference = "Stop"
$InvocationId = "{invocation_id}"
$TaskName = "{task_name}"
$ResultPath = "C:\ProgramData\ServiceDeskVDI\cleanup_9144_{invocation_id}.json"
$record = $null
if (Test-Path -LiteralPath $ResultPath -PathType Leaf) {{
    try {{ $record = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json -ErrorAction Stop }} catch {{}}
}}
$taskState = $null
$lastTaskResult = $null
try {{
    $scheduler = New-Object -ComObject "Schedule.Service"; $scheduler.Connect()
    $task = $scheduler.GetFolder("{_TASK_FOLDER}").GetTask($TaskName)
    $taskState = [int]$task.State
    $lastTaskResult = [int64]$task.LastTaskResult
}} catch {{}}
[ordered]@{{status="ok";code="GCP_VDI_CLEANUP_STATUS";invocation_id=$InvocationId;task_state=$taskState;last_task_result=$lastTaskResult;record=$record}} | ConvertTo-Json -Compress -Depth 8 | Write-Output
'''


def _finalize_script(invocation_id: str, *, cancel: bool) -> str:
    task_name = f"{_TASK_PREFIX}{invocation_id}"
    cancel_literal = "$true" if cancel else "$false"
    return rf'''$ErrorActionPreference = "SilentlyContinue"
$TaskName = "{task_name}"
$ResultPath = "C:\ProgramData\ServiceDeskVDI\cleanup_9144_{invocation_id}.json"
$Cancel = {cancel_literal}
$scheduler = New-Object -ComObject "Schedule.Service"; $scheduler.Connect()
$folder = $scheduler.GetFolder("{_TASK_FOLDER}")
if ($Cancel) {{
    $task = $folder.GetTask($TaskName)
    if ($null -ne $task) {{ $task.Stop(0) }}
    if (Test-Path -LiteralPath $ResultPath) {{
        try {{
            $record = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
            foreach ($id in @($record.cleanup_pid, $record.worker_pid)) {{
                if ($null -ne $id -and [int]$id -gt 0) {{ Stop-Process -Id ([int]$id) -Force -ErrorAction SilentlyContinue }}
            }}
        }} catch {{}}
    }}
}}
$folder.DeleteTask($TaskName, 0)
[ordered]@{{status="ok";code="GCP_VDI_CLEANUP_TASK_REMOVED";task_name=$TaskName}} | ConvertTo-Json -Compress | Write-Output
'''


async def _winrm_call(target_host: str, script: str) -> dict[str, Any]:
    return await asyncio.to_thread(win_tool.execute_winrm_ps, target_host, script)


def _monotonic() -> float:
    return time.monotonic()


async def execute_system_file_cleanup(
    mapping: Mapping[str, str],
    backend: str,
    offer_id: str | None = None,
) -> dict[str, Any]:
    """Run the fixed worker asynchronously through short private-WinRM calls."""
    if backend == "demo":
        return _demo_result()
    if backend != "gcp":
        return _error("GCP_VDI_CLEANUP_BACKEND_INVALID", "Cleanup is not available.")
    expected_username = str(mapping.get("windows_username") or "")
    if not _WINDOWS_USERNAME_RE.fullmatch(expected_username):
        return _error(
            "GCP_VDI_CLEANUP_MAPPING_INVALID",
            "The trusted shared-workstation mapping has no valid Windows user.",
        )
    try:
        invocation_id = str(uuid.UUID(str(offer_id or "")))
    except (TypeError, ValueError, AttributeError):
        return _error(
            "GCP_VDI_CLEANUP_OFFER_INVALID",
            "The authorized System File Cleanup offer is invalid.",
        )
    try:
        target_host = await asyncio.to_thread(_resolve_private_target, mapping)
    except Exception:
        return _error(
            "GCP_VDI_CLEANUP_PRIVATE_TARGET_UNAVAILABLE",
            "The mapped shared workstation private endpoint could not be verified; cleanup was not run.",
        )

    prepared: dict[str, Any] | None = None
    cancel = False
    try:
        executed = await _winrm_call(
            target_host, _prepare_task_script(invocation_id, expected_username)
        )
        if executed.get("status") != "success":
            return _error(
                "GCP_VDI_CLEANUP_TRANSPORT_FAILED",
                "Private WinRM could not start System File Cleanup.",
            )
        prepared = _json_record(str(executed.get("stdout") or ""))
        if not prepared:
            return _error(
                "GCP_VDI_CLEANUP_CONTROLLER_RESPONSE_INVALID",
                "The cleanup controller returned no valid startup evidence.",
            )
        if prepared.get("status") != "ok":
            return _error(
                str(prepared.get("code") or "GCP_VDI_CLEANUP_CONTROLLER_FAILED"),
                str(prepared.get("message") or "System File Cleanup could not be started."),
            )
        session_id = prepared.get("session_id")
        if (
            prepared.get("invocation_id") != invocation_id
            or prepared.get("task_name") != f"{_TASK_PREFIX}{invocation_id}"
            or not isinstance(session_id, int)
            or session_id <= 0
            or prepared.get("privilege_available") is not True
            or prepared.get("highest_available") is not True
            or prepared.get("logon_type") != 3
            or prepared.get("run_level") != 1
            or prepared.get("run_flags") != 4
        ):
            cancel = True
            return _error(
                "GCP_VDI_CLEANUP_TASK_EVIDENCE_INVALID",
                "The cleanup task startup evidence was invalid.",
            )

        deadline = _monotonic() + _CONTROLLER_TIMEOUT_SECONDS
        while _monotonic() < deadline:
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
            polled = await _winrm_call(target_host, _poll_script(invocation_id))
            if polled.get("status") != "success":
                continue
            status_record = _json_record(str(polled.get("stdout") or ""))
            if not status_record or status_record.get("invocation_id") != invocation_id:
                continue
            worker = status_record.get("record")
            if not isinstance(worker, Mapping):
                continue
            if worker.get("invocation_id") != invocation_id:
                cancel = True
                return _error(
                    "CLEANUP_TASK_RESULT_UNAVAILABLE",
                    "System File Cleanup returned mismatched status evidence.",
                )
            phase = worker.get("phase")
            if phase == "completed":
                return _parse_guest_result(
                    worker,
                    invocation_id=invocation_id,
                    expected_session_id=session_id,
                    expected_username=expected_username,
                )
            if phase in {"failed", "timed_out"}:
                return _error(
                    str(worker.get("code") or "SYSTEM_FILE_CLEANUP_FAILED"),
                    str(worker.get("message") or "System File Cleanup did not complete."),
                )
        cancel = True
        return _error(
            "SYSTEM_FILE_CLEANUP_TIMED_OUT",
            "System File Cleanup did not finish within the controller time limit.",
        )
    except Exception:
        cancel = prepared is not None and prepared.get("status") == "ok"
        return _error(
            "GCP_VDI_CLEANUP_CONTROLLER_FAILED",
            "The cleanup controller failed safely; no successful remediation was claimed.",
        )
    finally:
        if prepared is not None and prepared.get("status") == "ok":
            try:
                await _winrm_call(
                    target_host, _finalize_script(invocation_id, cancel=cancel)
                )
            except Exception:
                pass
