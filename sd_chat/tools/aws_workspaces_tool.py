"""Read-only Amazon WorkSpaces login and performance diagnostics.

The public tools in this module are deliberately cohesive.  They resolve the
authenticated caller through the existing identity context, require an explicit
UPN-to-WorkSpaces mapping, and then perform either one login diagnosis or one
performance diagnosis.  No AWS write API is used.

Registration codes are handled only as short-lived local variables for an
internal comparison against an authorized Windows client endpoint.  They are
never returned, logged, or persisted in ADK state.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from google.adk.tools import FunctionTool, ToolContext

from . import aad_tool, account_access_orchestrator, win_tool
from .identity_context_tool import ensure_identity_context_in_state
from .policy_tool import check_list

AWS_MODE_ENV = "AWS_WORKSPACES_MODE"
AWS_MAPPING_PATH_ENV = "AWS_WORKSPACES_USER_MAP_PATH"
AWS_DEMO_FIXTURE_PATH_ENV = "AWS_WORKSPACES_DEMO_FIXTURE_PATH"
AWS_LOOKBACK_ENV = "AWS_WORKSPACES_METRIC_LOOKBACK_MINUTES"

VALID_MODES = {"off", "demo", "aws"}
VALID_REPORTED_ERROR_CATEGORIES = {
    "not_authorized",
    "authentication_failure",
    "other",
    "unspecified",
}
KB_LATENCY_THRESHOLD_MS = 200.0

_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_DIRECTORY_ID_RE = re.compile(r"^d-[A-Za-z0-9-]{6,}$")

_METRIC_SPECS: Dict[str, Dict[str, str]] = {
    "InSessionLatency": {
        "key": "in_session_latency_ms",
        "statistic": "Average",
        "unit": "Milliseconds",
    },
    "CPUUsage": {
        "key": "cpu_usage_percent",
        "statistic": "Average",
        "unit": "Percent",
    },
    "MemoryUsage": {
        "key": "memory_usage_percent",
        "statistic": "Average",
        "unit": "Percent",
    },
    "RootVolumeDiskUsage": {
        "key": "root_disk_usage_percent",
        "statistic": "Average",
        "unit": "Percent",
    },
    "UserVolumeDiskUsage": {
        "key": "user_disk_usage_percent",
        "statistic": "Average",
        "unit": "Percent",
    },
    "ConnectionAttempt": {
        "key": "connection_attempt_count",
        "statistic": "Sum",
        "unit": "Count",
    },
    "ConnectionSuccess": {
        "key": "connection_success_count",
        "statistic": "Sum",
        "unit": "Count",
    },
    "ConnectionFailure": {
        "key": "connection_failure_count",
        "statistic": "Sum",
        "unit": "Count",
    },
    "SessionLaunchTime": {
        "key": "session_launch_time",
        "statistic": "Average",
        "unit": "Seconds",
    },
    "SessionDisconnect": {
        "key": "session_disconnect_count",
        "statistic": "Sum",
        "unit": "Count",
    },
    "UserConnected": {
        "key": "user_connected",
        "statistic": "Maximum",
        "unit": "Count",
    },
    "UDPPacketLossRate": {
        "key": "udp_packet_loss_rate",
        "statistic": "Average",
        "unit": "Percent",
    },
    "TCPRetransmissionRate": {
        "key": "tcp_retransmission_rate",
        "statistic": "Average",
        "unit": "Percent",
    },
}

_SYSTEM_FILE_CLEANUP_LIMITATION = (
    "KB0019144 recommends Windows Disk Cleanup > Clean Up System Files for "
    "significant latency, but this repository does not have a faithful governed "
    "automation for the KB's cleanup categories. Existing temporary-file cleanup "
    "is not treated as equivalent."
)


def _mode() -> str:
    return (os.getenv(AWS_MODE_ENV) or "off").strip().lower()


def _norm_upn(value: Any) -> str:
    return str(value or "").strip().lower()


def _norm_host(value: Any) -> str:
    host = str(value or "").strip().lower()
    if host.startswith(("http://", "https://")):
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    return host


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    text = str(value).strip()
    return text or None


def _error(code: str, message: str) -> Dict[str, Any]:
    return {"status": "error", "code": code, "message": message}


def _check(status: str, source: str, evidence: str) -> Dict[str, str]:
    if status not in {"pass", "fail", "not_verifiable", "not_applicable"}:
        status = "not_verifiable"
    return {"status": status, "source": source, "evidence": evidence}


def _metric_unavailable(statistic: str) -> Dict[str, Any]:
    return {
        "status": "unavailable",
        "value": None,
        "timestamp": None,
        "statistic": statistic,
        "unit": None,
    }


def _lookback_minutes() -> int:
    try:
        value = int((os.getenv(AWS_LOOKBACK_ENV) or "30").strip())
    except (TypeError, ValueError):
        return 30
    return min(max(value, 5), 1440)


def _load_json_file(path_value: str, missing_code: str, malformed_code: str) -> Any:
    path_text = str(path_value or "").strip()
    if not path_text:
        raise _ConfigurationError(missing_code)
    try:
        path = Path(path_text).expanduser()
        if path.stat().st_size > 2 * 1024 * 1024:
            raise _ConfigurationError(malformed_code)
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except _ConfigurationError:
        raise
    except FileNotFoundError as exc:
        raise _ConfigurationError(missing_code) from exc
    except (OSError, ValueError, TypeError) as exc:
        raise _ConfigurationError(malformed_code) from exc


class _ConfigurationError(Exception):
    pass


class _AwsCallError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _identity(
    tool_context: ToolContext,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    state = tool_context.state
    if state is None:
        state = {}
        tool_context.state = state
    result = ensure_identity_context_in_state(state)
    if not result.get("ok"):
        return None, _error(
            "AWS_WORKSPACES_CALLER_UNKNOWN",
            "The authenticated caller identity is unavailable; AWS WorkSpaces was not checked.",
        )
    identity = result.get("identity")
    if not isinstance(identity, dict) or not _norm_upn(identity.get("upn")):
        return None, _error(
            "AWS_WORKSPACES_CALLER_UNKNOWN",
            "The authenticated caller UPN is unavailable; AWS WorkSpaces was not checked.",
        )
    return identity, None


def _authorize_self(
    target_upn: str,
    tool_context: ToolContext,
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    identity, identity_error = _identity(tool_context)
    if identity_error is not None or identity is None:
        return None, identity_error
    caller_upn = _norm_upn(identity.get("upn"))
    target = _norm_upn(target_upn)
    if not target or target != caller_upn:
        return None, _error(
            "AWS_WORKSPACES_SELF_SERVICE_ONLY",
            "AWS WorkSpaces diagnosis is currently available only for the authenticated caller.",
        )
    return caller_upn, None


def _load_mapping(
    target_upn: str,
) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
    try:
        raw = _load_json_file(
            os.getenv(AWS_MAPPING_PATH_ENV, ""),
            "AWS_WORKSPACES_MAPPING_NOT_CONFIGURED",
            "AWS_WORKSPACES_MAPPING_MALFORMED",
        )
    except _ConfigurationError as exc:
        code = str(exc)
        message = (
            "The explicit AWS WorkSpaces identity mapping is not configured."
            if code == "AWS_WORKSPACES_MAPPING_NOT_CONFIGURED"
            else "The AWS WorkSpaces identity mapping is malformed."
        )
        return None, _error(code, f"{message} AWS WorkSpaces was not checked.")

    if not isinstance(raw, dict):
        return None, _error(
            "AWS_WORKSPACES_MAPPING_MALFORMED",
            "The AWS WorkSpaces identity mapping is malformed; AWS WorkSpaces was not checked.",
        )

    mapping_by_upn = {
        _norm_upn(key): value for key, value in raw.items() if _norm_upn(key)
    }
    target_key = _norm_upn(target_upn)
    if target_key not in mapping_by_upn:
        return None, _error(
            "AWS_WORKSPACES_USER_NOT_MAPPED",
            "No explicit AWS WorkSpaces mapping exists for the authenticated caller.",
        )
    entry = mapping_by_upn[target_key]
    if not isinstance(entry, dict):
        return None, _error(
            "AWS_WORKSPACES_MAPPING_MALFORMED",
            "The caller's AWS WorkSpaces mapping is malformed; AWS WorkSpaces was not checked.",
        )

    region = str(entry.get("region") or "").strip()
    directory_id = str(entry.get("directory_id") or "").strip()
    workspace_username = str(entry.get("workspace_username") or "").strip()
    if (
        not _REGION_RE.fullmatch(region)
        or not _DIRECTORY_ID_RE.fullmatch(directory_id)
        or not workspace_username
        or len(workspace_username) > 256
        or any(ord(char) < 32 for char in workspace_username)
    ):
        return None, _error(
            "AWS_WORKSPACES_MAPPING_MALFORMED",
            "The caller's AWS WorkSpaces mapping is malformed; AWS WorkSpaces was not checked.",
        )
    return {
        "region": region,
        "directory_id": directory_id,
        "workspace_username": workspace_username,
    }, None


def _boto3_client(service_name: str, region: str) -> Any:
    try:
        import boto3  # type: ignore
        from botocore.config import Config  # type: ignore
    except ImportError as exc:
        raise _AwsCallError("AWS_SDK_UNAVAILABLE") from exc
    return boto3.client(
        service_name,
        region_name=region,
        config=Config(
            connect_timeout=5,
            read_timeout=20,
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )


def _normalized_aws_exception(exc: Exception) -> _AwsCallError:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    aws_code = str(error.get("Code") or "") if isinstance(error, dict) else ""
    if aws_code in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
    }:
        return _AwsCallError("AWS_ACCESS_DENIED")
    if aws_code in {
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidClientTokenId",
        "UnrecognizedClientException",
    }:
        return _AwsCallError("AWS_CREDENTIALS_INVALID")
    if aws_code in {"InvalidParameterValuesException", "ResourceNotFoundException"}:
        return _AwsCallError("AWS_RESOURCE_OR_REGION_INVALID")
    class_name = type(exc).__name__
    if class_name in {"NoCredentialsError", "PartialCredentialsError"}:
        return _AwsCallError("AWS_CREDENTIALS_UNAVAILABLE")
    if class_name in {
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "EndpointConnectionError",
    }:
        return _AwsCallError("AWS_API_TIMEOUT_OR_ENDPOINT_ERROR")
    return _AwsCallError("AWS_API_ERROR")


def _call_aws(client: Any, method_name: str, **kwargs: Any) -> Dict[str, Any]:
    try:
        method = getattr(client, method_name)
        response = method(**kwargs)
    except _AwsCallError:
        raise
    except Exception as exc:
        raise _normalized_aws_exception(exc) from exc
    if not isinstance(response, dict):
        raise _AwsCallError("AWS_RESPONSE_INVALID")
    return response


def _public_workspace(raw: Dict[str, Any]) -> Dict[str, Any]:
    properties = raw.get("WorkspaceProperties")
    if not isinstance(properties, dict):
        properties = {}
    protocols = properties.get("Protocols")
    if not isinstance(protocols, list):
        protocols = []
    return {
        "assigned": True,
        "workspace_id": raw.get("WorkspaceId"),
        "directory_id": raw.get("DirectoryId"),
        "user_name": raw.get("UserName"),
        "computer_name": raw.get("ComputerName"),
        "state": raw.get("State") or "UNKNOWN",
        "bundle_id": raw.get("BundleId"),
        "running_mode": properties.get("RunningMode"),
        "protocols": [str(value) for value in protocols if value],
    }


def _public_connection(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    state = str(raw.get("ConnectionState") or "UNKNOWN").upper()
    if state not in {"CONNECTED", "DISCONNECTED", "UNKNOWN"}:
        state = "UNKNOWN"
    return {
        "state": state,
        "state_checked_at": _iso(raw.get("ConnectionStateCheckTimestamp")),
        "last_known_user_connection": _iso(raw.get("LastKnownUserConnectionTimestamp")),
    }


def _empty_workspace(mapping: Dict[str, str]) -> Dict[str, Any]:
    return {
        "assigned": False,
        "workspace_id": None,
        "directory_id": mapping["directory_id"],
        "user_name": mapping["workspace_username"],
        "computer_name": None,
        "state": None,
        "bundle_id": None,
        "running_mode": None,
        "protocols": [],
    }


def _aws_workspace_context(mapping: Dict[str, str]) -> Dict[str, Any]:
    region = mapping["region"]
    client = _boto3_client("workspaces", region)
    response = _call_aws(
        client,
        "describe_workspaces",
        DirectoryId=mapping["directory_id"],
        UserName=mapping["workspace_username"],
    )
    workspaces = response.get("Workspaces") or []
    if not isinstance(workspaces, list):
        raise _AwsCallError("AWS_RESPONSE_INVALID")
    if len(workspaces) > 1:
        raise _AwsCallError("AWS_WORKSPACES_MULTIPLE_UNEXPECTED")
    if not workspaces:
        return {
            "workspace": _empty_workspace(mapping),
            "connection": _public_connection(None),
            "registration_code": None,
            "mfa_directory_status": "not_verifiable",
            "diagnostic_errors": [],
            "workspaces_client": client,
        }

    raw_workspace = workspaces[0]
    if not isinstance(raw_workspace, dict) or not raw_workspace.get("WorkspaceId"):
        raise _AwsCallError("AWS_RESPONSE_INVALID")
    workspace = _public_workspace(raw_workspace)
    workspace_id = str(workspace["workspace_id"])

    connection_response = _call_aws(
        client,
        "describe_workspaces_connection_status",
        WorkspaceIds=[workspace_id],
    )
    connection_entries = connection_response.get("WorkspacesConnectionStatus") or []
    connection_raw = (
        connection_entries[0]
        if isinstance(connection_entries, list) and connection_entries
        else None
    )

    registration_code: Optional[str] = None
    diagnostic_errors: List[Dict[str, str]] = []
    try:
        directory_response = _call_aws(
            client,
            "describe_workspace_directories",
            DirectoryIds=[mapping["directory_id"]],
        )
        directories = directory_response.get("Directories") or []
        if isinstance(directories, list) and directories:
            directory = directories[0]
            if isinstance(directory, dict):
                candidate = directory.get("RegistrationCode")
                if isinstance(candidate, str) and candidate:
                    registration_code = candidate
    except _AwsCallError as exc:
        diagnostic_errors.append(
            {"source": "aws.workspaces.DescribeWorkspaceDirectories", "code": exc.code}
        )

    mfa_directory_status = "not_verifiable"
    try:
        directory_client = _boto3_client("ds", region)
        ds_response = _call_aws(
            directory_client,
            "describe_directories",
            DirectoryIds=[mapping["directory_id"]],
        )
        descriptions = ds_response.get("DirectoryDescriptions") or []
        if isinstance(descriptions, list) and descriptions:
            description = descriptions[0]
            if isinstance(description, dict):
                radius_status = str(description.get("RadiusStatus") or "").upper()
                radius_settings = description.get("RadiusSettings")
                if radius_status == "COMPLETED" and isinstance(radius_settings, dict):
                    mfa_directory_status = "enabled"
                elif not radius_status and not radius_settings:
                    mfa_directory_status = "disabled"
                elif radius_status in {"FAILED", "COMPLETED"}:
                    mfa_directory_status = "disabled"
    except _AwsCallError as exc:
        diagnostic_errors.append(
            {"source": "aws.directoryservice.DescribeDirectories", "code": exc.code}
        )

    return {
        "workspace": workspace,
        "connection": _public_connection(connection_raw),
        "registration_code": registration_code,
        "mfa_directory_status": mfa_directory_status,
        "diagnostic_errors": diagnostic_errors,
        "workspaces_client": client,
    }


def _load_demo_context(mapping: Dict[str, str]) -> Dict[str, Any]:
    try:
        fixture = _load_json_file(
            os.getenv(AWS_DEMO_FIXTURE_PATH_ENV, ""),
            "AWS_WORKSPACES_DEMO_FIXTURE_NOT_CONFIGURED",
            "AWS_WORKSPACES_DEMO_FIXTURE_MALFORMED",
        )
    except _ConfigurationError as exc:
        raise _AwsCallError(str(exc)) from exc
    entries = fixture.get("workspaces") if isinstance(fixture, dict) else None
    if not isinstance(entries, list):
        raise _AwsCallError("AWS_WORKSPACES_DEMO_FIXTURE_MALFORMED")
    matches = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and str(entry.get("region") or "") == mapping["region"]
        and str(entry.get("directory_id") or "") == mapping["directory_id"]
        and str(entry.get("workspace_username") or "") == mapping["workspace_username"]
    ]
    if len(matches) != 1:
        raise _AwsCallError("AWS_WORKSPACES_DEMO_FIXTURE_ENTRY_NOT_FOUND")
    entry = matches[0]
    raw_workspace = entry.get("workspace")
    if raw_workspace is None:
        workspace = _empty_workspace(mapping)
    elif isinstance(raw_workspace, dict):
        workspace = _public_workspace(raw_workspace)
    else:
        raise _AwsCallError("AWS_WORKSPACES_DEMO_FIXTURE_MALFORMED")
    connection = _public_connection(entry.get("connection"))
    registration_status = str(entry.get("registration_status") or "not_verifiable")
    if registration_status not in {"pass", "fail", "not_verifiable"}:
        raise _AwsCallError("AWS_WORKSPACES_DEMO_FIXTURE_MALFORMED")
    mfa_status = str(entry.get("mfa_directory_status") or "not_verifiable")
    if mfa_status not in {"enabled", "disabled", "not_verifiable"}:
        raise _AwsCallError("AWS_WORKSPACES_DEMO_FIXTURE_MALFORMED")
    return {
        "workspace": workspace,
        "connection": connection,
        "registration_status": registration_status,
        "mfa_directory_status": mfa_status,
        "inactivity_access_status": str(
            entry.get("inactivity_access_status") or "not_verifiable"
        ),
        "metrics": entry.get("metrics")
        if isinstance(entry.get("metrics"), dict)
        else {},
        "diagnostic_errors": [],
        "workspaces_client": None,
    }


def _workspace_context(mode: str, mapping: Dict[str, str]) -> Dict[str, Any]:
    if mode == "demo":
        return _load_demo_context(mapping)
    return _aws_workspace_context(mapping)


def _phase_b_account_checks(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Dict[str, str]]:
    """Reuse the Phase B controller without retaining an Account Access offer."""
    result = account_access_orchestrator.diagnose_account_access.func(
        target_upn, tool_context
    )
    state = tool_context.state
    if state is not None:
        state[account_access_orchestrator.ACCOUNT_ACCESS_OFFER_STATE_KEY] = None
        state["account_access_diagnosis"] = None
    if result.get("status") != "ok" or not isinstance(result.get("account"), dict):
        code = str(result.get("code") or "PHASE_B_ACCOUNT_STATUS_UNAVAILABLE")
        evidence = f"Phase B Account Access returned {code}."
        return {
            "account_enabled": _check(
                "not_verifiable", "phase_b.account_access", evidence
            ),
            "account_locked": _check(
                "not_verifiable", "phase_b.account_access", evidence
            ),
        }
    account = result["account"]
    enabled = account.get("enabled")
    locked = account.get("locked")
    enabled_status = (
        "pass" if enabled is True else "fail" if enabled is False else "not_verifiable"
    )
    locked_status = (
        "fail" if locked is True else "pass" if locked is False else "not_verifiable"
    )
    enabled_evidence = (
        "The Phase B protected account-status check reports the account enabled."
        if enabled is True
        else "The Phase B protected account-status check reports the account disabled."
        if enabled is False
        else "The Phase B protected account-status check could not determine enabled state."
    )
    locked_evidence = (
        "The Phase B protected account-status check reports the account locked."
        if locked is True
        else "The Phase B protected account-status check reports the account not locked."
        if locked is False
        else "The Phase B protected account-status source cannot verify current lock state."
    )
    return {
        "account_enabled": _check(
            enabled_status, "phase_b.account_access", enabled_evidence
        ),
        "account_locked": _check(
            locked_status, "phase_b.account_access", locked_evidence
        ),
    }


def _registration_check(
    mode: str,
    context: Dict[str, Any],
    tool_context: ToolContext,
    client_endpoint: str,
) -> Dict[str, Any]:
    workspace = context["workspace"]
    if not workspace.get("assigned"):
        return _check(
            "not_applicable",
            "aws.workspaces.DescribeWorkspaces",
            "Registration comparison is not applicable because no WorkSpace is assigned.",
        )
    if mode == "demo":
        status = context.get("registration_status") or "not_verifiable"
        evidence = {
            "pass": "The deterministic demo fixture reports registration valid.",
            "fail": "The deterministic demo fixture reports a registration mismatch.",
            "not_verifiable": "The deterministic demo fixture has no client registration telemetry.",
        }[status]
        return _check(status, "demo_fixture", evidence)

    expected_code = context.get("registration_code")
    if not isinstance(expected_code, str) or not expected_code:
        return _check(
            "not_verifiable",
            "aws.workspaces.DescribeWorkspaceDirectories",
            "Directory registration metadata was unavailable; no registration code was exposed.",
        )

    device_result = aad_tool.aad_get_my_devices.func(tool_context)
    allowed_hosts = (
        device_result.get("allowed_hosts") if isinstance(device_result, dict) else None
    )
    if not device_result.get("ok") or not isinstance(allowed_hosts, list):
        return _check(
            "not_verifiable",
            "microsoft_graph.registeredDevices",
            "Authorized WorkSpaces client endpoint telemetry is unavailable.",
        )
    normalized_allowed = sorted(
        {_norm_host(host) for host in allowed_hosts if _norm_host(host)}
    )
    selected = _norm_host(client_endpoint)
    if selected:
        if selected not in normalized_allowed:
            return _check(
                "not_verifiable",
                "policy.host_is_authorized",
                "The selected client endpoint is not authorized for the caller.",
            )
    elif len(normalized_allowed) == 1:
        selected = normalized_allowed[0]
    else:
        result: Dict[str, Any] = _check(
            "not_verifiable",
            "microsoft_graph.registeredDevices",
            "A single authorized WorkSpaces client endpoint could not be selected for registration inspection.",
        )
        result["selection_required"] = len(normalized_allowed) > 1
        result["authorized_client_endpoints"] = normalized_allowed
        return result

    policy = check_list(
        preconditions=[
            "host_is_authorized",
            "endpoint_reachable",
            "endpoint_is_windows",
        ],
        target_host=selected,
        allowed_hosts_csv=",".join(normalized_allowed),
    )
    if policy.get("status") != "ok":
        return _check(
            "not_verifiable",
            "policy.host_is_authorized",
            "The authorized client endpoint is not currently reachable and verifiable as Windows.",
        )

    escaped_code = expected_code.replace("'", "''")
    script = rf"""
$expected = '{escaped_code}'
$paths = @(
  (Join-Path $env:LOCALAPPDATA 'Amazon Web Services\Amazon WorkSpaces\UserSettings.json'),
  (Join-Path $env:APPDATA 'Amazon Web Services\Amazon WorkSpaces\RegistrationList.json')
)
$found = $false
$matched = $false
foreach ($path in $paths) {{
  if (Test-Path -LiteralPath $path) {{
    $found = $true
    try {{
      $content = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
      if ($content.Contains($expected)) {{ $matched = $true }}
    }} catch {{}}
  }}
}}
if (-not $found) {{ Write-Output 'NOT_VERIFIABLE'; exit 0 }}
if ($matched) {{ Write-Output 'VALID'; exit 0 }}
Write-Output 'MISMATCH'
exit 0
"""
    inspected = win_tool.execute_winrm_ps(selected, script)
    output = str(inspected.get("stdout") or "").strip().upper()
    if inspected.get("status") != "success" or output not in {
        "VALID",
        "MISMATCH",
        "NOT_VERIFIABLE",
    }:
        output = "NOT_VERIFIABLE"
    if output == "VALID":
        return _check(
            "pass",
            "authorized_windows_client",
            "The authorized WorkSpaces client registration matches the assigned directory.",
        )
    if output == "MISMATCH":
        return _check(
            "fail",
            "authorized_windows_client",
            "The authorized WorkSpaces client registration does not match the assigned directory.",
        )
    return _check(
        "not_verifiable",
        "authorized_windows_client",
        "WorkSpaces client registration metadata could not be verified.",
    )


def _mfa_check(context: Dict[str, Any]) -> Dict[str, str]:
    value = context.get("mfa_directory_status")
    if value == "enabled":
        return _check(
            "pass",
            "aws.directoryservice.DescribeDirectories",
            "Directory-level RADIUS/MFA configuration is enabled; individual user enrollment is not verifiable.",
        )
    if value == "disabled":
        return _check(
            "fail",
            "aws.directoryservice.DescribeDirectories",
            "Directory-level RADIUS/MFA configuration was not found; individual user enrollment is not inferred.",
        )
    return _check(
        "not_verifiable",
        "aws.directoryservice.DescribeDirectories",
        "Directory-level MFA configuration and individual user enrollment could not be verified.",
    )


def _inactivity_check(mode: str, context: Dict[str, Any]) -> Dict[str, str]:
    if mode == "demo":
        value = context.get("inactivity_access_status")
        if value == "pass":
            return _check(
                "pass",
                "demo_fixture",
                "The demo fixture reports inactivity access valid.",
            )
        if value == "fail":
            return _check(
                "fail",
                "demo_fixture",
                "The demo fixture reports access disabled by inactivity policy.",
            )
    return _check(
        "not_verifiable",
        "customer_policy_source_unavailable",
        "Standard AWS APIs do not expose the customer's exact inactivity-disable policy state.",
    )


def _login_finding(
    workspace: Dict[str, Any],
    checks: Dict[str, Dict[str, Any]],
    reported_error_category: str,
) -> Tuple[str, str, str]:
    if not workspace.get("assigned"):
        return (
            "WORKSPACE_NOT_ASSIGNED",
            "Your identity was resolved, but AWS shows no WorkSpace assigned to the explicitly mapped directory user.",
            "Escalate WorkSpace assignment through the existing ServiceNow process.",
        )
    if reported_error_category == "not_authorized":
        if checks["registration"]["status"] == "fail":
            return (
                "REGISTRATION_CONFIGURATION_MISMATCH",
                "The authorized WorkSpaces client registration does not match the assigned directory.",
                "Update the WorkSpaces client registration using KB0019144 guidance.",
            )
        if checks["registration"]["status"] == "not_verifiable":
            return (
                "REGISTRATION_CONFIGURATION_NOT_VERIFIABLE",
                "AWS confirms the WorkSpace assignment, but client registration could not be verified without an authorized reachable client endpoint.",
                "Verify the WorkSpaces client registration using KB0019144 guidance or create a ServiceNow incident.",
            )
        if checks["account_enabled"]["status"] == "fail":
            return (
                "DOMAIN_ACCOUNT_DISABLED",
                "Assignment and registration were checked first; the protected domain-account check reports the account disabled.",
                "Use the separately governed Account Access enable flow only with explicit user consent.",
            )
        if checks["account_locked"]["status"] == "fail":
            return (
                "DOMAIN_ACCOUNT_LOCKED",
                "Assignment and registration were checked first; the protected domain-account check reports the account locked.",
                "Use the separately governed Account Access unlock flow only with explicit user consent.",
            )
        if checks["workspace_available"]["status"] == "fail":
            return (
                "WORKSPACE_NOT_AVAILABLE",
                f"AWS reports the assigned WorkSpace in state {workspace.get('state') or 'UNKNOWN'}.",
                "Follow KB0019144 state guidance or create a ServiceNow incident.",
            )
        return (
            "NO_ASSIGNMENT_OR_REGISTRATION_ISSUE_FOUND",
            "AWS shows an assigned WorkSpace and no verified registration mismatch. The reported authorization failure still requires WorkSpaces-specific KB guidance.",
            "Follow KB0019144 WorkSpaces credential guidance or create a ServiceNow incident; do not automatically reset the AD password.",
        )
    if checks["account_enabled"]["status"] == "fail":
        return (
            "DOMAIN_ACCOUNT_DISABLED",
            "The WorkSpace is assigned, but the protected domain-account check reports the account disabled.",
            "Use the separately governed Account Access enable flow only with explicit user consent.",
        )
    if checks["account_locked"]["status"] == "fail":
        return (
            "DOMAIN_ACCOUNT_LOCKED",
            "The WorkSpace is assigned, but the protected domain-account check reports the account locked.",
            "Use the separately governed Account Access unlock flow only with explicit user consent.",
        )
    if checks["workspace_available"]["status"] == "fail":
        return (
            "WORKSPACE_NOT_AVAILABLE",
            f"AWS reports the assigned WorkSpace in state {workspace.get('state') or 'UNKNOWN'}.",
            "Follow KB0019144 state guidance or create a ServiceNow incident.",
        )
    if checks["registration"]["status"] == "fail":
        return (
            "REGISTRATION_CONFIGURATION_MISMATCH",
            "The authorized WorkSpaces client registration does not match the assigned directory.",
            "Update the WorkSpaces client registration using KB0019144 guidance.",
        )
    if checks["mfa"]["status"] == "fail":
        return (
            "DIRECTORY_MFA_CONFIGURATION_NOT_ENABLED",
            "AWS Directory Service does not show completed directory-level RADIUS/MFA configuration. Individual enrollment was not inferred.",
            "Follow the customer's MFA onboarding/escalation guidance.",
        )
    return (
        "NO_AWS_CONTROL_PLANE_CAUSE_FOUND",
        "No assignment, WorkSpace-state, or verified registration cause was found. This does not prove the password is wrong.",
        "Follow KB0019144 WorkSpaces-specific credential guidance or create a ServiceNow incident; do not automatically reset the AD password or route to Windows remediation.",
    )


def _aws_error_message(code: str) -> str:
    messages = {
        "AWS_SDK_UNAVAILABLE": "The AWS SDK dependency is unavailable; AWS WorkSpaces was not checked.",
        "AWS_CREDENTIALS_UNAVAILABLE": "AWS credentials are unavailable; AWS WorkSpaces was not checked.",
        "AWS_CREDENTIALS_INVALID": "AWS credentials are invalid or expired; AWS WorkSpaces was not checked.",
        "AWS_ACCESS_DENIED": "AWS denied the read-only diagnostic request; AWS WorkSpaces could not be checked.",
        "AWS_RESOURCE_OR_REGION_INVALID": "The mapped AWS directory or Region is invalid or unavailable.",
        "AWS_API_TIMEOUT_OR_ENDPOINT_ERROR": "The AWS diagnostic request timed out or the regional endpoint was unavailable.",
        "AWS_RESPONSE_INVALID": "AWS returned an invalid diagnostic response.",
        "AWS_WORKSPACES_MULTIPLE_UNEXPECTED": "AWS returned multiple WorkSpaces for one mapped directory user; diagnosis stopped safely.",
        "AWS_WORKSPACES_DEMO_FIXTURE_NOT_CONFIGURED": "Demo mode is explicit but its fixture path is not configured.",
        "AWS_WORKSPACES_DEMO_FIXTURE_MALFORMED": "The configured WorkSpaces demo fixture is malformed.",
        "AWS_WORKSPACES_DEMO_FIXTURE_ENTRY_NOT_FOUND": "The demo fixture has no exact entry for the explicit user mapping.",
        "AWS_API_ERROR": "The read-only AWS diagnostic request failed.",
    }
    return messages.get(code, "The read-only AWS diagnostic request failed.")


def _prepare(
    target_upn: str,
    tool_context: ToolContext,
) -> Tuple[Optional[str], Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
    mode = _mode()
    if mode not in VALID_MODES:
        return (
            None,
            None,
            _error(
                "AWS_WORKSPACES_MODE_INVALID",
                "AWS_WORKSPACES_MODE must be off, demo, or aws; AWS WorkSpaces was not checked.",
            ),
        )
    if mode == "off":
        return (
            None,
            None,
            _error(
                "AWS_WORKSPACES_BACKEND_OFF",
                "AWS WorkSpaces diagnosis is off; configure AWS_WORKSPACES_MODE=aws for real read-only checks.",
            ),
        )
    caller_upn, authorization_error = _authorize_self(target_upn, tool_context)
    if authorization_error is not None or caller_upn is None:
        return None, None, authorization_error
    mapping, mapping_error = _load_mapping(caller_upn)
    if mapping_error is not None or mapping is None:
        return None, None, mapping_error
    return mode, mapping, None


def _normalize_reported_error_category(value: str) -> str:
    category = str(value or "unspecified").strip().lower()
    return category if category in VALID_REPORTED_ERROR_CATEGORIES else "other"


def _query_cloudwatch_metrics(
    region: str,
    workspace_id: str,
) -> Tuple[Dict[str, Dict[str, Any]], Optional[Dict[str, str]]]:
    metrics = {
        spec["key"]: _metric_unavailable(spec["statistic"])
        for spec in _METRIC_SPECS.values()
    }
    try:
        client = _boto3_client("cloudwatch", region)
        queries: List[Dict[str, Any]] = []
        ids: Dict[str, Dict[str, str]] = {}
        for index, (metric_name, spec) in enumerate(_METRIC_SPECS.items()):
            query_id = f"m{index}"
            ids[query_id] = spec
            queries.append(
                {
                    "Id": query_id,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/WorkSpaces",
                            "MetricName": metric_name,
                            "Dimensions": [
                                {"Name": "WorkspaceId", "Value": workspace_id}
                            ],
                        },
                        "Period": 300,
                        "Stat": spec["statistic"],
                    },
                    "ReturnData": True,
                }
            )
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=_lookback_minutes())
        response = _call_aws(
            client,
            "get_metric_data",
            MetricDataQueries=queries,
            StartTime=start_time,
            EndTime=end_time,
            ScanBy="TimestampDescending",
            MaxDatapoints=10000,
        )
        results = response.get("MetricDataResults") or []
        if not isinstance(results, list):
            raise _AwsCallError("AWS_RESPONSE_INVALID")
        for result in results:
            if not isinstance(result, dict):
                continue
            spec = ids.get(str(result.get("Id") or ""))
            if spec is None:
                continue
            values = result.get("Values") or []
            timestamps = result.get("Timestamps") or []
            if not isinstance(values, list) or not isinstance(timestamps, list):
                continue
            if not values or not timestamps or isinstance(values[0], bool):
                continue
            try:
                value = float(values[0])
            except (TypeError, ValueError):
                continue
            metrics[spec["key"]] = {
                "status": "available",
                "value": value,
                "timestamp": _iso(timestamps[0]),
                "statistic": spec["statistic"],
                "unit": spec["unit"],
            }
        return metrics, None
    except _AwsCallError as exc:
        return metrics, {
            "source": "aws.cloudwatch.GetMetricData",
            "code": exc.code,
        }


def _demo_metrics(context: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    raw_metrics = context.get("metrics")
    raw_metrics = raw_metrics if isinstance(raw_metrics, dict) else {}
    metrics: Dict[str, Dict[str, Any]] = {}
    for metric_name, spec in _METRIC_SPECS.items():
        raw = raw_metrics.get(metric_name)
        if not isinstance(raw, dict) or raw.get("value") is None:
            metrics[spec["key"]] = _metric_unavailable(spec["statistic"])
            continue
        value = raw.get("value")
        if isinstance(value, bool):
            raise _AwsCallError("AWS_WORKSPACES_DEMO_FIXTURE_MALFORMED")
        try:
            normalized_value = float(value)
        except (TypeError, ValueError) as exc:
            raise _AwsCallError("AWS_WORKSPACES_DEMO_FIXTURE_MALFORMED") from exc
        metrics[spec["key"]] = {
            "status": "available",
            "value": normalized_value,
            "timestamp": _iso(raw.get("timestamp")),
            "statistic": spec["statistic"],
            "unit": spec["unit"],
        }
    return metrics


def _performance_finding(
    workspace: Dict[str, Any],
    connection: Dict[str, Any],
    metrics: Dict[str, Dict[str, Any]],
) -> Tuple[str, str, str]:
    if not workspace.get("assigned"):
        return (
            "WORKSPACE_NOT_ASSIGNED",
            "Your identity was resolved, but AWS shows no WorkSpace assigned to the explicitly mapped directory user.",
            "Escalate WorkSpace assignment through the existing ServiceNow process.",
        )
    if workspace.get("state") != "AVAILABLE":
        return (
            "WORKSPACE_NOT_AVAILABLE",
            f"AWS reports the WorkSpace in state {workspace.get('state') or 'UNKNOWN'}.",
            "Follow the WorkSpaces state guidance or create a ServiceNow incident.",
        )
    latency = metrics["in_session_latency_ms"]
    if (
        latency.get("status") == "available"
        and float(latency["value"]) > KB_LATENCY_THRESHOLD_MS
    ):
        value = float(latency["value"])
        return (
            "HIGH_IN_SESSION_LATENCY",
            f"The latest WorkSpaces round-trip latency is {value:g} ms, exceeding the KB0019144 threshold of 200 ms. Internet, ISP, or network path conditions may contribute; this does not prove the WorkSpace VM is defective.",
            "Follow the KB System File Cleanup guidance or create a ServiceNow incident; cleanup automation is not available in this phase.",
        )
    failures = metrics["connection_failure_count"]
    if failures.get("status") == "available" and float(failures["value"]) > 0:
        return (
            "RECENT_CONNECTION_FAILURES",
            f"CloudWatch reports {float(failures['value']):g} connection failure(s) in the recent diagnostic window.",
            "Review the network path and create a ServiceNow incident if failures continue.",
        )
    if not any(metric.get("status") == "available" for metric in metrics.values()):
        return (
            "NO_RECENT_SESSION_TELEMETRY",
            "CloudWatch returned no recent WorkSpaces session datapoints; missing data was not converted to zero.",
            "Retry during an active session or create a ServiceNow incident.",
        )
    if connection.get("state") == "DISCONNECTED":
        return (
            "WORKSPACE_DISCONNECTED",
            "AWS reports the WorkSpace disconnected. A disconnected state alone does not prove a fault.",
            "Retry the session and follow WorkSpaces connection guidance if the disconnect persists.",
        )
    return (
        "NO_KB_THRESHOLD_BREACH_DETECTED",
        "The latest InSessionLatency value does not exceed the KB0019144 threshold of 200 ms. Other metrics are observations only; no unsupported CPU, memory, disk, or packet threshold was applied.",
        "Continue WorkSpaces-specific troubleshooting or create a ServiceNow incident if symptoms persist.",
    )


def aws_diagnose_workspace_login(
    target_upn: str,
    tool_context: ToolContext,
    reported_error_category: str = "unspecified",
    client_endpoint: str = "",
) -> Dict[str, Any]:
    """Diagnose the authenticated caller's WorkSpaces login using read-only sources."""
    mode, mapping, prepare_error = _prepare(target_upn, tool_context)
    if prepare_error is not None or mode is None or mapping is None:
        return prepare_error or _error(
            "AWS_WORKSPACES_PRECHECK_FAILED", "AWS WorkSpaces was not checked."
        )
    try:
        context = _workspace_context(mode, mapping)
    except _AwsCallError as exc:
        return _error(exc.code, _aws_error_message(exc.code))

    target = _norm_upn(target_upn)
    workspace = context["workspace"]
    connection = context["connection"]
    category = _normalize_reported_error_category(reported_error_category)
    if category == "not_authorized":
        registration_check = _registration_check(
            mode, context, tool_context, client_endpoint
        )
        account_checks = _phase_b_account_checks(target, tool_context)
    else:
        account_checks = _phase_b_account_checks(target, tool_context)
        registration_check = _registration_check(
            mode, context, tool_context, client_endpoint
        )
    workspace_assigned = _check(
        "pass" if workspace.get("assigned") else "fail",
        "aws.workspaces.DescribeWorkspaces" if mode == "aws" else "demo_fixture",
        "AWS returned one WorkSpace for the explicit mapping."
        if workspace.get("assigned") and mode == "aws"
        else "The demo fixture returned one WorkSpace for the explicit mapping."
        if workspace.get("assigned")
        else "No WorkSpace was returned for the explicit directory-user mapping.",
    )
    if workspace.get("assigned"):
        workspace_available = _check(
            "pass" if workspace.get("state") == "AVAILABLE" else "fail",
            "aws.workspaces.DescribeWorkspaces" if mode == "aws" else "demo_fixture",
            f"The assigned WorkSpace state is {workspace.get('state') or 'UNKNOWN'}.",
        )
    else:
        workspace_available = _check(
            "not_applicable",
            "aws.workspaces.DescribeWorkspaces" if mode == "aws" else "demo_fixture",
            "WorkSpace availability is not applicable because no WorkSpace is assigned.",
        )
    checks: Dict[str, Dict[str, Any]] = {
        **account_checks,
        "workspace_assigned": workspace_assigned,
        "workspace_available": workspace_available,
        "registration": registration_check,
        "mfa": _mfa_check(context),
        "inactivity_access": _inactivity_check(mode, context),
    }
    finding_code, message, next_action = _login_finding(workspace, checks, category)
    diagnosis = {
        "issue_type": "login",
        "backend": mode,
        "target_upn": target,
        "region": mapping["region"],
        "workspace": workspace,
        "connection": connection,
        "checks": checks,
        "mfa_scope": "directory_configuration_only",
        "individual_mfa_enrollment": "not_verifiable",
        "reported_error_category": category,
        "finding_code": finding_code,
        "message": message,
        "recommended_next_action": next_action,
        "diagnostic_errors": context.get("diagnostic_errors") or [],
    }
    return {"status": "ok", "diagnosis": diagnosis}


def aws_diagnose_workspace_performance(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """Diagnose the authenticated caller's WorkSpaces performance read-only."""
    mode, mapping, prepare_error = _prepare(target_upn, tool_context)
    if prepare_error is not None or mode is None or mapping is None:
        return prepare_error or _error(
            "AWS_WORKSPACES_PRECHECK_FAILED", "AWS WorkSpaces was not checked."
        )
    try:
        context = _workspace_context(mode, mapping)
        workspace = context["workspace"]
        connection = context["connection"]
        metric_error: Optional[Dict[str, str]] = None
        if not workspace.get("assigned"):
            metrics = {
                spec["key"]: _metric_unavailable(spec["statistic"])
                for spec in _METRIC_SPECS.values()
            }
        elif mode == "demo":
            metrics = _demo_metrics(context)
        else:
            metrics, metric_error = _query_cloudwatch_metrics(
                mapping["region"], str(workspace["workspace_id"])
            )
    except _AwsCallError as exc:
        return _error(exc.code, _aws_error_message(exc.code))

    diagnostic_errors = list(context.get("diagnostic_errors") or [])
    if metric_error is not None:
        diagnostic_errors.append(metric_error)
    finding_code, message, next_action = _performance_finding(
        workspace, connection, metrics
    )
    diagnosis = {
        "issue_type": "performance",
        "backend": mode,
        "target_upn": _norm_upn(target_upn),
        "region": mapping["region"],
        "workspace_id": workspace.get("workspace_id"),
        "computer_name": workspace.get("computer_name"),
        "workspace_state": workspace.get("state"),
        "connection_state": connection.get("state"),
        "last_known_user_connection": connection.get("last_known_user_connection"),
        "metrics": metrics,
        "finding_code": finding_code,
        "kb_threshold_ms": int(KB_LATENCY_THRESHOLD_MS),
        "threshold_rule": "InSessionLatency > 200 ms",
        "message": message,
        "recommended_next_action": next_action,
        "system_file_cleanup": {
            "status": "not_automatable",
            "automatic_execution": False,
            "requires_separate_governed_flow": True,
            "message": _SYSTEM_FILE_CLEANUP_LIMITATION,
        },
        "diagnostic_errors": diagnostic_errors,
    }
    return {"status": "ok", "diagnosis": diagnosis}


aws_diagnose_workspace_login = FunctionTool(func=aws_diagnose_workspace_login)
aws_diagnose_workspace_performance = FunctionTool(
    func=aws_diagnose_workspace_performance
)

aws_workspaces_tools = [
    aws_diagnose_workspace_login,
    aws_diagnose_workspace_performance,
]
