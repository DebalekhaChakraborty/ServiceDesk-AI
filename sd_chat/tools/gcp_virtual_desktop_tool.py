"""Read-only Google Cloud Windows virtual-desktop diagnostics.

The public tools intentionally accept only the authenticated caller UPN. Project,
zone, instance, and Windows-user details are resolved from a trusted local mapping;
chat input can never select an arbitrary Compute Engine resource.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import unquote

from google.adk.tools import FunctionTool, ToolContext

from ..planner.reasoning_composer import propose_plan as _propose_plan
from .policy_tool import check_list as _check_list
from .sop_retriever import sop_retriever as _sop_retriever


SUPPORTED_MODES = {"off", "demo", "gcp"}
IAP_TCP_SOURCE_RANGE = "35.235.240.0/20"
RDP_USER_INPUT_DELAY_THRESHOLD_MS = 200.0
DEFAULT_LOOKBACK_MINUTES = 30
DEFAULT_TELEMETRY_FRESHNESS_MINUTES = 10
DEFAULT_LOG_LIMIT = 100
DEFAULT_DEMO_FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "gcp_virtual_desktop_demo.json"
)

_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_ZONE_RE = re.compile(r"^[a-z][a-z0-9-]+-[a-z]$")
_INSTANCE_RE = re.compile(r"^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_WINDOWS_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,20}$")

_METRIC_SPECS = {
    "cpu": {
        "type": "compute.googleapis.com/instance/cpu/utilization",
    },
    "memory_percent_used": {
        "type": "agent.googleapis.com/memory/percent_used",
        "metric_filter": 'metric.labels.state = "used"',
    },
    "disk_percent_used": {
        "type": "agent.googleapis.com/disk/percent_used",
        "metric_filter": 'metric.labels.state = "used"',
        "select": "max",
    },
    "network_received_bytes": {
        "type": "compute.googleapis.com/instance/network/received_bytes_count",
    },
    "network_sent_bytes": {
        "type": "compute.googleapis.com/instance/network/sent_bytes_count",
    },
}

_AUTH_FAILURE_EVENT_IDS = {4625}
_DISCONNECT_EVENT_IDS = {24, 40, 4779}
_SESSION_EVENT_IDS = {21, 22, 23, 24, 25, 40, 1149, 4778, 4779}
_SECURITY_CHANNEL = "Security"
_LSM_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
_RCM_CHANNEL = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
_SECURITY_RDP_EVENT_IDS = {4625, 4778, 4779}
_LSM_RDP_EVENT_IDS = {21, 22, 23, 24, 25, 40}
_RCM_RDP_EVENT_IDS = {1149}

_ORCHESTRATION_SPECS = {
    "login": {
        "action_id": "gcp.virtual_desktop.diagnose_login",
        "tool": "gcp_virtual_desktop_tool",
        "action": "diagnose_virtual_desktop_login",
        "step": "Validate the GCP virtual desktop state and recent RDP login/session health.",
        "sop_query": "GCP virtual desktop login and RDP session diagnosis",
    },
    "performance": {
        "action_id": "gcp.virtual_desktop.diagnose_performance",
        "tool": "gcp_virtual_desktop_tool",
        "action": "diagnose_virtual_desktop_performance",
        "step": "Check the GCP virtual desktop's host performance and Remote Desktop responsiveness.",
        "sop_query": "GCP virtual desktop performance and RDP responsiveness diagnosis",
    },
}


class _MappingError(ValueError):
    """A private mapping is missing or invalid."""


def _mode() -> str:
    return (os.getenv("GCP_VDI_MODE") or "off").strip().lower()


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int((os.getenv(name) or str(default)).strip())
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, value))


def _norm_upn(value: Any) -> str:
    return str(value or "").strip().lower()


def _error(code: str, message: str, backend: str) -> Dict[str, Any]:
    return {
        "status": "error",
        "code": code,
        "message": message,
        "backend": backend,
    }


def _identity_upn(tool_context: ToolContext) -> str:
    state = tool_context.state if tool_context is not None else None
    if state is None:
        return ""
    identity = state.get("identity_context")
    if not isinstance(identity, Mapping):
        return ""
    return _norm_upn(identity.get("upn"))


def _validate_mapping_entry(raw: Any) -> Dict[str, str]:
    if not isinstance(raw, Mapping):
        raise _MappingError("entry_not_object")

    entry = {
        "project_id": str(raw.get("project_id") or "").strip(),
        "zone": str(raw.get("zone") or "").strip(),
        "instance_name": str(raw.get("instance_name") or "").strip(),
        "windows_username": str(raw.get("windows_username") or "").strip(),
    }
    if not _PROJECT_RE.fullmatch(entry["project_id"]):
        raise _MappingError("invalid_project_id")
    if not _ZONE_RE.fullmatch(entry["zone"]):
        raise _MappingError("invalid_zone")
    if not _INSTANCE_RE.fullmatch(entry["instance_name"]):
        raise _MappingError("invalid_instance_name")
    if not _WINDOWS_USER_RE.fullmatch(entry["windows_username"]):
        raise _MappingError("invalid_windows_username")
    return entry


def _mapping_for(caller_upn: str) -> Dict[str, str]:
    configured_path = (os.getenv("GCP_VDI_MAPPING_PATH") or "").strip()
    if not configured_path:
        raise _MappingError("mapping_path_not_configured")

    try:
        payload = json.loads(Path(configured_path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise _MappingError("mapping_file_missing") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise _MappingError("mapping_file_invalid") from exc

    if not isinstance(payload, Mapping):
        raise _MappingError("mapping_root_not_object")

    normalized = {
        _norm_upn(key): value for key, value in payload.items() if _norm_upn(key)
    }
    if caller_upn not in normalized:
        raise KeyError(caller_upn)
    return _validate_mapping_entry(normalized[caller_upn])


def _resolve_request(
    target_upn: str,
    tool_context: ToolContext,
) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
    configured_mode = _mode()
    if configured_mode not in SUPPORTED_MODES:
        return None, _error(
            "GCP_VDI_MODE_INVALID",
            "GCP virtual desktop diagnosis has an invalid backend mode.",
            configured_mode or "unconfigured",
        )
    if configured_mode == "off":
        return None, _error(
            "GCP_VDI_BACKEND_OFF",
            "GCP virtual desktop diagnosis is disabled.",
            "off",
        )

    caller_upn = _identity_upn(tool_context)
    requested_upn = _norm_upn(target_upn)
    if not caller_upn:
        return None, _error(
            "GCP_VDI_CALLER_UNKNOWN",
            "The authenticated caller identity is unavailable.",
            configured_mode,
        )
    if not requested_upn or requested_upn != caller_upn:
        return None, _error(
            "GCP_VDI_SELF_SERVICE_ONLY",
            "GCP virtual desktop diagnosis is currently available only for the authenticated caller's assigned desktop.",
            configured_mode,
        )

    try:
        mapping = _mapping_for(caller_upn)
    except KeyError:
        return None, _error(
            "GCP_VDI_MAPPING_NOT_FOUND",
            "No GCP virtual desktop is assigned to the authenticated caller.",
            configured_mode,
        )
    except _MappingError:
        return None, _error(
            "GCP_VDI_MAPPING_INVALID",
            "The trusted GCP virtual desktop mapping is missing or invalid.",
            configured_mode,
        )

    return mapping, None


def _orchestration_gate(
    issue_type: str,
    target_upn: str,
    tool_context: ToolContext,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Enforce SOP -> exact atomic plan -> policy before any backend read.

    The root model owns semantic routing, but it is not a security boundary.  This
    controller therefore repeats the approved orchestration deterministically so
    an automatic tool call cannot bypass a failed or invented plan.  SOP
    prerequisites remain in the knowledge article; the generic planner receives
    only the registry's single executable, read-only diagnostic step.
    """
    spec = _ORCHESTRATION_SPECS[issue_type]
    backend = _mode()

    try:
        retrieved = _sop_retriever(
            query=str(spec["sop_query"]),
            tool_context=tool_context,
        )
    except Exception:
        retrieved = {"status": "error"}

    meta = retrieved.get("meta") if isinstance(retrieved, Mapping) else None
    try:
        results_count = (
            int(meta.get("results_count", 0)) if isinstance(meta, Mapping) else 0
        )
    except (TypeError, ValueError):
        results_count = 0
    if not isinstance(retrieved, Mapping) or retrieved.get("status") != "ok":
        return None, _error(
            "GCP_VDI_SOP_RETRIEVAL_FAILED",
            "The approved GCP virtual desktop SOP could not be retrieved; diagnosis was not run.",
            backend,
        )
    if results_count < 1:
        return None, _error(
            "GCP_VDI_SOP_NOT_FOUND",
            "No approved GCP virtual desktop SOP was found; diagnosis was not run.",
            backend,
        )

    canonical_step = str(spec["step"])
    try:
        planned = _propose_plan(
            user_text=canonical_step,
            ctx_vars=["target_upn"],
            sop_texts=[canonical_step],
        )
    except Exception:
        planned = {"status": "error"}

    plan = planned.get("plan") if isinstance(planned, Mapping) else None
    sequence = plan.get("tool_sequence") if isinstance(plan, Mapping) else None
    unmapped = plan.get("unmapped") if isinstance(plan, Mapping) else None
    step = sequence[0] if isinstance(sequence, list) and len(sequence) == 1 else None
    exact_action = bool(
        isinstance(step, Mapping)
        and step.get("action_id") == spec["action_id"]
        and step.get("tool") == spec["tool"]
        and step.get("action") == spec["action"]
    )
    plan_safe = bool(
        isinstance(planned, Mapping)
        and planned.get("status") == "ok"
        and isinstance(plan, Mapping)
        and plan.get("can_execute_fully") is True
        and plan.get("low_confidence") is False
        and plan.get("required_inputs") == []
        and unmapped == []
        and exact_action
    )
    if not plan_safe:
        return None, _error(
            "GCP_VDI_PLAN_NOT_EXECUTABLE",
            "The GCP virtual desktop diagnosis did not produce one exact, fully mapped high-confidence action; diagnosis was not run.",
            backend,
        )

    preconditions = plan.get("preconditions")
    if not isinstance(preconditions, list) or not all(
        isinstance(value, str) for value in preconditions
    ):
        return None, _error(
            "GCP_VDI_PLAN_NOT_EXECUTABLE",
            "The GCP virtual desktop plan preconditions were invalid; diagnosis was not run.",
            backend,
        )

    try:
        policy = _check_list(
            preconditions=preconditions,
            caller_upn=target_upn,
            target_upn=target_upn,
            tool_context=tool_context,
        )
    except Exception:
        policy = {"status": "error"}
    if not isinstance(policy, Mapping) or policy.get("status") != "ok":
        return None, _error(
            "GCP_VDI_POLICY_DENIED",
            "The GCP virtual desktop diagnosis policy check did not pass; diagnosis was not run.",
            backend,
        )

    return {
        "sop_retrieved": True,
        "sop_results_count": results_count,
        "plan_action_id": spec["action_id"],
        "plan_confidence": plan.get("confidence"),
        "policy_status": "ok",
    }, None


def _iso_timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    to_datetime = getattr(value, "ToDatetime", None)
    if callable(to_datetime):
        try:
            return _iso_timestamp(to_datetime(tzinfo=timezone.utc))
        except TypeError:
            return _iso_timestamp(to_datetime())
    return None


def _point_value(point: Any) -> Optional[float]:
    value = getattr(point, "value", None)
    if value is None:
        return None
    protobuf_value = getattr(value, "_pb", value)
    which = getattr(protobuf_value, "WhichOneof", None)
    kind = which("value") if callable(which) else None
    if kind not in {"double_value", "int64_value"}:
        return None
    try:
        return float(getattr(value, kind))
    except (TypeError, ValueError):
        return None


def _unavailable(reason: str = "no_recent_datapoint") -> Dict[str, Any]:
    return {"status": "unavailable", "value": None, "timestamp": None, "reason": reason}


def _metric_observation(
    monitoring_client: Any,
    project_id: str,
    instance_id: str,
    spec: Mapping[str, str],
    start_time: datetime,
    end_time: datetime,
) -> Dict[str, Any]:
    metric_type = spec["type"]
    filters = [
        f'metric.type = "{metric_type}"',
        'resource.type = "gce_instance"',
        f'resource.labels.instance_id = "{instance_id}"',
    ]
    if spec.get("metric_filter"):
        filters.append(str(spec["metric_filter"]))

    request = {
        "name": f"projects/{project_id}",
        "filter": " AND ".join(filters),
        "interval": {"start_time": start_time, "end_time": end_time},
        "view": 0,
    }
    candidates: List[Tuple[float, Optional[str]]] = []
    for series in monitoring_client.list_time_series(request=request):
        for point in list(getattr(series, "points", []) or [])[:1]:
            value = _point_value(point)
            timestamp = _iso_timestamp(
                getattr(getattr(point, "interval", None), "end_time", None)
            )
            if value is not None:
                candidates.append((value, timestamp))

    if not candidates:
        return _unavailable()
    if spec.get("select") == "max":
        value, timestamp = max(candidates, key=lambda candidate: candidate[0])
    else:
        value, timestamp = candidates[0]
    return {
        "status": "available",
        "value": value,
        "timestamp": timestamp,
        "metric_type": metric_type,
    }


def _collect_metrics(
    project_id: str, instance_id: str
) -> Tuple[Dict[str, Any], List[str]]:
    from google.cloud import monitoring_v3

    client = monitoring_v3.MetricServiceClient()
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(
        minutes=_bounded_int(
            "GCP_VDI_LOOKBACK_MINUTES",
            DEFAULT_LOOKBACK_MINUTES,
            5,
            1440,
        )
    )
    observations: Dict[str, Any] = {}
    errors: List[str] = []
    for name, spec in _METRIC_SPECS.items():
        try:
            observations[name] = _metric_observation(
                client,
                project_id,
                instance_id,
                spec,
                start_time,
                end_time,
            )
        except Exception:
            observations[name] = _unavailable("query_failed")
            errors.append(f"metric:{name}:query_failed")
    return observations, errors


def _instance_uptime_observation(
    instance: Any,
    observed_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Return Compute Engine running duration, not a latest delta metric bucket."""
    if str(getattr(instance, "status", "") or "") != "RUNNING":
        return _unavailable("instance_not_running")

    started_at = _iso_timestamp(getattr(instance, "last_start_timestamp", None))
    if not started_at:
        return _unavailable("last_start_timestamp_unavailable")
    try:
        start_time = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except ValueError:
        return _unavailable("last_start_timestamp_invalid")
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=timezone.utc)

    now = observed_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    uptime_seconds = (
        now.astimezone(timezone.utc) - start_time.astimezone(timezone.utc)
    ).total_seconds()
    if uptime_seconds < 0:
        return _unavailable("last_start_timestamp_in_future")
    return {
        "status": "available",
        "value": round(uptime_seconds, 3),
        "timestamp": _iso_timestamp(now),
        "source": "compute_instance_last_start_timestamp",
        "started_at": started_at,
    }


def _find_payload_value(payload: Any, names: Iterable[str], depth: int = 0) -> Any:
    if depth > 5:
        return None
    wanted = {name.lower() for name in names}
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if str(key).lower() in wanted and not isinstance(value, (Mapping, list)):
                return value
        for value in payload.values():
            found = _find_payload_value(value, wanted, depth + 1)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = _find_payload_value(value, wanted, depth + 1)
            if found is not None:
                return found
    return None


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1"}:
            return True
        if normalized in {"false", "0"}:
            return False
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    return None


def _log_id(log_name: str) -> str:
    marker = "/logs/"
    return unquote(log_name.split(marker, 1)[-1]) if marker in log_name else log_name


def _is_relevant_rdp_event(event_id: int, channel: str) -> bool:
    normalized_channel = channel.strip().casefold()
    return (
        (
            normalized_channel == _SECURITY_CHANNEL.casefold()
            and event_id in _SECURITY_RDP_EVENT_IDS
        )
        or (
            normalized_channel == _LSM_CHANNEL.casefold()
            and event_id in _LSM_RDP_EVENT_IDS
        )
        or (
            normalized_channel == _RCM_CHANNEL.casefold()
            and event_id in _RCM_RDP_EVENT_IDS
        )
    )


def _collect_logs(
    project_id: str,
    instance_id: str,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
    from google.cloud import logging_v2

    client = logging_v2.Client(project=project_id)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(
        minutes=_bounded_int(
            "GCP_VDI_LOOKBACK_MINUTES",
            DEFAULT_LOOKBACK_MINUTES,
            5,
            1440,
        )
    )
    telemetry_start_time = end_time - timedelta(
        minutes=_bounded_int(
            "GCP_VDI_TELEMETRY_FRESHNESS_MINUTES",
            DEFAULT_TELEMETRY_FRESHNESS_MINUTES,
            1,
            60,
        )
    )
    start_iso = _iso_timestamp(start_time)
    telemetry_start_iso = _iso_timestamp(telemetry_start_time)
    resource_filter = (
        f'resource.type="gce_instance" AND resource.labels.instance_id="{instance_id}" '
    )
    telemetry_filter = (
        resource_filter
        + f'AND timestamp>="{telemetry_start_iso}" '
        + f'AND logName="projects/{project_id}/logs/servicedesk_rdp_telemetry"'
    )

    def channel_event_filter(channel: str, event_ids: Iterable[int]) -> str:
        ids = " OR ".join(
            f"jsonPayload.EventID={event_id}" for event_id in sorted(event_ids)
        )
        return f'(jsonPayload.Channel="{channel}" AND ({ids}))'

    event_scope_filter = " OR ".join(
        (
            channel_event_filter(_SECURITY_CHANNEL, _SECURITY_RDP_EVENT_IDS),
            channel_event_filter(_LSM_CHANNEL, _LSM_RDP_EVENT_IDS),
            channel_event_filter(_RCM_CHANNEL, _RCM_RDP_EVENT_IDS),
        )
    )
    events_filter = (
        resource_filter + f'AND timestamp>="{start_iso}" ' + "AND ("
        f'logName="projects/{project_id}/logs/windows_event_log" OR '
        f'logName="projects/{project_id}/logs/servicedesk_rdp_events"'
        f") AND ({event_scope_filter})"
    )

    telemetry: Dict[str, Any] = _unavailable("no_recent_rdp_telemetry")
    events: List[Dict[str, Any]] = []
    errors: List[str] = []
    try:
        telemetry_entries = client.list_entries(
            resource_names=[f"projects/{project_id}"],
            filter_=telemetry_filter,
            order_by=logging_v2.DESCENDING,
            max_results=1,
            page_size=1,
        )
        for entry in telemetry_entries:
            payload = getattr(entry, "payload", {}) or {}
            timestamp = _iso_timestamp(getattr(entry, "timestamp", None))
            delay = _find_payload_value(payload, {"max_user_input_delay_ms"})
            session_active = _as_bool(_find_payload_value(payload, {"session_active"}))
            session_count = _as_int(_find_payload_value(payload, {"session_count"}))
            counter_available = _as_bool(
                _find_payload_value(payload, {"counter_available"})
            )
            observed_at = (
                _iso_timestamp(_find_payload_value(payload, {"timestamp"})) or timestamp
            )
            try:
                numeric_delay = float(delay) if delay is not None else None
            except (TypeError, ValueError):
                numeric_delay = None
            measurement_available = (
                session_active is True
                and counter_available is not False
                and numeric_delay is not None
            )
            if session_active is not True:
                reason = "no_active_rdp_session"
            elif counter_available is False or numeric_delay is None:
                reason = "counter_value_unavailable"
            else:
                reason = None
            telemetry = {
                "status": "available" if measurement_available else "unavailable",
                "value": numeric_delay if measurement_available else None,
                "timestamp": observed_at,
                "session_active": session_active is True,
                "session_count": session_count,
                "counter_available": counter_available,
                "source": "windows_user_input_delay",
                "reason": reason,
            }
            break
    except Exception:
        errors.append("telemetry_query_failed")
        telemetry = _unavailable("telemetry_query_failed")

    log_limit = _bounded_int("GCP_VDI_LOG_LIMIT", DEFAULT_LOG_LIMIT, 1, 500)
    try:
        event_entries = client.list_entries(
            resource_names=[f"projects/{project_id}"],
            filter_=events_filter,
            order_by=logging_v2.DESCENDING,
            max_results=log_limit,
            page_size=log_limit,
        )
        for entry in event_entries:
            payload = getattr(entry, "payload", {}) or {}
            timestamp = _iso_timestamp(getattr(entry, "timestamp", None))
            current_log_id = _log_id(str(getattr(entry, "log_name", "") or ""))

            event_id = _as_int(
                _find_payload_value(payload, {"eventid", "event_id", "id"})
            )
            if event_id is None or event_id not in (
                _AUTH_FAILURE_EVENT_IDS | _DISCONNECT_EVENT_IDS | _SESSION_EVENT_IDS
            ):
                continue
            channel = str(
                _find_payload_value(payload, {"channel", "logname", "providername"})
                or current_log_id
            )
            if not _is_relevant_rdp_event(event_id, channel):
                continue
            logon_type = _as_int(
                _find_payload_value(payload, {"logontype", "logon_type"})
            )
            if event_id in _AUTH_FAILURE_EVENT_IDS and logon_type != 10:
                continue
            if event_id in _AUTH_FAILURE_EVENT_IDS:
                category = "authentication_failure"
            elif event_id in _DISCONNECT_EVENT_IDS:
                category = "disconnect"
            else:
                category = "session"
            events.append(
                {
                    "timestamp": timestamp,
                    "event_id": event_id,
                    "channel": channel,
                    "category": category,
                }
            )
    except Exception:
        errors.append("rdp_event_query_failed")
    return telemetry, events, errors


def _allows_tcp_port(allowed: Any, port: str) -> bool:
    protocol = str(
        getattr(allowed, "I_p_protocol", None)
        or getattr(allowed, "ip_protocol", None)
        or ""
    ).lower()
    if protocol not in {"tcp", "all"}:
        return False
    ports = [str(value) for value in (getattr(allowed, "ports", None) or [])]
    if not ports:
        return True
    for candidate in ports:
        if candidate == port:
            return True
        if "-" in candidate:
            try:
                lower, upper = (int(value) for value in candidate.split("-", 1))
                if lower <= int(port) <= upper:
                    return True
            except ValueError:
                continue
    return False


def _network_access(
    project_id: str,
    instance: Any,
) -> Tuple[Dict[str, Any], List[str]]:
    from google.cloud import compute_v1

    interfaces = list(getattr(instance, "network_interfaces", []) or [])
    networks = {
        str(getattr(interface, "network", "") or "").rsplit("/", 1)[-1]
        for interface in interfaces
    }
    has_external_ip = any(
        bool(
            getattr(access_config, "nat_i_p", None)
            or getattr(access_config, "nat_ip", None)
        )
        for interface in interfaces
        for access_config in list(getattr(interface, "access_configs", []) or [])
    )
    instance_tags = set(getattr(getattr(instance, "tags", None), "items", []) or [])
    iap_allowed = False
    public_allowed = False
    errors: List[str] = []
    try:
        for firewall in compute_v1.FirewallsClient().list(project=project_id):
            if getattr(firewall, "disabled", False):
                continue
            if str(getattr(firewall, "direction", "INGRESS") or "INGRESS") != "INGRESS":
                continue
            network_name = str(getattr(firewall, "network", "") or "").rsplit("/", 1)[
                -1
            ]
            if network_name not in networks:
                continue
            target_tags = set(getattr(firewall, "target_tags", []) or [])
            if target_tags and not (target_tags & instance_tags):
                continue
            if not any(
                _allows_tcp_port(rule, "3389")
                for rule in (getattr(firewall, "allowed", []) or [])
            ):
                continue
            sources = set(getattr(firewall, "source_ranges", []) or [])
            iap_allowed = iap_allowed or IAP_TCP_SOURCE_RANGE in sources
            public_allowed = public_allowed or "0.0.0.0/0" in sources
    except Exception:
        errors.append("firewall_query_failed")

    return {
        "status": "available" if not errors else "partially_available",
        "external_ip": has_external_ip,
        "iap_tcp_3389_allowed": iap_allowed,
        "public_tcp_3389_rule_present": public_allowed,
        "public_rdp_exposed": bool(has_external_ip and public_allowed),
    }, errors


def _load_gcp_snapshot(mapping: Mapping[str, str]) -> Dict[str, Any]:
    from google.api_core.exceptions import NotFound
    from google.cloud import compute_v1

    project_id = mapping["project_id"]
    zone = mapping["zone"]
    instance_name = mapping["instance_name"]
    try:
        instance = compute_v1.InstancesClient().get(
            project=project_id,
            zone=zone,
            instance=instance_name,
        )
    except NotFound:
        return {
            "instance": {
                "exists": False,
                "id": None,
                "name": instance_name,
                "status": "NOT_FOUND",
            },
            "metrics": {},
            "rdp_telemetry": _unavailable("instance_not_found"),
            "events": [],
            "network_access": {"status": "unavailable"},
            "collection_errors": [],
        }

    instance_id = str(getattr(instance, "id", "") or "")
    metrics, metric_errors = _collect_metrics(project_id, instance_id)
    metrics["uptime_seconds"] = _instance_uptime_observation(instance)
    telemetry, events, logging_errors = _collect_logs(project_id, instance_id)
    network_access, network_errors = _network_access(project_id, instance)
    return {
        "instance": {
            "exists": True,
            "id": instance_id,
            "name": str(getattr(instance, "name", instance_name) or instance_name),
            "status": str(getattr(instance, "status", "UNKNOWN") or "UNKNOWN"),
        },
        "metrics": metrics,
        "rdp_telemetry": telemetry,
        "events": events,
        "network_access": network_access,
        "collection_errors": metric_errors + logging_errors + network_errors,
    }


def _load_demo_snapshot(mapping: Mapping[str, str]) -> Dict[str, Any]:
    fixture_path = Path(
        (
            os.getenv("GCP_VDI_DEMO_FIXTURE_PATH") or str(DEFAULT_DEMO_FIXTURE_PATH)
        ).strip()
    )
    scenario = (os.getenv("GCP_VDI_DEMO_SCENARIO") or "running_healthy").strip()
    try:
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))
        scenarios = payload["scenarios"]
        snapshot = scenarios[scenario]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("invalid_demo_fixture") from exc
    if not isinstance(snapshot, Mapping):
        raise ValueError("invalid_demo_snapshot")
    cloned = json.loads(json.dumps(snapshot))
    instance = cloned.get("instance")
    if not isinstance(instance, dict):
        raise ValueError("invalid_demo_instance")
    instance["name"] = mapping["instance_name"]
    return cloned


def _latest_timestamp(snapshot: Mapping[str, Any]) -> Optional[str]:
    timestamps: List[str] = []
    metrics = snapshot.get("metrics")
    if isinstance(metrics, Mapping):
        timestamps.extend(
            str(item.get("timestamp"))
            for item in metrics.values()
            if isinstance(item, Mapping) and item.get("timestamp")
        )
    telemetry = snapshot.get("rdp_telemetry")
    if isinstance(telemetry, Mapping) and telemetry.get("timestamp"):
        timestamps.append(str(telemetry["timestamp"]))
    timestamps.extend(
        str(event.get("timestamp"))
        for event in (snapshot.get("events") or [])
        if isinstance(event, Mapping) and event.get("timestamp")
    )
    return max(timestamps) if timestamps else None


def _safe_events(snapshot: Mapping[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "timestamp": event.get("timestamp"),
            "event_id": event.get("event_id"),
            "channel": event.get("channel"),
            "category": event.get("category"),
        }
        for event in (snapshot.get("events") or [])
        if isinstance(event, Mapping)
    ]


def _base_diagnosis(
    issue_type: str,
    backend: str,
    target_upn: str,
    mapping: Mapping[str, str],
    snapshot: Mapping[str, Any],
) -> Dict[str, Any]:
    instance = (
        snapshot.get("instance")
        if isinstance(snapshot.get("instance"), Mapping)
        else {}
    )
    return {
        "issue_type": issue_type,
        "backend": backend,
        "target_upn": target_upn,
        "project_id": mapping["project_id"],
        "zone": mapping["zone"],
        "instance_name": mapping["instance_name"],
        "instance_id": instance.get("id"),
        "instance_state": instance.get("status", "UNKNOWN"),
        "read_only": True,
        "infrastructure_mutation_performed": False,
        "automatic_password_reset_performed": False,
    }


def _login_diagnosis(
    backend: str,
    target_upn: str,
    mapping: Mapping[str, str],
    snapshot: Mapping[str, Any],
) -> Dict[str, Any]:
    diagnosis = _base_diagnosis("login", backend, target_upn, mapping, snapshot)
    instance = (
        snapshot.get("instance")
        if isinstance(snapshot.get("instance"), Mapping)
        else {}
    )
    events = _safe_events(snapshot)
    auth_failures = [
        event for event in events if event.get("category") == "authentication_failure"
    ]
    disconnects = [event for event in events if event.get("category") == "disconnect"]
    telemetry = snapshot.get("rdp_telemetry")
    telemetry = telemetry if isinstance(telemetry, Mapping) else _unavailable()
    rdp_evidence_available = bool(events or telemetry.get("timestamp"))

    if not instance.get("exists"):
        finding = "VDI_INSTANCE_NOT_FOUND"
        message = "The assigned GCP virtual desktop was not found."
    elif instance.get("status") != "RUNNING":
        finding = "VDI_INSTANCE_NOT_RUNNING"
        message = f"The assigned GCP virtual desktop is {instance.get('status', 'not running')}."
    elif auth_failures:
        finding = "RDP_AUTH_FAILURE_DETECTED"
        message = "A recent Remote Desktop authentication failure was detected."
    elif disconnects:
        finding = "RDP_RECENT_DISCONNECT"
        message = "A recent Remote Desktop session disconnect was detected."
    elif not rdp_evidence_available:
        finding = "RDP_TELEMETRY_UNAVAILABLE"
        message = "No recent Remote Desktop session telemetry is available."
    else:
        finding = "NO_GCP_VDI_LOGIN_CAUSE_FOUND"
        message = (
            "The available read-only evidence did not identify a specific login cause."
        )

    diagnosis.update(
        {
            "rdp_telemetry": dict(telemetry),
            "recent_rdp_events": events,
            "recent_auth_failure_count": len(auth_failures),
            "recent_disconnect_count": len(disconnects),
            "telemetry_latest_timestamp": _latest_timestamp(snapshot),
            "access": snapshot.get("network_access") or {"status": "unavailable"},
            "collection_limitations": list(snapshot.get("collection_errors") or []),
            "finding_code": finding,
            "message": message,
        }
    )
    return {"status": "ok", "diagnosis": diagnosis}


def _performance_diagnosis(
    backend: str,
    target_upn: str,
    mapping: Mapping[str, str],
    snapshot: Mapping[str, Any],
) -> Dict[str, Any]:
    diagnosis = _base_diagnosis("performance", backend, target_upn, mapping, snapshot)
    instance = (
        snapshot.get("instance")
        if isinstance(snapshot.get("instance"), Mapping)
        else {}
    )
    events = _safe_events(snapshot)
    disconnects = [event for event in events if event.get("category") == "disconnect"]
    telemetry = snapshot.get("rdp_telemetry")
    telemetry = dict(telemetry) if isinstance(telemetry, Mapping) else _unavailable()
    metrics = dict(snapshot.get("metrics") or {})
    metrics["rdp_user_input_delay_ms"] = telemetry
    delay = telemetry.get("value") if telemetry.get("status") == "available" else None

    if not instance.get("exists"):
        finding = "VDI_INSTANCE_NOT_FOUND"
        message = "The assigned GCP virtual desktop was not found."
    elif instance.get("status") != "RUNNING":
        finding = "VDI_INSTANCE_NOT_RUNNING"
        message = f"The assigned GCP virtual desktop is {instance.get('status', 'not running')}."
    elif (
        isinstance(delay, (int, float))
        and float(delay) > RDP_USER_INPUT_DELAY_THRESHOLD_MS
    ):
        finding = "RDP_USER_INPUT_DELAY_ELEVATED"
        message = "RDP User Input Delay is above the PoC responsiveness threshold."
    elif len(disconnects) >= 2:
        finding = "RDP_RECENT_DISCONNECTS"
        message = "Repeated recent Remote Desktop session disconnects were detected."
    elif telemetry.get("status") != "available":
        finding = "NO_RECENT_RDP_TELEMETRY"
        message = "Recent RDP User Input Delay telemetry is unavailable; it was not treated as zero."
    else:
        finding = "NO_RDP_INPUT_DELAY_THRESHOLD_BREACH"
        message = (
            "RDP User Input Delay did not exceed the PoC responsiveness threshold."
        )

    diagnosis.update(
        {
            "metrics": metrics,
            "recent_rdp_events": events,
            "recent_disconnect_count": len(disconnects),
            "telemetry_latest_timestamp": _latest_timestamp(snapshot),
            "collection_limitations": list(snapshot.get("collection_errors") or []),
            "finding_code": finding,
            "rdp_user_input_delay_threshold_ms": RDP_USER_INPUT_DELAY_THRESHOLD_MS,
            "threshold_rule": "RDP User Input Delay > 200 ms",
            "threshold_source": "Microsoft Remote Desktop guidance",
            "message": message,
        }
    )
    return {"status": "ok", "diagnosis": diagnosis}


def _diagnose(
    issue_type: str,
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    mapping, request_error = _resolve_request(target_upn, tool_context)
    if request_error is not None:
        return request_error
    assert mapping is not None
    backend = _mode()

    orchestration, orchestration_error = _orchestration_gate(
        issue_type,
        _norm_upn(target_upn),
        tool_context,
    )
    if orchestration_error is not None:
        return orchestration_error
    assert orchestration is not None

    try:
        snapshot = (
            _load_demo_snapshot(mapping)
            if backend == "demo"
            else _load_gcp_snapshot(mapping)
        )
    except Exception:
        return _error(
            "GCP_VDI_API_FAILURE"
            if backend == "gcp"
            else "GCP_VDI_DEMO_FIXTURE_INVALID",
            "GCP virtual desktop evidence could not be retrieved.",
            backend,
        )

    normalized_upn = _norm_upn(target_upn)
    if issue_type == "login":
        result = _login_diagnosis(backend, normalized_upn, mapping, snapshot)
    else:
        result = _performance_diagnosis(backend, normalized_upn, mapping, snapshot)
    result["orchestration"] = orchestration
    return result


def gcp_diagnose_virtual_desktop_login(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """Diagnose the authenticated caller's mapped GCP Windows desktop login path read-only."""
    return _diagnose("login", target_upn, tool_context)


def gcp_diagnose_virtual_desktop_performance(
    target_upn: str,
    tool_context: ToolContext,
) -> Dict[str, Any]:
    """Diagnose the authenticated caller's mapped GCP Windows desktop performance read-only."""
    return _diagnose("performance", target_upn, tool_context)


gcp_diagnose_virtual_desktop_login = FunctionTool(
    func=gcp_diagnose_virtual_desktop_login
)
gcp_diagnose_virtual_desktop_performance = FunctionTool(
    func=gcp_diagnose_virtual_desktop_performance
)

gcp_virtual_desktop_tools = [
    gcp_diagnose_virtual_desktop_login,
    gcp_diagnose_virtual_desktop_performance,
]
