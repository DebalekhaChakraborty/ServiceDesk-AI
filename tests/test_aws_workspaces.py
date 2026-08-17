import asyncio
import inspect
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sd_chat.agent import root_agent, sd_chat
from sd_chat.planner import reasoning_composer
from sd_chat.tools import aws_workspaces_tool as workspaces

CALLER_UPN = "user@example.com"
MAPPING_PATH = Path("examples/aws_workspaces_user_map.example.json").resolve()
FIXTURE_PATH = Path("tests/fixtures/aws_workspaces_demo.json").resolve()


def _context(upn=CALLER_UPN, devices=None):
    persona = {
        "displayName": "Example User",
        "userPrincipalName": upn,
        "id": "caller-object-id",
        "devices": devices or [],
    }
    return SimpleNamespace(
        state={"persona": persona, "user:persona": persona},
        invocation_id="phase-c-test",
    )


def _account_checks(enabled="pass", locked="pass"):
    return {
        "account_enabled": workspaces._check(
            enabled, "phase_b.account_access", "enabled evidence"
        ),
        "account_locked": workspaces._check(
            locked, "phase_b.account_access", "locked evidence"
        ),
    }


def _workspace_context(
    *,
    assigned=True,
    state="AVAILABLE",
    connection="CONNECTED",
    registration="pass",
    computer_name="REMOTE-WORKSPACE",
    running_mode="AUTO_STOP",
):
    return {
        "workspace": {
            "assigned": assigned,
            "workspace_id": "ws-1234567890" if assigned else None,
            "directory_id": "d-1234567890",
            "user_name": "example.directory.user",
            "computer_name": computer_name if assigned else None,
            "state": state if assigned else None,
            "bundle_id": "wsb-1234567890" if assigned else None,
            "running_mode": running_mode if assigned else None,
            "protocols": ["WSP"] if assigned else [],
        },
        "connection": {
            "state": connection,
            "state_checked_at": "2026-01-01T10:00:00Z",
            "last_known_user_connection": "2026-01-01T09:59:00Z",
        },
        "registration_status": registration,
        "mfa_directory_status": "enabled",
        "inactivity_access_status": "not_verifiable",
        "metrics": {},
        "diagnostic_errors": [],
        "workspaces_client": None,
    }


def _metrics(**values):
    result = {
        spec["key"]: workspaces._metric_unavailable(spec, lookback_minutes=30)
        for spec in workspaces._METRIC_SPECS.values()
    }
    units = {spec["key"]: spec["unit"] for spec in workspaces._METRIC_SPECS.values()}
    statistics = {
        spec["key"]: spec["statistic"] for spec in workspaces._METRIC_SPECS.values()
    }
    for key, value in values.items():
        result[key] = {
            "status": "available",
            "value": float(value),
            "timestamp": "2026-01-01T10:00:00Z",
            "statistic": statistics[key],
            "unit": units[key],
            "aggregation": next(
                spec["aggregation"]
                for spec in workspaces._METRIC_SPECS.values()
                if spec["key"] == key
            ),
            "period_seconds": 300,
            "lookback_minutes": 30,
            "datapoints_used": 1,
        }
    return result


@pytest.fixture(autouse=True)
def isolated_phase_c(monkeypatch):
    monkeypatch.setenv("AWS_WORKSPACES_MODE", "demo")
    monkeypatch.setenv("AWS_WORKSPACES_USER_MAP_PATH", str(MAPPING_PATH))
    monkeypatch.setenv("AWS_WORKSPACES_DEMO_FIXTURE_PATH", str(FIXTURE_PATH))
    monkeypatch.setenv("AWS_WORKSPACES_METRIC_LOOKBACK_MINUTES", "30")
    monkeypatch.setattr(
        workspaces.account_access_orchestrator.diagnose_account_access,
        "func",
        lambda target_upn, tool_context: {
            "status": "ok",
            "account": {"enabled": True, "locked": False},
            "offer": None,
        },
    )


def test_mode_defaults_off(monkeypatch):
    monkeypatch.delenv("AWS_WORKSPACES_MODE", raising=False)

    assert workspaces._mode() == "off"
    result = workspaces.aws_diagnose_workspace_login.func(CALLER_UPN, _context())

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_BACKEND_OFF"
    assert (
        "was not checked" not in result["message"].lower()
        or "diagnosis is off" in result["message"].lower()
    )


def test_invalid_mode_fails_without_demo_fallback(monkeypatch):
    monkeypatch.setenv("AWS_WORKSPACES_MODE", "unexpected")

    result = workspaces.aws_diagnose_workspace_performance.func(CALLER_UPN, _context())

    assert result["code"] == "AWS_WORKSPACES_MODE_INVALID"


def test_arbitrary_other_user_is_rejected_before_mapping_or_aws(monkeypatch):
    mapping = Mock()
    aws_context = Mock()
    monkeypatch.setattr(workspaces, "_load_mapping", mapping)
    monkeypatch.setattr(workspaces, "_workspace_context", aws_context)

    result = workspaces.aws_diagnose_workspace_login.func(
        "other@example.com", _context()
    )

    assert result["code"] == "AWS_WORKSPACES_SELF_SERVICE_ONLY"
    mapping.assert_not_called()
    aws_context.assert_not_called()


def test_unknown_caller_is_rejected():
    result = workspaces.aws_diagnose_workspace_login.func(
        CALLER_UPN, SimpleNamespace(state={}, invocation_id="unknown")
    )

    assert result["code"] == "AWS_WORKSPACES_CALLER_UNKNOWN"


def test_mapping_uses_explicit_workspace_username_without_upn_stripping(
    tmp_path, monkeypatch
):
    path = tmp_path / "mapping.json"
    path.write_text(
        json.dumps(
            {
                "person@company.example": {
                    "region": "us-west-2",
                    "directory_id": "d-abcdef1234",
                    "workspace_username": "DirectoryUser42",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AWS_WORKSPACES_USER_MAP_PATH", str(path))

    mapping, error = workspaces._load_mapping("PERSON@COMPANY.EXAMPLE")

    assert error is None
    assert mapping == {
        "region": "us-west-2",
        "directory_id": "d-abcdef1234",
        "workspace_username": "DirectoryUser42",
    }
    assert mapping["workspace_username"] != "person"


@pytest.mark.parametrize("directory_id", ["d-abcdef12", "wsd-abc12345"])
def test_mapping_accepts_current_workspaces_directory_id_forms(
    tmp_path, monkeypatch, directory_id
):
    path = tmp_path / "mapping.json"
    path.write_text(
        json.dumps(
            {
                CALLER_UPN: {
                    "region": "us-east-1",
                    "directory_id": directory_id,
                    "workspace_username": "u" * 63,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AWS_WORKSPACES_USER_MAP_PATH", str(path))

    mapping, error = workspaces._load_mapping(CALLER_UPN)

    assert error is None
    assert mapping["directory_id"] == directory_id
    assert len(mapping["workspace_username"]) == 63


def test_mapping_rejects_workspace_username_over_63_characters(tmp_path, monkeypatch):
    path = tmp_path / "mapping.json"
    path.write_text(
        json.dumps(
            {
                CALLER_UPN: {
                    "region": "us-east-1",
                    "directory_id": "d-abcdef1234",
                    "workspace_username": "u" * 64,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AWS_WORKSPACES_USER_MAP_PATH", str(path))

    mapping, error = workspaces._load_mapping(CALLER_UPN)

    assert mapping is None
    assert error["code"] == "AWS_WORKSPACES_MAPPING_MALFORMED"


@pytest.mark.parametrize(
    "payload,code",
    [
        ({"user@example.com": "bad"}, "AWS_WORKSPACES_MAPPING_MALFORMED"),
        ({"nobody@example.com": {}}, "AWS_WORKSPACES_USER_NOT_MAPPED"),
        (
            {
                "user@example.com": {
                    "region": "not-a-region",
                    "directory_id": "d-1234567890",
                    "workspace_username": "user",
                }
            },
            "AWS_WORKSPACES_MAPPING_MALFORMED",
        ),
    ],
)
def test_mapping_errors_are_normalized(tmp_path, monkeypatch, payload, code):
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("AWS_WORKSPACES_USER_MAP_PATH", str(path))

    _, error = workspaces._load_mapping(CALLER_UPN)

    assert error["code"] == code


def test_demo_login_assigned_available_connected_and_last_connection():
    result = workspaces.aws_diagnose_workspace_login.func(
        CALLER_UPN, _context(), reported_error_category="authentication_failure"
    )

    assert result["status"] == "ok"
    diagnosis = result["diagnosis"]
    assert diagnosis["backend"] == "demo"
    assert diagnosis["workspace"]["assigned"] is True
    assert diagnosis["workspace"]["state"] == "AVAILABLE"
    assert diagnosis["connection"]["state"] == "CONNECTED"
    assert (
        diagnosis["connection"]["last_known_user_connection"] == "2026-01-01T09:59:00Z"
    )
    assert diagnosis["checks"]["workspace_assigned"]["status"] == "pass"
    assert diagnosis["checks"]["workspace_available"]["status"] == "pass"


def test_unassigned_workspace_is_strong_finding(tmp_path, monkeypatch):
    mapping_path = tmp_path / "mapping.json"
    mapping_path.write_text(
        json.dumps(
            {
                "unassigned@example.com": {
                    "region": "us-east-1",
                    "directory_id": "d-0987654321",
                    "workspace_username": "unassigned.directory.user",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AWS_WORKSPACES_USER_MAP_PATH", str(mapping_path))

    result = workspaces.aws_diagnose_workspace_login.func(
        "unassigned@example.com",
        _context("unassigned@example.com"),
        reported_error_category="not_authorized",
    )

    diagnosis = result["diagnosis"]
    assert diagnosis["finding_code"] == "WORKSPACE_NOT_ASSIGNED"
    assert diagnosis["checks"]["workspace_assigned"]["status"] == "fail"
    assert diagnosis["checks"]["registration"]["status"] == "not_applicable"
    assert "password" not in diagnosis["recommended_next_action"].lower()


@pytest.mark.parametrize(
    "raw,expected",
    [
        ({"ConnectionState": "CONNECTED"}, "CONNECTED"),
        ({"ConnectionState": "DISCONNECTED"}, "DISCONNECTED"),
        ({"ConnectionState": "SOMETHING_NEW"}, "UNKNOWN"),
        ({}, "UNKNOWN"),
    ],
)
def test_connection_state_is_normalized(raw, expected):
    assert workspaces._public_connection(raw)["state"] == expected


def test_unavailable_workspace_state_is_reported(monkeypatch):
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        lambda mode, mapping: _workspace_context(state="STOPPED"),
    )

    result = workspaces.aws_diagnose_workspace_login.func(CALLER_UPN, _context())

    assert result["diagnosis"]["checks"]["workspace_available"]["status"] == "fail"
    assert result["diagnosis"]["finding_code"] == "WORKSPACE_NOT_AVAILABLE"


def test_not_authorized_prioritizes_assignment_and_registration():
    checks = {
        **_account_checks(enabled="fail"),
        "workspace_available": workspaces._check("pass", "aws", "available"),
        "registration": workspaces._check("fail", "client", "mismatch"),
        "mfa": workspaces._check("pass", "directory", "configured"),
    }

    finding = workspaces._login_finding(
        _workspace_context()["workspace"], checks, "not_authorized"
    )

    assert finding[0] == "REGISTRATION_CONFIGURATION_MISMATCH"


def test_not_authorized_runs_registration_before_phase_b_account_check(monkeypatch):
    calls = []
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        lambda mode, mapping: _workspace_context(),
    )
    monkeypatch.setattr(
        workspaces,
        "_registration_check",
        lambda *args: (
            calls.append("registration") or workspaces._check("pass", "client", "valid")
        ),
    )
    monkeypatch.setattr(
        workspaces,
        "_phase_b_account_checks",
        lambda *args: calls.append("account") or _account_checks(),
    )

    result = workspaces.aws_diagnose_workspace_login.func(
        CALLER_UPN,
        _context(),
        reported_error_category="not_authorized",
    )

    assert result["status"] == "ok"
    assert calls == ["registration", "account"]


def test_not_authorized_registration_unverifiable_has_stable_finding():
    checks = {
        **_account_checks(),
        "workspace_available": workspaces._check("pass", "aws", "available"),
        "registration": workspaces._check("not_verifiable", "client", "missing"),
        "mfa": workspaces._check("pass", "directory", "configured"),
    }

    finding = workspaces._login_finding(
        _workspace_context()["workspace"], checks, "not_authorized"
    )

    assert finding[0] == "REGISTRATION_CONFIGURATION_NOT_VERIFIABLE"


def test_authentication_failure_does_not_invoke_password_reset_or_windows(monkeypatch):
    reset = Mock()
    windows = Mock()
    monkeypatch.setattr(workspaces.aad_tool.aad_reset_password, "func", reset)
    monkeypatch.setattr(workspaces.win_tool, "execute_winrm_ps", windows)

    result = workspaces.aws_diagnose_workspace_login.func(
        CALLER_UPN, _context(), reported_error_category="authentication_failure"
    )

    assert result["status"] == "ok"
    assert (
        "does not prove the password is wrong" in result["diagnosis"]["message"].lower()
    )
    assert (
        "do not automatically reset"
        in result["diagnosis"]["recommended_next_action"].lower()
    )
    reset.assert_not_called()
    windows.assert_not_called()


def test_phase_b_account_status_is_reused_and_offer_is_removed(monkeypatch):
    context = _context()
    diagnose = Mock(
        return_value={
            "status": "ok",
            "account": {"enabled": False, "locked": None},
            "offer": {"action_id": "ad.enable_account"},
        }
    )
    monkeypatch.setattr(
        workspaces.account_access_orchestrator.diagnose_account_access,
        "func",
        diagnose,
    )
    context.state["account_access_offer"] = {"stale": True}
    context.state["account_access_diagnosis"] = {"stale": True}

    checks = workspaces._phase_b_account_checks(CALLER_UPN, context)

    diagnose.assert_called_once_with(CALLER_UPN, context)
    assert checks["account_enabled"]["status"] == "fail"
    assert checks["account_locked"]["status"] == "not_verifiable"
    assert context.state["account_access_offer"] is None
    assert context.state["account_access_diagnosis"] is None


def test_registration_mismatch_is_normalized_without_returning_code(monkeypatch):
    context = _workspace_context()
    context["registration_code"] = "SENSITIVE-REGISTRATION-CODE"
    monkeypatch.setattr(
        workspaces.aad_tool.aad_get_my_devices,
        "func",
        Mock(return_value={"ok": True, "allowed_hosts": ["client.example"]}),
    )
    monkeypatch.setattr(
        workspaces,
        "check_list",
        Mock(return_value={"status": "ok", "details": {}}),
    )
    remote = Mock(
        return_value={"status": "success", "stdout": "MISMATCH", "stderr": ""}
    )
    monkeypatch.setattr(workspaces.win_tool, "execute_winrm_ps", remote)

    result = workspaces._registration_check(
        "aws", context, _context(), "client.example", CALLER_UPN
    )

    assert result["status"] == "fail"
    assert result["evidence"].endswith("assigned directory.")
    assert "SENSITIVE-REGISTRATION-CODE" not in json.dumps(result)
    remote.assert_called_once()
    assert remote.call_args.args[0] == "client.example"


def test_registration_inspection_uses_only_correlated_interactive_local_profile():
    script = workspaces._registration_inspection_script(
        "SENSITIVE-REGISTRATION-CODE", CALLER_UPN
    )

    assert "Win32_ComputerSystem" in script
    assert "UserName" in script
    assert "IdentityType]::Sid" in script
    assert "UserPrincipalName" in script
    assert "Win32_UserProfile" in script
    assert "$_.Loaded" in script
    assert "$_.Special" in script
    assert "AppData\\Local\\Amazon Web Services\\Amazon WorkSpaces" in script
    assert "Join-Path $configRoot 'UserSettings.json'" in script
    assert "Join-Path $configRoot 'RegistrationList.json'" in script
    assert "$env:LOCALAPPDATA" not in script
    assert "$env:APPDATA" not in script
    assert "if ($readFailed) { Write-NotVerifiable }" in script


def test_registration_is_not_verifiable_when_profile_correlation_fails(monkeypatch):
    context = _workspace_context()
    context["registration_code"] = "SENSITIVE-REGISTRATION-CODE"
    monkeypatch.setattr(
        workspaces.aad_tool.aad_get_my_devices,
        "func",
        Mock(return_value={"ok": True, "allowed_hosts": ["client.example"]}),
    )
    monkeypatch.setattr(
        workspaces,
        "check_list",
        Mock(return_value={"status": "ok", "details": {}}),
    )
    remote = Mock(
        return_value={"status": "success", "stdout": "NOT_VERIFIABLE", "stderr": ""}
    )
    monkeypatch.setattr(workspaces.win_tool, "execute_winrm_ps", remote)

    result = workspaces._registration_check(
        "aws", context, _context(), "client.example", CALLER_UPN
    )

    assert result["status"] == "not_verifiable"
    script = remote.call_args.args[1]
    assert CALLER_UPN in script
    assert "MISMATCH" in script
    assert script.index("UserPrincipalName") < script.index("MISMATCH")


def test_registration_not_verifiable_without_single_authorized_client(monkeypatch):
    context = _workspace_context()
    context["registration_code"] = "SENSITIVE-REGISTRATION-CODE"
    monkeypatch.setattr(
        workspaces.aad_tool.aad_get_my_devices,
        "func",
        Mock(
            return_value={
                "ok": True,
                "allowed_hosts": ["client-one", "client-two"],
            }
        ),
    )
    remote = Mock()
    monkeypatch.setattr(workspaces.win_tool, "execute_winrm_ps", remote)

    result = workspaces._registration_check(
        "aws", context, _context(), "", CALLER_UPN
    )

    assert result["status"] == "not_verifiable"
    assert result["selection_required"] is True
    assert result["authorized_client_endpoints"] == ["client-one", "client-two"]
    remote.assert_not_called()


def test_arbitrary_registration_endpoint_is_never_used(monkeypatch):
    context = _workspace_context()
    context["registration_code"] = "SENSITIVE-REGISTRATION-CODE"
    monkeypatch.setattr(
        workspaces.aad_tool.aad_get_my_devices,
        "func",
        Mock(return_value={"ok": True, "allowed_hosts": ["authorized-client"]}),
    )
    policy = Mock()
    remote = Mock()
    monkeypatch.setattr(workspaces, "check_list", policy)
    monkeypatch.setattr(workspaces.win_tool, "execute_winrm_ps", remote)

    result = workspaces._registration_check(
        "aws", context, _context(), "attacker-host", CALLER_UPN
    )

    assert result["status"] == "not_verifiable"
    policy.assert_not_called()
    remote.assert_not_called()


def test_mfa_is_directory_level_and_individual_enrollment_not_fabricated():
    result = workspaces._mfa_check({"mfa_directory_status": "enabled"})

    assert result["status"] == "pass"
    assert "Directory-level" in result["evidence"]
    assert "individual user enrollment is not verifiable" in result["evidence"]
    assert "Okta token is enrolled" not in result["evidence"]


def test_inactivity_policy_is_not_fabricated_in_aws_mode():
    result = workspaces._inactivity_check("aws", {"inactivity_access_status": "pass"})

    assert result["status"] == "not_verifiable"
    assert result["source"] == "customer_policy_source_unavailable"


class _FakeWorkSpacesClient:
    def __init__(self, registration_code="SENSITIVE-REGISTRATION-CODE"):
        self.registration_code = registration_code
        self.calls = []

    def describe_workspaces(self, **kwargs):
        self.calls.append(("describe_workspaces", kwargs))
        return {
            "Workspaces": [
                {
                    "WorkspaceId": "ws-1234567890",
                    "DirectoryId": "d-1234567890",
                    "UserName": "example.directory.user",
                    "ComputerName": "REMOTE-WORKSPACE",
                    "State": "AVAILABLE",
                    "BundleId": "wsb-1234567890",
                    "WorkspaceProperties": {
                        "RunningMode": "AUTO_STOP",
                        "Protocols": ["WSP"],
                    },
                }
            ]
        }

    def describe_workspaces_connection_status(self, **kwargs):
        self.calls.append(("describe_workspaces_connection_status", kwargs))
        return {
            "WorkspacesConnectionStatus": [
                {
                    "WorkspaceId": "ws-1234567890",
                    "ConnectionState": "DISCONNECTED",
                    "ConnectionStateCheckTimestamp": datetime(
                        2026, 1, 1, 10, 0, tzinfo=timezone.utc
                    ),
                    "LastKnownUserConnectionTimestamp": datetime(
                        2026, 1, 1, 9, 59, tzinfo=timezone.utc
                    ),
                }
            ]
        }

    def describe_workspace_directories(self, **kwargs):
        self.calls.append(("describe_workspace_directories", kwargs))
        return {"Directories": [{"RegistrationCode": self.registration_code}]}


class _FakeDirectoryClient:
    def __init__(self):
        self.calls = []

    def describe_directories(self, **kwargs):
        self.calls.append(("describe_directories", kwargs))
        return {
            "DirectoryDescriptions": [
                {
                    "DirectoryId": "d-1234567890",
                    "RadiusStatus": "Completed",
                    "RadiusSettings": {"RadiusServers": ["radius.example"]},
                }
            ]
        }


def test_real_adapter_calls_only_required_read_apis(monkeypatch):
    ws_client = _FakeWorkSpacesClient()
    ds_client = _FakeDirectoryClient()
    monkeypatch.setattr(
        workspaces,
        "_boto3_client",
        lambda service, region: ws_client if service == "workspaces" else ds_client,
    )

    context = workspaces._aws_workspace_context(
        {
            "region": "us-east-1",
            "directory_id": "d-1234567890",
            "workspace_username": "example.directory.user",
        }
    )

    assert [name for name, _ in ws_client.calls] == [
        "describe_workspaces",
        "describe_workspaces_connection_status",
        "describe_workspace_directories",
    ]
    assert ws_client.calls[0][1] == {
        "DirectoryId": "d-1234567890",
        "UserName": "example.directory.user",
    }
    assert ws_client.calls[1][1] == {"WorkspaceIds": ["ws-1234567890"]}
    assert ds_client.calls == [
        ("describe_directories", {"DirectoryIds": ["d-1234567890"]})
    ]
    assert context["workspace"]["assigned"] is True
    assert context["connection"]["state"] == "DISCONNECTED"
    assert context["mfa_directory_status"] == "enabled"


@pytest.mark.parametrize(
    "exception_name,response,expected",
    [
        (
            "ClientError",
            {"Error": {"Code": "AccessDeniedException"}},
            "AWS_ACCESS_DENIED",
        ),
        (
            "ClientError",
            {"Error": {"Code": "InvalidParameterValuesException"}},
            "AWS_RESOURCE_OR_REGION_INVALID",
        ),
        ("NoCredentialsError", None, "AWS_CREDENTIALS_UNAVAILABLE"),
        (
            "EndpointConnectionError",
            None,
            "AWS_API_TIMEOUT_OR_ENDPOINT_ERROR",
        ),
    ],
)
def test_aws_sdk_failures_are_safely_normalized(exception_name, response, expected):
    exception_type = type(exception_name, (Exception,), {})
    exc = exception_type("raw SDK detail must not be returned")
    if response is not None:
        exc.response = response

    normalized = workspaces._normalized_aws_exception(exc)

    assert normalized.code == expected
    assert "raw SDK detail" not in workspaces._aws_error_message(expected)


def test_multiple_workspaces_for_one_mapping_fails_closed(monkeypatch):
    class MultipleClient:
        def describe_workspaces(self, **kwargs):
            return {
                "Workspaces": [
                    {"WorkspaceId": "ws-1111111111"},
                    {"WorkspaceId": "ws-2222222222"},
                ]
            }

    monkeypatch.setattr(
        workspaces,
        "_boto3_client",
        lambda service, region: MultipleClient(),
    )

    with pytest.raises(workspaces._AwsCallError) as raised:
        workspaces._aws_workspace_context(
            {
                "region": "us-east-1",
                "directory_id": "d-1234567890",
                "workspace_username": "example.directory.user",
            }
        )

    assert raised.value.code == "AWS_WORKSPACES_MULTIPLE_UNEXPECTED"


def test_directory_metadata_failure_is_partial_and_non_fabricating(monkeypatch):
    ws_client = _FakeWorkSpacesClient()
    ds_client = _FakeDirectoryClient()

    def fail_workspace_directories(**kwargs):
        exc_type = type("ClientError", (Exception,), {})
        exc = exc_type("sensitive raw detail")
        exc.response = {"Error": {"Code": "AccessDeniedException"}}
        raise exc

    def fail_directories(**kwargs):
        exc_type = type("ClientError", (Exception,), {})
        exc = exc_type("sensitive raw detail")
        exc.response = {"Error": {"Code": "AccessDeniedException"}}
        raise exc

    ws_client.describe_workspace_directories = fail_workspace_directories
    ds_client.describe_directories = fail_directories
    monkeypatch.setattr(
        workspaces,
        "_boto3_client",
        lambda service, region: ws_client if service == "workspaces" else ds_client,
    )

    context = workspaces._aws_workspace_context(
        {
            "region": "us-east-1",
            "directory_id": "d-1234567890",
            "workspace_username": "example.directory.user",
        }
    )

    assert context["workspace"]["assigned"] is True
    assert context["registration_code"] is None
    assert context["mfa_directory_status"] == "not_verifiable"
    assert context["diagnostic_errors"] == [
        {
            "source": "aws.workspaces.DescribeWorkspaceDirectories",
            "code": "AWS_ACCESS_DENIED",
        },
        {
            "source": "aws.directoryservice.DescribeDirectories",
            "code": "AWS_ACCESS_DENIED",
        },
    ]


def test_registration_code_never_appears_in_public_result_or_logs(monkeypatch, capsys):
    marker = "SENSITIVE-REGISTRATION-CODE"
    ws_client = _FakeWorkSpacesClient(marker)
    ds_client = _FakeDirectoryClient()
    monkeypatch.setenv("AWS_WORKSPACES_MODE", "aws")
    monkeypatch.setattr(
        workspaces,
        "_boto3_client",
        lambda service, region: ws_client if service == "workspaces" else ds_client,
    )
    monkeypatch.setattr(
        workspaces.aad_tool.aad_get_my_devices,
        "func",
        Mock(return_value={"ok": False, "allowed_hosts": []}),
    )

    result = workspaces.aws_diagnose_workspace_login.func(CALLER_UPN, _context())
    captured = capsys.readouterr()

    assert result["status"] == "ok"
    assert marker not in json.dumps(result)
    assert marker not in captured.out
    assert marker not in captured.err


def test_aws_failure_never_silently_becomes_demo_success(monkeypatch):
    monkeypatch.setenv("AWS_WORKSPACES_MODE", "aws")
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        Mock(side_effect=workspaces._AwsCallError("AWS_ACCESS_DENIED")),
    )

    result = workspaces.aws_diagnose_workspace_login.func(CALLER_UPN, _context())

    assert result == {
        "status": "error",
        "code": "AWS_ACCESS_DENIED",
        "message": "AWS denied the read-only diagnostic request; AWS WorkSpaces could not be checked.",
    }
    assert "demo" not in json.dumps(result).lower()


class _FakeCloudWatchClient:
    def __init__(self, results):
        self.results = results
        self.calls = []

    def get_metric_data(self, **kwargs):
        self.calls.append(kwargs)
        return {"MetricDataResults": self.results}


def test_cloudwatch_get_metric_data_queries_all_required_metrics(monkeypatch):
    client = _FakeCloudWatchClient(
        [
            {
                "Id": "m0",
                "Values": [243.0],
                "Timestamps": [datetime(2026, 1, 1, tzinfo=timezone.utc)],
                "StatusCode": "Complete",
            }
        ]
    )
    monkeypatch.setattr(workspaces, "_boto3_client", lambda service, region: client)

    metrics, error = workspaces._query_cloudwatch_metrics("us-east-1", "ws-1234567890")

    assert error is None
    call = client.calls[0]
    query_names = {
        query["MetricStat"]["Metric"]["MetricName"]
        for query in call["MetricDataQueries"]
    }
    assert query_names == set(workspaces._METRIC_SPECS)
    assert all(
        query["MetricStat"]["Metric"]["Namespace"] == "AWS/WorkSpaces"
        for query in call["MetricDataQueries"]
    )
    assert all(
        query["MetricStat"]["Metric"]["Dimensions"]
        == [{"Name": "WorkspaceId", "Value": "ws-1234567890"}]
        for query in call["MetricDataQueries"]
    )
    assert all(
        query["MetricStat"]["Period"] == 300
        for query in call["MetricDataQueries"]
    )
    assert metrics["in_session_latency_ms"]["value"] == 243.0
    assert metrics["in_session_latency_ms"]["aggregation"] == "latest_datapoint"
    assert metrics["in_session_latency_ms"]["datapoints_used"] == 1
    assert metrics["memory_usage_percent"]["status"] == "unavailable"
    assert metrics["memory_usage_percent"]["value"] is None


def test_cloudwatch_uses_latest_points_and_aggregates_all_count_buckets(monkeypatch):
    first = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    second = datetime(2026, 1, 1, 10, 5, tzinfo=timezone.utc)
    latest = datetime(2026, 1, 1, 10, 10, tzinfo=timezone.utc)
    client = _FakeCloudWatchClient(
        [
            {
                "Id": "m0",
                "Values": [100.0, 243.0, 150.0],
                "Timestamps": [first, latest, second],
            },
            {
                "Id": "m5",
                "Values": [1.0, 2.0, 3.0],
                "Timestamps": [latest, second, first],
            },
            {"Id": "m6", "Values": [1.0, 1.0], "Timestamps": [latest, second]},
            {"Id": "m7", "Values": [2.0, 1.0], "Timestamps": [latest, second]},
            {
                "Id": "m9",
                "Values": [1.0, 1.0, 1.0],
                "Timestamps": [latest, second, first],
            },
        ]
    )
    monkeypatch.setattr(workspaces, "_boto3_client", lambda service, region: client)

    metrics, error = workspaces._query_cloudwatch_metrics(
        "us-east-1", "ws-1234567890"
    )

    assert error is None
    latency = metrics["in_session_latency_ms"]
    assert latency["value"] == 243.0
    assert latency["timestamp"] == "2026-01-01T10:10:00Z"
    assert latency["aggregation"] == "latest_datapoint"
    assert latency["datapoints_used"] == 1

    expected_counts = {
        "connection_attempt_count": (6.0, 3),
        "connection_success_count": (2.0, 2),
        "connection_failure_count": (3.0, 2),
        "session_disconnect_count": (3.0, 3),
    }
    for key, (expected_value, expected_points) in expected_counts.items():
        metric = metrics[key]
        assert metric["value"] == expected_value
        assert metric["timestamp"] is None
        assert metric["aggregation"] == "lookback_window_sum"
        assert metric["lookback_minutes"] == 30
        assert metric["period_seconds"] == 300
        assert metric["datapoints_used"] == expected_points
        assert metric["window_start"] is not None
        assert metric["window_end"] is not None
        assert metric["latest_datapoint_timestamp"] == "2026-01-01T10:10:00Z"


def test_only_window_count_metrics_use_lookback_aggregation():
    count_metrics = {
        name
        for name, spec in workspaces._METRIC_SPECS.items()
        if spec["aggregation"] == "lookback_window_sum"
    }

    assert count_metrics == {
        "ConnectionAttempt",
        "ConnectionSuccess",
        "ConnectionFailure",
        "SessionDisconnect",
    }
    assert (
        workspaces._METRIC_SPECS["UserConnected"]["aggregation"]
        == "latest_datapoint"
    )
    assert (
        workspaces._METRIC_SPECS["SessionLaunchTime"]["aggregation"]
        == "latest_datapoint"
    )


@pytest.mark.parametrize(
    "latency,expected",
    [
        (199.0, "NO_KB_THRESHOLD_BREACH_DETECTED"),
        (200.0, "NO_KB_THRESHOLD_BREACH_DETECTED"),
        (200.1, "HIGH_IN_SESSION_LATENCY"),
    ],
)
def test_exact_kb_latency_threshold(monkeypatch, latency, expected):
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        lambda mode, mapping: _workspace_context(),
    )
    monkeypatch.setattr(
        workspaces,
        "_demo_metrics",
        lambda context: _metrics(in_session_latency_ms=latency),
    )

    result = workspaces.aws_diagnose_workspace_performance.func(CALLER_UPN, _context())

    assert result["diagnosis"]["finding_code"] == expected
    assert result["diagnosis"]["kb_threshold_ms"] == 200
    assert result["diagnosis"]["threshold_rule"] == "InSessionLatency > 200 ms"


def test_missing_cloudwatch_datapoint_is_unavailable_not_zero(monkeypatch):
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        lambda mode, mapping: _workspace_context(),
    )
    monkeypatch.setattr(workspaces, "_demo_metrics", lambda context: _metrics())

    result = workspaces.aws_diagnose_workspace_performance.func(CALLER_UPN, _context())

    diagnosis = result["diagnosis"]
    assert diagnosis["finding_code"] == "NO_RECENT_SESSION_TELEMETRY"
    assert all(metric["value"] is None for metric in diagnosis["metrics"].values())


def test_performance_surfaces_supporting_metrics_without_invented_thresholds(
    monkeypatch,
):
    observations = _metrics(
        in_session_latency_ms=150,
        cpu_usage_percent=78,
        memory_usage_percent=64,
        root_disk_usage_percent=51,
        user_disk_usage_percent=42,
        udp_packet_loss_rate=1.2,
        tcp_retransmission_rate=0.4,
        connection_failure_count=0,
    )
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        lambda mode, mapping: _workspace_context(),
    )
    monkeypatch.setattr(workspaces, "_demo_metrics", lambda context: observations)

    result = workspaces.aws_diagnose_workspace_performance.func(CALLER_UPN, _context())

    metrics = result["diagnosis"]["metrics"]
    assert metrics["cpu_usage_percent"]["value"] == 78
    assert metrics["memory_usage_percent"]["value"] == 64
    assert metrics["root_disk_usage_percent"]["value"] == 51
    assert metrics["user_disk_usage_percent"]["value"] == 42
    assert metrics["udp_packet_loss_rate"]["value"] == 1.2
    assert metrics["tcp_retransmission_rate"]["value"] == 0.4
    assert result["diagnosis"]["finding_code"] == "NO_KB_THRESHOLD_BREACH_DETECTED"
    assert (
        "unsupported CPU, memory, disk, or packet threshold"
        in result["diagnosis"]["message"]
    )


def test_recent_connection_failure_is_surfaced(monkeypatch):
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        lambda mode, mapping: _workspace_context(),
    )
    monkeypatch.setattr(
        workspaces,
        "_demo_metrics",
        lambda context: _metrics(in_session_latency_ms=120, connection_failure_count=2),
    )

    result = workspaces.aws_diagnose_workspace_performance.func(CALLER_UPN, _context())

    assert result["diagnosis"]["finding_code"] == "RECENT_CONNECTION_FAILURES"


def test_performance_diagnosis_never_runs_cleanup_or_trusts_remote_computer(
    monkeypatch,
):
    remote_name = "REMOTE-WORKSPACE-NOT-A-CLIENT"
    cleanup = Mock()
    winrm = Mock()
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        lambda mode, mapping: _workspace_context(computer_name=remote_name),
    )
    monkeypatch.setattr(
        workspaces,
        "_demo_metrics",
        lambda context: _metrics(in_session_latency_ms=243),
    )
    monkeypatch.setattr(workspaces.win_tool, "cleanup_temp_files", cleanup)
    monkeypatch.setattr(workspaces.win_tool, "execute_winrm_ps", winrm)

    result = workspaces.aws_diagnose_workspace_performance.func(CALLER_UPN, _context())

    diagnosis = result["diagnosis"]
    assert diagnosis["finding_code"] == "HIGH_IN_SESSION_LATENCY"
    assert diagnosis["system_file_cleanup"]["status"] == "not_automatable"
    assert diagnosis["system_file_cleanup"]["automatic_execution"] is False
    assert diagnosis["system_file_cleanup"]["requires_separate_governed_flow"] is True
    cleanup.assert_not_called()
    winrm.assert_not_called()


def test_malformed_demo_fixture_returns_error_not_fake_result(tmp_path, monkeypatch):
    fixture = tmp_path / "fixture.json"
    fixture.write_text("{not-json", encoding="utf-8")
    monkeypatch.setenv("AWS_WORKSPACES_DEMO_FIXTURE_PATH", str(fixture))

    result = workspaces.aws_diagnose_workspace_performance.func(CALLER_UPN, _context())

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_DEMO_FIXTURE_MALFORMED"


def test_realistic_login_and_performance_sop_steps_map_atomically(monkeypatch):
    monkeypatch.setattr(reasoning_composer, "GENAI_AVAILABLE", False)

    login = reasoning_composer.propose_plan(
        user_text="I can't login to AWS WorkSpaces.",
        ctx_vars=["target_upn"],
        sop_texts=[
            "Validate AWS WorkSpaces assignment, connection and registration prerequisites."
        ],
    )
    performance = reasoning_composer.propose_plan(
        user_text="My AWS WorkSpace is freezing.",
        ctx_vars=["target_upn"],
        sop_texts=["Check AWS WorkSpaces round-trip latency and session performance."],
    )

    assert login["plan"]["can_execute_fully"] is True
    assert login["plan"]["low_confidence"] is False
    assert [step["action_id"] for step in login["plan"]["tool_sequence"]] == [
        "aws.workspaces.diagnose_login"
    ]
    assert performance["plan"]["can_execute_fully"] is True
    assert performance["plan"]["low_confidence"] is False
    assert [step["action_id"] for step in performance["plan"]["tool_sequence"]] == [
        "aws.workspaces.diagnose_performance"
    ]


def test_root_agent_contract_preserves_existing_domains_and_adds_two_aws_tools():
    tool_names = {getattr(tool, "name", "") for tool in root_agent.tools}

    assert root_agent is sd_chat
    assert "aws_diagnose_workspace_login" in tool_names
    assert "aws_diagnose_workspace_performance" in tool_names
    assert "diagnose_account_access" in tool_names
    assert "execute_explicit_account_unlock" in tool_names
    assert "execute_explicit_password_reset" in tool_names


def test_agent_instruction_enforces_named_system_routing_and_password_safety():
    instruction = sd_chat.instruction

    assert "AWS WorkSpaces owns the initial" in instruction
    assert "precedence over generic AD Account Access" in instruction
    assert "Semantically distinguish a WorkSpaces LOGIN" in instruction
    assert "A WorkSpaces login diagnosis is not password-reset intent" in instruction
    assert "performance diagnosis is not Windows-remediation intent" in instruction
    assert "aws.workspaces.diagnose_login" in instruction
    assert "aws.workspaces.diagnose_performance" in instruction
    assert "never automatically call or" in instruction
    assert "recommend aad_reset_password" in instruction
    assert 'A follow-up such as "reset it" must be clarified' in instruction
    assert "route WorkSpaces Authentication Failure to Windows support" in instruction
    assert "cleanup_temp_files is not KB0019144 System File Cleanup" in instruction
    assert "system_file_cleanup.status == not_automatable" in instruction


def test_security_contract_has_no_write_api_or_embedded_credentials():
    source = inspect.getsource(workspaces).lower()
    # StartWorkspaces is the single approved mutation for this phase. Every other
    # WorkSpaces write API must remain absent from the runtime tool entirely,
    # including as a string passed to the generic _call_aws dispatcher.
    forbidden_calls = {
        "create_workspaces",
        "terminate_workspaces",
        "rebuild_workspaces",
        "restore_workspace",
        "modify_workspace",
        "stop_workspaces",
        "reboot_workspaces",
        "migrate_workspace",
    }

    assert not any(call in source for call in forbidden_calls)
    assert "aws_access_key_id" not in source
    assert "aws_secret_access_key" not in source
    assert "aws_session_token" not in source
    fixture_text = FIXTURE_PATH.read_text(encoding="utf-8")
    assert "RegistrationCode" not in fixture_text
    assert "registration_code" not in fixture_text


def test_public_result_contract_has_only_safe_check_states():
    result = workspaces.aws_diagnose_workspace_login.func(CALLER_UPN, _context())

    assert result["status"] == "ok"
    checks = result["diagnosis"]["checks"]
    assert set(checks) == {
        "account_enabled",
        "account_locked",
        "workspace_assigned",
        "workspace_available",
        "registration",
        "mfa",
        "inactivity_access",
    }
    assert all(
        check["status"] in {"pass", "fail", "not_verifiable", "not_applicable"}
        for check in checks.values()
    )
    assert all(
        check.get("source") and check.get("evidence") for check in checks.values()
    )


# ---------------------------------------------------------------------------
# Governed start remediation (aws.workspaces.start)
#
# StartWorkspaces is the only AWS mutation in this phase. These tests pin the
# offer/confirmation contract: the offer comes from live evidence, the model
# never names a WorkSpace, diagnosis and mutation never share a turn, the write
# happens exactly once, and success is claimed only from a fresh AVAILABLE read.
# ---------------------------------------------------------------------------

START_STATE_KEY = workspaces.AWS_WORKSPACES_START_OFFER_STATE_KEY


class _FakeStartClient:
    """Minimal WorkSpaces client whose reported state can change per call."""

    def __init__(
        self,
        states=("STOPPED", "AVAILABLE"),
        *,
        running_mode="AUTO_STOP",
        workspace_id="ws-1234567890",
        failed_requests=None,
        connection_state="DISCONNECTED",
        start_error=None,
    ):
        self._states = list(states)
        self.running_mode = running_mode
        self.workspace_id = workspace_id
        self.failed_requests = list(failed_requests or [])
        self.connection_state = connection_state
        self.start_error = start_error
        self.calls = []

    @property
    def start_calls(self):
        return [name for name, _ in self.calls if name == "start_workspaces"]

    def _next_state(self):
        if len(self._states) > 1:
            return self._states.pop(0)
        return self._states[0]

    def describe_workspaces(self, **kwargs):
        self.calls.append(("describe_workspaces", kwargs))
        state = self._next_state()
        if state is None:
            return {"Workspaces": []}
        return {
            "Workspaces": [
                {
                    "WorkspaceId": self.workspace_id,
                    "DirectoryId": "d-1234567890",
                    "UserName": "example.directory.user",
                    "ComputerName": "REMOTE-WORKSPACE",
                    "State": state,
                    "BundleId": "wsb-1234567890",
                    "WorkspaceProperties": {
                        "RunningMode": self.running_mode,
                        "Protocols": ["WSP"],
                    },
                }
            ]
        }

    def start_workspaces(self, **kwargs):
        self.calls.append(("start_workspaces", kwargs))
        if self.start_error is not None:
            raise self.start_error
        return {"FailedRequests": self.failed_requests}

    def describe_workspaces_connection_status(self, **kwargs):
        self.calls.append(("describe_workspaces_connection_status", kwargs))
        return {
            "WorkspacesConnectionStatus": [
                {
                    "WorkspaceId": self.workspace_id,
                    "ConnectionState": self.connection_state,
                    "ConnectionStateCheckTimestamp": datetime(
                        2026, 1, 1, 10, 0, tzinfo=timezone.utc
                    ),
                    "LastKnownUserConnectionTimestamp": datetime(
                        2026, 1, 1, 9, 59, tzinfo=timezone.utc
                    ),
                }
            ]
        }


def _diagnose_for_offer(monkeypatch, *, state="STOPPED", running_mode="AUTO_STOP"):
    """Run the real read-only login diagnosis and return (context, result)."""
    monkeypatch.setenv("AWS_WORKSPACES_MODE", "aws")
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        lambda mode, mapping: _workspace_context(
            state=state, running_mode=running_mode, connection="DISCONNECTED"
        ),
    )
    context = _context()
    context.invocation_id = "turn-1-diagnosis"
    result = workspaces.aws_diagnose_workspace_login.func(CALLER_UPN, context)
    return context, result


def _confirm(context, client, monkeypatch, *, invocation_id="turn-2-confirmation"):
    """Confirm in a later turn with AWS reachable only through the fake client."""
    monkeypatch.setenv("AWS_WORKSPACES_MODE", "aws")
    monkeypatch.setattr(workspaces, "START_POLL_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(workspaces, "_boto3_client", lambda service, region: client)
    context.invocation_id = invocation_id
    return asyncio.run(workspaces.aws_confirm_workspace_start.func(context))


# --- offer creation is evidence-driven -------------------------------------


def test_stopped_autostop_workspace_creates_start_offer(monkeypatch):
    context, result = _diagnose_for_offer(monkeypatch)

    offer = result["start_offer"]
    assert offer["available"] is True
    assert offer["action_id"] == "aws.workspaces.start"
    assert offer["expected_state"] == "STOPPED"
    stored = context.state[START_STATE_KEY]
    assert stored["phase"] == "offered"
    assert stored["workspace_id"] == "ws-1234567890"
    assert stored["caller_upn"] == CALLER_UPN


def test_manual_running_mode_also_creates_start_offer(monkeypatch):
    _, result = _diagnose_for_offer(monkeypatch, running_mode="MANUAL")

    assert result["start_offer"] is not None


def test_available_workspace_creates_no_start_offer(monkeypatch):
    context, result = _diagnose_for_offer(monkeypatch, state="AVAILABLE")

    assert result["start_offer"] is None
    assert context.state[START_STATE_KEY] is None


@pytest.mark.parametrize("state", ["ERROR", "UNHEALTHY", "SUSPENDED", "TERMINATED"])
def test_other_workspace_states_never_create_a_start_offer(monkeypatch, state):
    context, result = _diagnose_for_offer(monkeypatch, state=state)

    assert result["start_offer"] is None
    assert context.state[START_STATE_KEY] is None


def test_always_on_running_mode_is_not_startable_and_is_not_modified(monkeypatch):
    context, result = _diagnose_for_offer(monkeypatch, running_mode="ALWAYS_ON")

    assert result["start_offer"] is None
    assert context.state[START_STATE_KEY] is None
    assert "modify_workspace" not in inspect.getsource(workspaces).lower()


def test_demo_backend_never_creates_a_start_offer(monkeypatch):
    monkeypatch.setenv("AWS_WORKSPACES_MODE", "demo")
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        lambda mode, mapping: _workspace_context(state="STOPPED"),
    )

    result = workspaces.aws_diagnose_workspace_login.func(CALLER_UPN, _context())

    assert result["start_offer"] is None


def test_offer_is_not_created_from_caller_text(monkeypatch):
    """Asking to start an AVAILABLE WorkSpace still produces no offer."""
    monkeypatch.setenv("AWS_WORKSPACES_MODE", "aws")
    monkeypatch.setattr(
        workspaces,
        "_workspace_context",
        lambda mode, mapping: _workspace_context(state="AVAILABLE"),
    )

    result = workspaces.aws_diagnose_workspace_login.func(
        CALLER_UPN, _context(), "authentication_failure"
    )

    assert result["start_offer"] is None


# --- the model can never choose the target ---------------------------------


def test_confirmation_tool_accepts_no_target_arguments():
    signature = inspect.signature(workspaces.aws_confirm_workspace_start.func)

    # tool_context is injected by ADK, not by the model. The declaration the
    # model actually sees therefore has no parameters at all, so there is no
    # WorkspaceId, Region, DirectoryId, or username it could ever supply.
    assert list(signature.parameters) == ["tool_context"]
    declaration = workspaces.aws_confirm_workspace_start._get_declaration()
    properties = (
        (declaration.parameters.properties or {}) if declaration.parameters else {}
    )
    assert properties == {}
    assert declaration.parameters is None or not declaration.parameters.required


def test_public_offer_never_exposes_infrastructure_values(monkeypatch):
    _, result = _diagnose_for_offer(monkeypatch)

    exposed = json.dumps(result["start_offer"])
    assert "ws-1234567890" not in exposed
    assert "d-1234567890" not in exposed
    assert "example.directory.user" not in exposed
    assert "us-east-1" not in exposed


def test_start_uses_offer_workspace_id_not_any_caller_value(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=["STOPPED", "AVAILABLE"])

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "ok"
    start_kwargs = [kwargs for name, kwargs in client.calls if name == "start_workspaces"]
    assert start_kwargs == [
        {"StartWorkspaceRequests": [{"WorkspaceId": "ws-1234567890"}]}
    ]


# --- separate-turn confirmation --------------------------------------------


def test_same_turn_diagnosis_and_mutation_is_refused(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient()

    result = _confirm(context, client, monkeypatch, invocation_id="turn-1-diagnosis")

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_NEW_CONFIRMATION_REQUIRED"
    assert client.start_calls == []


def test_later_confirmation_starts_the_workspace_exactly_once(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=["STOPPED", "STARTING", "AVAILABLE"])

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "ok"
    assert result["verified_available"] is True
    assert result["workspace_state"] == "AVAILABLE"
    assert result["message"] == (
        "Your AWS WorkSpace is available now. Please try connecting again."
    )
    assert len(client.start_calls) == 1
    assert context.state[START_STATE_KEY]["phase"] == "executed"


def test_yes_without_any_offer_executes_nothing(monkeypatch):
    client = _FakeStartClient()
    context = _context()

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_OFFER_MISSING"
    assert client.calls == []


def test_expired_offer_executes_nothing(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    context.state[START_STATE_KEY]["expires_at"] = int(time.time()) - 1
    client = _FakeStartClient()

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_OFFER_EXPIRED"
    assert client.start_calls == []
    assert context.state[START_STATE_KEY]["phase"] == "expired"


def test_offer_for_another_action_is_refused(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    context.state[START_STATE_KEY]["action_id"] = "gcp.virtual_desktop.system_file_cleanup"
    client = _FakeStartClient()

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_ACTION_INVALID"
    assert client.start_calls == []


def test_confirmation_cannot_be_replayed(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=["STOPPED", "AVAILABLE"])

    first = _confirm(context, client, monkeypatch)
    replay = _confirm(context, client, monkeypatch, invocation_id="turn-3-replay")

    assert first["status"] == "ok"
    assert replay["status"] == "error"
    assert replay["code"] == "AWS_WORKSPACES_START_OFFER_MISSING"
    assert len(client.start_calls) == 1


def test_offer_is_consumed_before_the_write_leaves_the_process(monkeypatch):
    """The one-way transition must happen before StartWorkspaces, not after.

    Consuming it only on the way out would leave a window in which a concurrent
    confirmation still observes phase == "offered" and starts the WorkSpace a
    second time.
    """
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=["STOPPED", "AVAILABLE"])
    observed_phases = []

    original_start = client.start_workspaces

    def recording_start(**kwargs):
        observed_phases.append(context.state[START_STATE_KEY]["phase"])
        return original_start(**kwargs)

    client.start_workspaces = recording_start

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "ok"
    assert observed_phases == ["confirmed"]
    assert context.state[START_STATE_KEY]["phase"] == "executed"


def test_caller_change_after_the_offer_starts_nothing(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    other = {
        "displayName": "Other User",
        "userPrincipalName": "other@example.com",
        "id": "other-object-id",
        "devices": [],
    }
    context.state["persona"] = other
    context.state["user:persona"] = other
    context.state.pop("identity_context", None)
    client = _FakeStartClient()

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_CALLER_CHANGED"
    assert client.calls == []
    assert context.state[START_STATE_KEY]["phase"] == "failed"


# --- fresh re-verification before the write --------------------------------


def test_workspace_id_change_invalidates_the_offer(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=["STOPPED"], workspace_id="ws-9999999999")

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_WORKSPACE_CHANGED"
    assert client.start_calls == []
    assert context.state[START_STATE_KEY]["phase"] == "failed"


def test_state_change_before_confirmation_invalidates_the_offer(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=["AVAILABLE"])

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_STATE_CHANGED"
    assert client.start_calls == []


def test_running_mode_change_before_confirmation_starts_nothing(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=["STOPPED"], running_mode="ALWAYS_ON")

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_RUNNING_MODE_INVALID"
    assert client.start_calls == []


def test_unassigned_workspace_at_confirmation_starts_nothing(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=[None])

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_WORKSPACE_CHANGED"
    assert client.start_calls == []


# --- post-action verification and failure handling -------------------------


def test_success_requires_a_fresh_available_reading(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=["STOPPED", "STARTING", "STARTING", "AVAILABLE"])

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "ok"
    describes = [name for name, _ in client.calls if name == "describe_workspaces"]
    # One pre-write re-verification plus polling until AVAILABLE was observed.
    assert len(describes) == 4
    assert client.calls[-1][0] == "describe_workspaces_connection_status"


def test_disconnected_connection_state_does_not_block_success(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(
        states=["STOPPED", "AVAILABLE"], connection_state="DISCONNECTED"
    )

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "ok"
    assert result["verified_available"] is True
    assert result["connection"]["state"] == "DISCONNECTED"


def test_timeout_before_available_is_never_reported_as_success(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    monkeypatch.setattr(workspaces, "START_POLL_TIMEOUT_SECONDS", 0)
    client = _FakeStartClient(states=["STOPPED", "STARTING"])

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_NOT_AVAILABLE_IN_TIME"
    assert result["verified_available"] is False
    assert result["workspace_state"] == "STARTING"
    assert "available now" not in result["message"]
    assert len(client.start_calls) == 1


def test_error_state_after_start_is_never_reported_as_success(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=["STOPPED", "ERROR"])

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_ENTERED_FAILURE_STATE"
    assert result["verified_available"] is False
    assert result["workspace_state"] == "ERROR"
    assert len(client.start_calls) == 1


def test_failed_request_entry_is_reported_and_not_retried(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(
        states=["STOPPED"],
        failed_requests=[
            {
                "WorkspaceId": "ws-1234567890",
                "ErrorCode": "ResourceUnavailable",
                "ErrorMessage": "The WorkSpace is not currently startable.",
            }
        ],
    )

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_WORKSPACES_START_REQUEST_REJECTED"
    assert "ResourceUnavailable" in result["message"]
    assert len(client.start_calls) == 1
    assert context.state[START_STATE_KEY]["phase"] == "failed"


def test_start_api_exception_is_not_retried_or_faked(monkeypatch):
    context, _ = _diagnose_for_offer(monkeypatch)
    denied = Exception("denied")
    denied.response = {"Error": {"Code": "AccessDeniedException"}}
    client = _FakeStartClient(states=["STOPPED"], start_error=denied)

    result = _confirm(context, client, monkeypatch)

    assert result["status"] == "error"
    assert result["code"] == "AWS_ACCESS_DENIED"
    assert len(client.start_calls) == 1
    assert context.state[START_STATE_KEY]["phase"] == "failed"


# --- surface and disclosure contracts --------------------------------------


def test_runtime_tool_exposes_no_stop_reboot_rebuild_or_terminate(monkeypatch):
    exported = {getattr(tool, "name", "") for tool in workspaces.aws_workspaces_tools}

    assert exported == {
        "aws_diagnose_workspace_login",
        "aws_diagnose_workspace_performance",
        "aws_confirm_workspace_start",
    }
    source = inspect.getsource(workspaces).lower()
    for forbidden in (
        "stop_workspaces",
        "reboot_workspaces",
        "rebuild_workspaces",
        "restore_workspace",
        "terminate_workspaces",
        "modify_workspace",
    ):
        assert forbidden not in source


def test_registration_code_never_reaches_start_output_or_state(monkeypatch):
    context, diagnosis = _diagnose_for_offer(monkeypatch)
    client = _FakeStartClient(states=["STOPPED", "AVAILABLE"])

    result = _confirm(context, client, monkeypatch)

    serialized = json.dumps(
        {
            "diagnosis": diagnosis,
            "start": result,
            "state": {
                key: value
                for key, value in context.state.items()
                if key != "user:persona"
            },
        },
        default=str,
    ).lower()
    assert "registrationcode" not in serialized
    assert "registration_code" not in serialized


def test_start_action_registry_entry_is_atomic_and_input_free():
    entry = json.loads(
        Path("sd_chat/action_registry/aws.workspaces.start.json").read_text(
            encoding="utf-8"
        )
    )

    assert entry["id"] == "aws.workspaces.start"
    assert entry["inputs"] == []
    assert entry["args_template"] == {}
    assert entry["tool"] == "aws_workspaces_tool"
    assert entry["action"] == "confirm_workspace_start"


def test_agent_instruction_binds_start_to_the_offer_and_forbids_same_turn():
    instruction = sd_chat.instruction

    assert "aws_confirm_workspace_start() with NO arguments" in instruction
    assert "Do NOT start it in that same turn" in instruction
    assert "verified_available == true" in instruction
    assert "Never announce" in instruction
    assert "Never retry the start" in instruction
    assert "start_offer is null or absent, do not mention starting" in instruction


def test_start_tool_is_registered_on_the_root_agent():
    tool_names = {getattr(tool, "name", "") for tool in root_agent.tools}

    assert "aws_confirm_workspace_start" in tool_names
    assert "gcp_diagnose_virtual_desktop_login" in tool_names
    assert "diagnose_account_access" in tool_names
