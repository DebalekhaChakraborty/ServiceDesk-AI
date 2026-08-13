# ServiceDesk GCP Windows virtual-desktop PoC telemetry bootstrap.
# This script is idempotent, contains no credentials, and performs no user remediation.
# It must not change domain membership, SCCM/ConfigMgr, endpoint-management policy,
# Windows networking, firewall state, or existing user/device configuration.

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ServiceDeskRoot = "C:\ProgramData\ServiceDeskVDI"
$TelemetryPath = Join-Path $ServiceDeskRoot "rdp_telemetry.jsonl"
$CollectorPath = Join-Path $ServiceDeskRoot "Collect-RdpUserInputDelay.ps1"
$CounterProbePath = Join-Path $ServiceDeskRoot "Measure-RdpUserInputDelay.ps1"
$TaskRunnerPath = Join-Path $ServiceDeskRoot "Invoke-RdpTelemetryCollector.ps1"
$SupervisorPath = Join-Path $ServiceDeskRoot "Run-RdpTelemetryCollector.ps1"
$CollectorAuditPath = Join-Path $ServiceDeskRoot "rdp_collector_audit.jsonl"
$CapabilityPath = Join-Path $ServiceDeskRoot "capabilities.json"
$SetupStatusPath = Join-Path $ServiceDeskRoot "setup_status.json"
$OpsAgentConfigPath = "C:\Program Files\Google\Cloud Operations\Ops Agent\config\config.yaml"
$OpsAgentBackupPath = "C:\Program Files\Google\Cloud Operations\Ops Agent\config\config.pre-servicedesk.bak"
$OpsAgentManagedSnapshotPath = Join-Path $ServiceDeskRoot "ops_agent_servicedesk_config.yaml"
$OpsAgentOwnershipMarker = "# managed-by: ServiceDeskVDI"
$TaskName = "ServiceDeskVDI-RdpTelemetry"

New-Item -Path $ServiceDeskRoot -ItemType Directory -Force | Out-Null

function Write-SetupStatus {
    param(
        [string]$Status,
        [string]$Phase,
        [string]$Message
    )
    [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        status = $Status
        phase = $Phase
        message = $Message
    } | ConvertTo-Json -Compress | Set-Content -Path $SetupStatusPath -Encoding UTF8
}

function Write-ExistingTaskDiagnostic {
    # Capture the previous task's truth before this idempotent bootstrap replaces
    # it. Only fixed ServiceDesk action/principal values and scheduler metadata are
    # emitted; unexpected executable/argument/principal values are redacted.
    try {
        $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -eq $ExistingTask) {
            return
        }
        $ExistingTaskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        $ExpectedExecute = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $ExpectedArguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SupervisorPath -MaximumIterations 1"
        $ExistingAction = @($ExistingTask.Actions)[0]
        $ExistingTrigger = @($ExistingTask.Triggers)[0]
        $ActualExecute = [string]$ExistingAction.Execute
        $ActualArguments = [string]$ExistingAction.Arguments
        $ActualPrincipal = [string]$ExistingTask.Principal.UserId
        $SafeLastRunTime = $null
        $SafeNextRunTime = $null
        if ($null -ne $ExistingTaskInfo -and $ExistingTaskInfo.LastRunTime.Year -gt 1) {
            $SafeLastRunTime = $ExistingTaskInfo.LastRunTime.ToUniversalTime().ToString("o")
        }
        if ($null -ne $ExistingTaskInfo -and $ExistingTaskInfo.NextRunTime.Year -gt 1) {
            $SafeNextRunTime = $ExistingTaskInfo.NextRunTime.ToUniversalTime().ToString("o")
        }
        $TelemetryFile = Get-Item -Path $TelemetryPath -ErrorAction SilentlyContinue
        $AuditFile = Get-Item -Path $CollectorAuditPath -ErrorAction SilentlyContinue
        [ordered]@{
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
            phase = "existing_task_diagnostic"
            task_state = [string]$ExistingTask.State
            last_run_time = $SafeLastRunTime
            next_run_time = $SafeNextRunTime
            last_task_result = if ($null -ne $ExistingTaskInfo) { [int64]$ExistingTaskInfo.LastTaskResult } else { $null }
            missed_runs = if ($null -ne $ExistingTaskInfo) { [int64]$ExistingTaskInfo.NumberOfMissedRuns } else { $null }
            action_execute = if ($ActualExecute -ieq $ExpectedExecute) { $ExpectedExecute } else { "unexpected_redacted" }
            action_arguments = if ($ActualArguments -ceq $ExpectedArguments) { $ExpectedArguments } else { "unexpected_redacted" }
            trigger_start_boundary = if ($null -ne $ExistingTrigger) { [string]$ExistingTrigger.StartBoundary } else { $null }
            repetition_interval = if ($null -ne $ExistingTrigger) { [string]$ExistingTrigger.Repetition.Interval } else { $null }
            repetition_duration = if ($null -ne $ExistingTrigger) { [string]$ExistingTrigger.Repetition.Duration } else { $null }
            principal_user_id = if ($ActualPrincipal -ieq "SYSTEM") { "SYSTEM" } else { "unexpected_redacted" }
            principal_logon_type = [string]$ExistingTask.Principal.LogonType
            principal_run_level = [string]$ExistingTask.Principal.RunLevel
            telemetry_last_write_time = if ($null -ne $TelemetryFile) { $TelemetryFile.LastWriteTimeUtc.ToString("o") } else { $null }
            telemetry_size_bytes = if ($null -ne $TelemetryFile) { [int64]$TelemetryFile.Length } else { $null }
            audit_last_write_time = if ($null -ne $AuditFile) { $AuditFile.LastWriteTimeUtc.ToString("o") } else { $null }
            audit_size_bytes = if ($null -ne $AuditFile) { [int64]$AuditFile.Length } else { $null }
        } | ConvertTo-Json -Compress | Add-Content -Path $CollectorAuditPath -Encoding UTF8

        $TaskSchedulerEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-TaskScheduler/Operational"
            StartTime = (Get-Date).AddHours(-6)
        } -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -like "*ServiceDeskVDI-RdpTelemetry*"
        } | Select-Object -First 30
        foreach ($TaskEvent in $TaskSchedulerEvents) {
            [ordered]@{
                timestamp = (Get-Date).ToUniversalTime().ToString("o")
                phase = "existing_task_scheduler_event"
                event_time = $TaskEvent.TimeCreated.ToUniversalTime().ToString("o")
                event_id = [int]$TaskEvent.Id
                event_level = [string]$TaskEvent.LevelDisplayName
            } | ConvertTo-Json -Compress | Add-Content -Path $CollectorAuditPath -Encoding UTF8
        }
    }
    catch {
        # Diagnostic collection must not alter or block bootstrap behavior.
    }
}

try {
    Write-ExistingTaskDiagnostic
    Write-SetupStatus -Status "running" -Phase "ops_agent" -Message "Checking Google Ops Agent."
    $OpsAgentService = Get-Service -Name "google-cloud-ops-agent" -ErrorAction SilentlyContinue
    if (-not $OpsAgentService) {
        $InstallerPath = Join-Path $env:TEMP "add-google-cloud-ops-agent-repo.ps1"
        (New-Object Net.WebClient).DownloadFile(
            "https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.ps1",
            $InstallerPath
        )
        & $InstallerPath -AlsoInstall
        if ($LASTEXITCODE -ne 0) {
            throw "Google Ops Agent installation returned exit code $LASTEXITCODE."
        }
    }

    Write-SetupStatus -Status "running" -Phase "capability_discovery" -Message "Discovering Windows RDP telemetry capabilities."
    $RequestedChannels = @(
        "System",
        "Application",
        "Security",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
    )
    $AvailableChannels = @()
    $UnavailableChannels = @()
    foreach ($Channel in $RequestedChannels) {
        try {
            Get-WinEvent -ListLog $Channel -ErrorAction Stop | Out-Null
            $AvailableChannels += $Channel
        }
        catch {
            $UnavailableChannels += $Channel
        }
    }

    $CounterSet = Get-Counter -ListSet * -ErrorAction SilentlyContinue |
        Where-Object { $_.CounterSetName -eq "User Input Delay per Session" } |
        Select-Object -First 1
    $CounterPaths = @()
    if ($null -ne $CounterSet) {
        # Persist the validated wildcard path once. Recurring probes reuse this
        # exact path and never enumerate every Windows performance-counter set.
        $CounterPaths = @($CounterSet.Paths | Where-Object { $_ })
    }
    $CounterAvailable = $CounterPaths.Count -gt 0

    [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        available_event_channels = $AvailableChannels
        unavailable_event_channels = $UnavailableChannels
        user_input_delay_counter_set_available = $CounterAvailable
        user_input_delay_counter_set = if ($CounterAvailable) { $CounterSet.CounterSetName } else { $null }
        user_input_delay_counter_paths = $CounterPaths
    } | ConvertTo-Json -Depth 4 | Set-Content -Path $CapabilityPath -Encoding UTF8

    $CounterProbeScript = @'
param(
    [Parameter(Mandatory = $true)]
    [string]$ResultToken
)

$ErrorActionPreference = "Stop"
$ServiceDeskRoot = "C:\ProgramData\ServiceDeskVDI"
$CapabilityPath = Join-Path $ServiceDeskRoot "capabilities.json"
if ($ResultToken -notmatch "^\d+$") {
    throw "Invalid internal result token."
}
$ResultPath = Join-Path $ServiceDeskRoot ("rdp_input_delay_sample_{0}.txt" -f $ResultToken)

$CounterAvailable = $false
$CounterPaths = @()
try {
    $Capabilities = Get-Content -Path $CapabilityPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $CounterAvailable = $Capabilities.user_input_delay_counter_set_available -eq $true
    $CounterPaths = @($Capabilities.user_input_delay_counter_paths | Where-Object { $_ })
}
catch {
    $CounterAvailable = $false
    $CounterPaths = @()
}

$SessionLines = & "$env:SystemRoot\System32\qwinsta.exe" 2>$null
$ActiveRdpSessionIds = @()
foreach ($SessionLine in @($SessionLines | Select-Object -Skip 1)) {
    $NormalizedLine = ([string]$SessionLine -replace "^\s*>", "").Trim()
    if (-not $NormalizedLine) {
        continue
    }
    $Columns = @($NormalizedLine -split "\s+")
    $StateIndex = [Array]::IndexOf($Columns, "Active")
    if ($StateIndex -lt 2) {
        continue
    }
    $SessionName = [string]$Columns[0]
    $SessionId = [string]$Columns[$StateIndex - 1]
    if ($SessionName -match "^rdp-tcp(?:#\d+)?$" -and $SessionId -match "^\d+$") {
        $ActiveRdpSessionIds += $SessionId
    }
}

$ProbeRecord = [ordered]@{
    session_count = $ActiveRdpSessionIds.Count
    counter_value = $null
}
$ProbeRecord | ConvertTo-Json -Compress | Set-Content -Path $ResultPath -Encoding UTF8

if ($ActiveRdpSessionIds.Count -eq 0 -or -not $CounterAvailable -or $CounterPaths.Count -eq 0) {
    exit 0
}

$CounterResult = Get-Counter -Counter $CounterPaths -MaxSamples 1 -ErrorAction Stop
$MaximumDelay = @(
    $CounterResult.CounterSamples |
        Where-Object { $ActiveRdpSessionIds -contains [string]$_.InstanceName } |
        ForEach-Object { [double]$_.CookedValue } |
        Where-Object { $_ -ge 0 }
) | Measure-Object -Maximum
if ($null -ne $MaximumDelay.Maximum) {
    $ProbeRecord.counter_value = [double]$MaximumDelay.Maximum
    $ProbeRecord | ConvertTo-Json -Compress | Set-Content -Path $ResultPath -Encoding UTF8
}
'@
    Set-Content -Path $CounterProbePath -Value $CounterProbeScript -Encoding UTF8

    $CollectorScript = @'
$ErrorActionPreference = "Continue"
$ServiceDeskRoot = "C:\ProgramData\ServiceDeskVDI"
$TelemetryPath = Join-Path $ServiceDeskRoot "rdp_telemetry.jsonl"
$CapabilityPath = Join-Path $ServiceDeskRoot "capabilities.json"
$CounterProbePath = Join-Path $ServiceDeskRoot "Measure-RdpUserInputDelay.ps1"
$CounterProbeOutputPath = Join-Path $ServiceDeskRoot ("rdp_input_delay_sample_{0}.txt" -f $PID)
$RotatedPath = "$TelemetryPath.1"
$MaximumLogBytes = 5MB
$PublishIntervalSeconds = 30
$MaximumCounterProbeMilliseconds = 2500

New-Item -Path $ServiceDeskRoot -ItemType Directory -Force | Out-Null
if (-not (Test-Path $TelemetryPath)) {
    New-Item -Path $TelemetryPath -ItemType File -Force | Out-Null
}

$CounterAvailable = $false
try {
    $Capabilities = Get-Content -Path $CapabilityPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $CounterAvailable = $Capabilities.user_input_delay_counter_set_available -eq $true
}
catch {
    $CounterAvailable = $false
}

$WindowEnds = (Get-Date).AddSeconds($PublishIntervalSeconds)
$DelaySamples = @()
$MaximumActiveSessions = 0

while ((Get-Date) -lt $WindowEnds) {
    $CounterProbeProcess = $null
    try {
        Remove-Item -Path $CounterProbeOutputPath -Force -ErrorAction SilentlyContinue
        $CounterProbeProcess = Start-Process `
            -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -ArgumentList @(
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-File", $CounterProbePath,
                "-ResultToken", $PID
            ) `
            -PassThru
        if (-not $CounterProbeProcess.WaitForExit($MaximumCounterProbeMilliseconds)) {
            & "$env:SystemRoot\System32\taskkill.exe" `
                /PID $CounterProbeProcess.Id `
                /T `
                /F | Out-Null
            $CounterProbeProcess.WaitForExit()
        }

        $ProbeRecord = Get-Content -Path $CounterProbeOutputPath -Raw -ErrorAction SilentlyContinue |
            ConvertFrom-Json -ErrorAction SilentlyContinue
        $ProbeSessionCount = 0
        if ($null -ne $ProbeRecord) {
            $ProbeSessionCount = [int]$ProbeRecord.session_count
        }
        if ($ProbeSessionCount -gt $MaximumActiveSessions) {
            $MaximumActiveSessions = $ProbeSessionCount
        }
        if ($null -ne $ProbeRecord.counter_value -and [double]$ProbeRecord.counter_value -ge 0) {
            $DelaySamples += [double]$ProbeRecord.counter_value
        }
    }
    catch {
        # A single unavailable native Windows probe must not stop the window.
    }
    finally {
        if ($null -ne $CounterProbeProcess -and -not $CounterProbeProcess.HasExited) {
            & "$env:SystemRoot\System32\taskkill.exe" `
                /PID $CounterProbeProcess.Id `
                /T `
                /F | Out-Null
        }
        Remove-Item -Path $CounterProbeOutputPath -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
}

$MaximumDelay = $null
if ($DelaySamples.Count -gt 0) {
    $MaximumDelay = [math]::Round(
        [double](($DelaySamples | Measure-Object -Maximum).Maximum),
        2
    )
}

$Record = [ordered]@{
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    session_active = ($MaximumActiveSessions -gt 0)
    session_count = $MaximumActiveSessions
    counter_available = $CounterAvailable
    max_user_input_delay_ms = $MaximumDelay
}

try {
    if ((Test-Path $TelemetryPath) -and (Get-Item $TelemetryPath).Length -ge $MaximumLogBytes) {
        Move-Item -Path $TelemetryPath -Destination $RotatedPath -Force
        New-Item -Path $TelemetryPath -ItemType File -Force | Out-Null
    }
    $Record | ConvertTo-Json -Compress | Add-Content -Path $TelemetryPath -Encoding UTF8
}
catch {
    exit 1
}
'@
    Set-Content -Path $CollectorPath -Value $CollectorScript -Encoding UTF8

    $TaskRunnerScript = @'
$ErrorActionPreference = "Continue"
$CollectorPath = "C:\ProgramData\ServiceDeskVDI\Collect-RdpUserInputDelay.ps1"
$AuditPath = "C:\ProgramData\ServiceDeskVDI\rdp_collector_audit.jsonl"
$MaximumAuditBytes = 1MB

function Write-CollectorAudit {
    param(
        [string]$Phase,
        [Nullable[int]]$ExitCode
    )
    try {
        if ((Test-Path $AuditPath) -and (Get-Item $AuditPath).Length -ge $MaximumAuditBytes) {
            Move-Item -Path $AuditPath -Destination "$AuditPath.1" -Force
        }
        [ordered]@{
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
            phase = $Phase
            exit_code = $ExitCode
        } | ConvertTo-Json -Compress | Add-Content -Path $AuditPath -Encoding UTF8
    }
    catch {
        # The audit is diagnostic only and must not change collector behavior.
    }
}

Write-CollectorAudit -Phase "started" -ExitCode $null
& "PowerShell.exe" `
    -NoLogo `
    -NoProfile `
    -NonInteractive `
    -ExecutionPolicy Bypass `
    -File $CollectorPath
$CollectorExitCode = $LASTEXITCODE
Write-CollectorAudit -Phase "completed" -ExitCode $CollectorExitCode
exit $CollectorExitCode
'@
    Set-Content -Path $TaskRunnerPath -Value $TaskRunnerScript -Encoding UTF8

    $SupervisorScript = @'
param(
    [int]$MaximumIterations = 0
)

$ErrorActionPreference = "Continue"
$TaskRunnerPath = "C:\ProgramData\ServiceDeskVDI\Invoke-RdpTelemetryCollector.ps1"
$AuditPath = "C:\ProgramData\ServiceDeskVDI\rdp_collector_audit.jsonl"
$MaximumCollectorRuntimeMilliseconds = 45000
$RestartDelaySeconds = 2
$Iteration = 0
$SupervisorExitCode = 0

function Write-SupervisorAudit {
    param(
        [string]$Phase,
        [Nullable[int]]$ExitCode
    )
    try {
        [ordered]@{
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
            phase = $Phase
            exit_code = $ExitCode
        } | ConvertTo-Json -Compress | Add-Content -Path $AuditPath -Encoding UTF8
    }
    catch {
        # The audit is diagnostic only and must not change collector behavior.
    }
}

Write-SupervisorAudit -Phase "supervisor_started" -ExitCode $null

while ($MaximumIterations -eq 0 -or $Iteration -lt $MaximumIterations) {
    $Iteration += 1
    $CollectorProcess = $null
    try {
        $CollectorProcess = Start-Process `
            -FilePath "PowerShell.exe" `
            -ArgumentList @(
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-File", $TaskRunnerPath
            ) `
            -PassThru
        if (-not $CollectorProcess.WaitForExit($MaximumCollectorRuntimeMilliseconds)) {
            Write-SupervisorAudit -Phase "collector_timeout" -ExitCode $null
            $SupervisorExitCode = 124
            & "$env:SystemRoot\System32\taskkill.exe" `
                /PID $CollectorProcess.Id `
                /T `
                /F | Out-Null
            $CollectorProcess.WaitForExit()
        }
        elseif ($CollectorProcess.ExitCode -ne 0) {
            $SupervisorExitCode = [int]$CollectorProcess.ExitCode
            Write-SupervisorAudit -Phase "collector_failed" -ExitCode $SupervisorExitCode
        }
    }
    catch {
        $SupervisorExitCode = 1
        Write-SupervisorAudit -Phase "collector_launch_failed" -ExitCode $null
        if ($null -ne $CollectorProcess -and -not $CollectorProcess.HasExited) {
            & "$env:SystemRoot\System32\taskkill.exe" `
                /PID $CollectorProcess.Id `
                /T `
                /F | Out-Null
        }
    }
    if ($MaximumIterations -eq 0 -or $Iteration -lt $MaximumIterations) {
        Start-Sleep -Seconds $RestartDelaySeconds
    }
}
Write-SupervisorAudit -Phase "supervisor_completed" -ExitCode $SupervisorExitCode
exit $SupervisorExitCode
'@
    Set-Content -Path $SupervisorPath -Value $SupervisorScript -Encoding UTF8

    $ChannelYaml = ($AvailableChannels | ForEach-Object {
        "          - '" + ($_ -replace "'", "''") + "'"
    }) -join "`r`n"
    $OpsAgentConfig = @"
$OpsAgentOwnershipMarker
logging:
  receivers:
    windows_event_log:
      type: windows_event_log
      channels:
$ChannelYaml
      receiver_version: 2
    servicedesk_rdp_telemetry:
      type: files
      include_paths:
        - 'C:\ProgramData\ServiceDeskVDI\rdp_telemetry.jsonl'
      record_log_file_path: false
    servicedesk_rdp_collector_audit:
      type: files
      include_paths:
        - 'C:\ProgramData\ServiceDeskVDI\rdp_collector_audit.jsonl'
      record_log_file_path: false
  processors:
    servicedesk_rdp_json:
      type: parse_json
  service:
    pipelines:
      default_pipeline:
        receivers: [windows_event_log]
      servicedesk_rdp_telemetry:
        receivers: [servicedesk_rdp_telemetry]
        processors: [servicedesk_rdp_json]
      servicedesk_rdp_collector_audit:
        receivers: [servicedesk_rdp_collector_audit]
        processors: [servicedesk_rdp_json]
"@
    New-Item -Path (Split-Path $OpsAgentConfigPath) -ItemType Directory -Force | Out-Null
    function Get-NormalizedConfigText {
        param([string]$Text)
        return (($Text -replace "`r`n", "`n").Trim())
    }

    $ExistingOpsAgentConfig = ""
    if (Test-Path $OpsAgentConfigPath) {
        $ExistingOpsAgentConfig = Get-Content -Path $OpsAgentConfigPath -Raw -ErrorAction Stop
    }
    $MeaningfulExistingLines = @(
        $ExistingOpsAgentConfig -split "`r?`n" |
            Where-Object { $_.Trim() -and -not $_.Trim().StartsWith("#") }
    )
    $ExistingConfigIsMeaningful = $MeaningfulExistingLines.Count -gt 0
    $ManagedSnapshotMatches = $false
    if (Test-Path $OpsAgentManagedSnapshotPath) {
        $ManagedSnapshot = Get-Content -Path $OpsAgentManagedSnapshotPath -Raw -ErrorAction Stop
        $ManagedSnapshotMatches =
            (Get-NormalizedConfigText $ExistingOpsAgentConfig) -eq
            (Get-NormalizedConfigText $ManagedSnapshot)
    }
    # Recognize the exact config produced by the earlier PoC revision once, so it
    # can be upgraded to the ownership-marker/snapshot model without treating an
    # unrelated file containing similarly named entries as ServiceDesk-owned.
    $LegacyServiceDeskConfig = $OpsAgentConfig.Replace(
        "$OpsAgentOwnershipMarker`r`n",
        ""
    ).Replace("$OpsAgentOwnershipMarker`n", "")
    $LegacyServiceDeskConfigMatches =
        (Get-NormalizedConfigText $ExistingOpsAgentConfig) -eq
        (Get-NormalizedConfigText $LegacyServiceDeskConfig)

    if ($ExistingConfigIsMeaningful -and
        -not $ManagedSnapshotMatches -and
        -not $LegacyServiceDeskConfigMatches) {
        if (-not (Test-Path $OpsAgentBackupPath)) {
            Copy-Item -Path $OpsAgentConfigPath -Destination $OpsAgentBackupPath -ErrorAction Stop
        }
        throw "Existing Ops Agent user configuration is not ServiceDesk-owned; it was preserved and requires an explicit safe merge."
    }
    if ((Test-Path $OpsAgentConfigPath) -and -not (Test-Path $OpsAgentBackupPath)) {
        Copy-Item -Path $OpsAgentConfigPath -Destination $OpsAgentBackupPath -ErrorAction Stop
    }

    # Windows PowerShell's `Set-Content -Encoding UTF8` writes a BOM. The Ops
    # Agent YAML parser treats that marker as part of the first key (`?logging`)
    # and refuses to start, so write ServiceDesk-owned files explicitly without it.
    $Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    $OpsAgentTempPath = "$OpsAgentConfigPath.servicedesk.tmp"
    [System.IO.File]::WriteAllText($OpsAgentTempPath, $OpsAgentConfig, $Utf8WithoutBom)
    Move-Item -Path $OpsAgentTempPath -Destination $OpsAgentConfigPath -Force
    [System.IO.File]::WriteAllText(
        $OpsAgentManagedSnapshotPath,
        $OpsAgentConfig,
        $Utf8WithoutBom
    )

    Write-SetupStatus -Status "running" -Phase "collector_validation" -Message "Validating the read-only RDP telemetry collector."
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

    # Do not manually start a long-running child from the GCE metadata startup
    # runner. Windows can retain that process in the startup job and terminate it
    # when the metadata script exits. A logon-only trigger is also insufficient:
    # reconnecting an existing RDP session does not create a new Windows logon.
    # First validate one exact supervisor/collector iteration synchronously. The
    # scheduled task is registered only after this exits, preventing the first
    # trigger from overlapping the startup validation copy.
    $CollectorValidationStarted = (Get-Date).ToUniversalTime()
    & "PowerShell.exe" `
        -NoLogo `
        -NoProfile `
        -NonInteractive `
        -ExecutionPolicy Bypass `
        -File $SupervisorPath `
        -MaximumIterations 1
    if ($LASTEXITCODE -ne 0) {
        throw "The RDP telemetry collector validation returned exit code $LASTEXITCODE."
    }
    $TelemetryFile = Get-Item -Path $TelemetryPath -ErrorAction SilentlyContinue
    if ($null -eq $TelemetryFile -or $TelemetryFile.LastWriteTimeUtc -lt $CollectorValidationStarted) {
        throw "The RDP telemetry collector validation did not produce a fresh sample."
    }

    # Run one bounded supervisor iteration through Task Scheduler every minute.
    # Each scheduled invocation exits after its 30-second collection window;
    # IgnoreNew prevents overlap if an invocation takes longer than expected.
    # The repeating trigger and VM have a three-hour safety boundary, while each
    # collector child is capped at 45 seconds.
    Write-SetupStatus -Status "running" -Phase "scheduled_task" -Message "Registering read-only RDP telemetry collector."
    $TaskAction = New-ScheduledTaskAction `
        -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SupervisorPath -MaximumIterations 1"
    # Keep the first boundary comfortably after registration and the Ops Agent
    # restart below. A missed StartWhenAvailable boundary can be queued with a
    # substantial scheduler delay, so it is not a substitute for a future
    # boundary during bootstrap.
    $TaskStartTime = (Get-Date).AddMinutes(2)
    $TaskTrigger = New-ScheduledTaskTrigger `
        -Once `
        -At $TaskStartTime `
        -RepetitionInterval (New-TimeSpan -Minutes 1) `
        -RepetitionDuration (New-TimeSpan -Hours 3)
    $TaskPrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $TaskSettings = New-ScheduledTaskSettingsSet `
        -MultipleInstances IgnoreNew `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 3)
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $TaskAction `
        -Trigger $TaskTrigger `
        -Principal $TaskPrincipal `
        -Settings $TaskSettings `
        -Force | Out-Null

    $CollectorTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $CollectorTaskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    $TaskRegistrationCheckedAt = Get-Date
    try {
        [ordered]@{
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
            phase = "task_registered"
            exit_code = $null
            task_state = if ($null -ne $CollectorTask) { [string]$CollectorTask.State } else { "unavailable" }
            next_run_time = if ($null -ne $CollectorTaskInfo) { $CollectorTaskInfo.NextRunTime.ToUniversalTime().ToString("o") } else { $null }
        } | ConvertTo-Json -Compress | Add-Content -Path $CollectorAuditPath -Encoding UTF8
    }
    catch {
        # Registration audit is diagnostic only.
    }
    $CollectorReady = $null -ne $CollectorTask -and
        $CollectorTask.State -eq "Ready" -and
        $null -ne $CollectorTaskInfo -and
        $CollectorTaskInfo.NextRunTime -gt $TaskRegistrationCheckedAt
    if (-not $CollectorReady) {
        $TaskResult = if ($null -ne $CollectorTaskInfo) { $CollectorTaskInfo.LastTaskResult } else { "unavailable" }
        throw "The RDP telemetry collector did not validate or register its bounded scheduled supervisor task (task result: $TaskResult)."
    }

    Restart-Service -Name "google-cloud-ops-agent" -Force
    $RequiredAgentServices = @(
        "google-cloud-ops-agent",
        "google-cloud-ops-agent-fluent-bit",
        "google-cloud-ops-agent-opentelemetry-collector"
    )
    $AgentStartDeadline = (Get-Date).AddSeconds(60)
    $AllAgentServicesRunning = $false
    do {
        $AgentServices = @(
            Get-Service -Name $RequiredAgentServices -ErrorAction SilentlyContinue
        )
        $AllAgentServicesRunning = $AgentServices.Count -eq $RequiredAgentServices.Count -and
            @($AgentServices | Where-Object { $_.Status -ne "Running" }).Count -eq 0
        if (-not $AllAgentServicesRunning) {
            Start-Sleep -Seconds 5
        }
    } while (-not $AllAgentServicesRunning -and (Get-Date) -lt $AgentStartDeadline)
    if (-not $AllAgentServicesRunning) {
        throw "One or more Google Ops Agent services did not reach running state within 60 seconds."
    }

    Write-SetupStatus -Status "ok" -Phase "complete" -Message "Ops Agent and ServiceDesk RDP telemetry are configured."
}
catch {
    Write-SetupStatus -Status "error" -Phase "failed" -Message $_.Exception.Message
    Write-Output "ServiceDesk PoC setup error: $($_.Exception.Message)"
    $DiagnosticLogs = @(
        "C:\ProgramData\Google\Cloud Operations\Ops Agent\log\health-checks.log",
        "C:\ProgramData\Google\Cloud Operations\Ops Agent\log\logging-module.log"
    )
    foreach ($DiagnosticLog in $DiagnosticLogs) {
        if (Test-Path $DiagnosticLog) {
            Write-Output "ServiceDesk Ops Agent diagnostic: $DiagnosticLog"
            Get-Content -Path $DiagnosticLog -Tail 80 -ErrorAction SilentlyContinue |
                Write-Output
        }
    }
    if (Test-Path $OpsAgentConfigPath) {
        $ConfigFile = Get-Item -Path $OpsAgentConfigPath -ErrorAction SilentlyContinue
        $ConfigHash = Get-FileHash -Path $OpsAgentConfigPath -Algorithm SHA256 -ErrorAction SilentlyContinue
        Write-Output "ServiceDesk Ops Agent config diagnostic: bytes=$($ConfigFile.Length), sha256=$($ConfigHash.Hash)"
    }
    $ServiceDiagnostics = Get-CimInstance Win32_Service -Filter "Name LIKE 'google-cloud-ops-agent%'" |
        Select-Object Name, State, StartMode, ExitCode, PathName |
        ConvertTo-Json -Compress
    Write-Output "ServiceDesk Ops Agent service state: $ServiceDiagnostics"
    $EventDiagnostics = Get-WinEvent -FilterHashtable @{
        LogName = "Application"
        StartTime = (Get-Date).AddMinutes(-10)
        Level = 2, 3
    } -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProviderName -like "*Ops Agent*" -or
            $_.ProviderName -like "*google-cloud*" -or
            $_.Message -like "*Ops Agent*"
        } |
        Select-Object -First 20 TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        ConvertTo-Json -Compress -Depth 4
    Write-Output "ServiceDesk Ops Agent related events: $EventDiagnostics"
    Start-Sleep -Seconds 3
    throw
}
