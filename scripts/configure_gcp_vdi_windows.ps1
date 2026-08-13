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

try {
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
    $CounterAvailable = $null -ne $CounterSet

    [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        available_event_channels = $AvailableChannels
        unavailable_event_channels = $UnavailableChannels
        user_input_delay_counter_set_available = $CounterAvailable
        user_input_delay_counter_set = if ($CounterAvailable) { $CounterSet.CounterSetName } else { $null }
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
try {
    $Capabilities = Get-Content -Path $CapabilityPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $CounterAvailable = $Capabilities.user_input_delay_counter_set_available -eq $true
}
catch {
    $CounterAvailable = $false
}

$SessionLines = & "$env:SystemRoot\System32\qwinsta.exe" 2>$null
$ActiveSessions = @(
    $SessionLines |
        Select-Object -Skip 1 |
        Where-Object { $_ -match "\sActive\s" }
).Count

$ProbeRecord = [ordered]@{
    session_count = $ActiveSessions
    counter_value = $null
}
$ProbeRecord | ConvertTo-Json -Compress | Set-Content -Path $ResultPath -Encoding UTF8

if ($ActiveSessions -eq 0 -or -not $CounterAvailable) {
    exit 0
}

$CounterSet = Get-Counter -ListSet * -ErrorAction Stop |
    Where-Object { $_.CounterSetName -eq "User Input Delay per Session" } |
    Select-Object -First 1
if (-not $CounterSet) {
    exit 0
}

$CounterPaths = @($CounterSet.PathsWithInstances | Where-Object { $_ })
if ($CounterPaths.Count -eq 0) {
    $CounterPaths = @($CounterSet.Paths | Where-Object { $_ })
}
if ($CounterPaths.Count -eq 0) {
    exit 0
}

$CounterResult = Get-Counter -Counter $CounterPaths -MaxSamples 1 -ErrorAction Stop
$MaximumDelay = @(
    $CounterResult.CounterSamples |
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
            & "$env:SystemRoot\System32\taskkill.exe" `
                /PID $CollectorProcess.Id `
                /T `
                /F | Out-Null
            $CollectorProcess.WaitForExit()
        }
    }
    catch {
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
Write-SupervisorAudit -Phase "supervisor_completed" -ExitCode 0
'@
    Set-Content -Path $SupervisorPath -Value $SupervisorScript -Encoding UTF8

    $ChannelYaml = ($AvailableChannels | ForEach-Object {
        "          - '" + ($_ -replace "'", "''") + "'"
    }) -join "`r`n"
    $OpsAgentConfig = @"
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
    # Windows PowerShell's `Set-Content -Encoding UTF8` writes a BOM. The Ops
    # Agent YAML parser treats that marker as part of the first key (`?logging`)
    # and refuses to start, so write the configuration explicitly without it.
    $Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OpsAgentConfigPath, $OpsAgentConfig, $Utf8WithoutBom)

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
    $TaskStartTime = (Get-Date).AddSeconds(30)
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
        $null -ne $CollectorTaskInfo
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
        $RenderedConfig = (Get-Content -Path $OpsAgentConfigPath -Raw -ErrorAction SilentlyContinue) `
            -replace "`r?`n", " | "
        Write-Output "ServiceDesk Ops Agent rendered config: $RenderedConfig"
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
