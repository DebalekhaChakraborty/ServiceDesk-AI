$ErrorActionPreference = "Continue"
$ServiceDeskRoot = "C:\ProgramData\ServiceDeskVDI"
$CapabilityPath = Join-Path $ServiceDeskRoot "capabilities.json"
$CounterProbePath = Join-Path $ServiceDeskRoot "Measure-RdpUserInputDelay.ps1"
$CounterProbeOutputPath = Join-Path $ServiceDeskRoot ("rdp_input_delay_sample_{0}.txt" -f $PID)
$MaximumTelemetryFiles = 360
$PublishIntervalSeconds = 30
$MaximumCounterProbeMilliseconds = 5000
$Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
$ServiceDeskEventSource = "ServiceDeskVDI"
$TelemetryEventId = 7101

New-Item -Path $ServiceDeskRoot -ItemType Directory -Force | Out-Null

$CounterAvailable = $false
$RttCounterAvailable = $false
# 0 means the capability file was unreadable or predates the versioned contract.
# It is reported verbatim so the backend can tell an outdated collector apart
# from a genuinely unavailable counter. The collector never invents the field.
$CapabilitySchemaVersion = 0
try {
    $Capabilities = Get-Content -Path $CapabilityPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $CounterAvailable = $Capabilities.user_input_delay_counter_set_available -eq $true
    $RttCounterAvailable = $Capabilities.rdp_tcp_rtt_counter_set_available -eq $true
    $ReportedVersion = $Capabilities.servicedesk_vdi_telemetry_schema_version
    if ($ReportedVersion -is [int] -or $ReportedVersion -match "^\d+$") {
        $CapabilitySchemaVersion = [int]$ReportedVersion
    }
}
catch {
    $CounterAvailable = $false
    $RttCounterAvailable = $false
    $CapabilitySchemaVersion = 0
}

$WindowEnds = (Get-Date).AddSeconds($PublishIntervalSeconds)
$DelaySamples = @()
$RttSamples = @()
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
        if ($null -ne $ProbeRecord.user_input_delay_value -and [double]$ProbeRecord.user_input_delay_value -ge 0) {
            $DelaySamples += [double]$ProbeRecord.user_input_delay_value
        }
        if ($null -ne $ProbeRecord.tcp_rtt_value -and [double]$ProbeRecord.tcp_rtt_value -ge 0) {
            $RttSamples += [double]$ProbeRecord.tcp_rtt_value
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
$MaximumRtt = $null
if ($RttSamples.Count -gt 0) {
    $MaximumRtt = [math]::Round(
        [double](($RttSamples | Measure-Object -Maximum).Maximum),
        2
    )
}

$Record = [ordered]@{
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    # Echoed from capabilities.json so the backend can detect a guest whose
    # bootstrap predates RDP TCP RTT discovery. 0 = missing/unreadable.
    servicedesk_vdi_telemetry_schema_version = $CapabilitySchemaVersion
    session_active = ($MaximumActiveSessions -gt 0)
    session_count = $MaximumActiveSessions
    counter_available = $CounterAvailable
    max_user_input_delay_ms = $MaximumDelay
    rdp_tcp_rtt_counter_available = $RttCounterAvailable
    rdp_tcp_rtt_ms = $MaximumRtt
    rdp_tcp_rtt_source = "windows_remotefx_network_current_tcp_rtt"
}

try {
    # Publish a completed record under a fresh, fixed-prefix filename. On
    # Windows this avoids write contention with the Ops Agent tail receiver,
    # which can keep an already-discovered file open. The temporary filename
    # does not match the receiver wildcard and the final move is atomic.
    $RecordToken = "{0}_{1}_{2}" -f (
        (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffffffZ")
    ), $PID, ([guid]::NewGuid().ToString("N"))
    $TelemetryTempPath = Join-Path $ServiceDeskRoot ("rdp_telemetry_{0}.tmp" -f $RecordToken)
    $TelemetryPath = Join-Path $ServiceDeskRoot ("rdp_telemetry_{0}.jsonl" -f $RecordToken)
    $TelemetryJson = $Record | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($TelemetryTempPath, $TelemetryJson, $Utf8WithoutBom)
    Move-Item -Path $TelemetryTempPath -Destination $TelemetryPath
    Write-EventLog -LogName "Application" -Source $ServiceDeskEventSource -EventId $TelemetryEventId -EntryType Information -Message $TelemetryJson
    Get-ChildItem -Path $ServiceDeskRoot -Filter "rdp_telemetry_*.jsonl" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -Skip $MaximumTelemetryFiles |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
catch {
    if ($TelemetryTempPath) {
        Remove-Item -Path $TelemetryTempPath -Force -ErrorAction SilentlyContinue
    }
    exit 1
}
