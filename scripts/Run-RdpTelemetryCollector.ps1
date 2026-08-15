param(
    [int]$MaximumIterations = 0
)

$ErrorActionPreference = "Continue"
$TaskRunnerPath = "C:\ProgramData\ServiceDeskVDI\Invoke-RdpTelemetryCollector.ps1"
$ServiceDeskRoot = "C:\ProgramData\ServiceDeskVDI"
$MaximumAuditFiles = 720
$Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
$ServiceDeskEventSource = "ServiceDeskVDI"
$AuditEventId = 7102
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
        $AuditToken = "{0}_{1}_{2}" -f (
            (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffffffZ")
        ), $PID, ([guid]::NewGuid().ToString("N"))
        $AuditTempPath = Join-Path $ServiceDeskRoot ("rdp_collector_audit_{0}.tmp" -f $AuditToken)
        $AuditPath = Join-Path $ServiceDeskRoot ("rdp_collector_audit_{0}.jsonl" -f $AuditToken)
        $AuditJson = [ordered]@{
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
            phase = $Phase
            exit_code = $ExitCode
        } | ConvertTo-Json -Compress
        [System.IO.File]::WriteAllText($AuditTempPath, $AuditJson, $Utf8WithoutBom)
        Move-Item -Path $AuditTempPath -Destination $AuditPath
        Write-EventLog -LogName "Application" -Source $ServiceDeskEventSource -EventId $AuditEventId -EntryType Information -Message $AuditJson
        Get-ChildItem -Path $ServiceDeskRoot -Filter "rdp_collector_audit_*.jsonl" -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -Skip $MaximumAuditFiles |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch {
        if ($AuditTempPath) {
            Remove-Item -Path $AuditTempPath -Force -ErrorAction SilentlyContinue
        }
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
