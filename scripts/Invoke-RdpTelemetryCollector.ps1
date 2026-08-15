$ErrorActionPreference = "Continue"
$CollectorPath = "C:\ProgramData\ServiceDeskVDI\Collect-RdpUserInputDelay.ps1"
$ServiceDeskRoot = "C:\ProgramData\ServiceDeskVDI"
$MaximumAuditFiles = 720
$Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
$ServiceDeskEventSource = "ServiceDeskVDI"
$AuditEventId = 7102

function Write-CollectorAudit {
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
