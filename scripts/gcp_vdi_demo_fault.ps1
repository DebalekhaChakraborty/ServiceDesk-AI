<#
LAB FAULT INJECTION — NOT PRODUCTION TELEMETRY

Run only on the approved GCP virtual-desktop PoC guest through an operator's
existing secure administrative session. This script is intentionally not called
by the ServiceDesk agent. It creates bounded CPU pressure only and removes all
background jobs before returning.
#>
[CmdletBinding()]
param(
    [ValidateRange(60, 120)]
    [int]$DurationSeconds = 90,
    [ValidateRange(1, 2)]
    [int]$WorkerCount = 1
)

$ErrorActionPreference = "Stop"
$deadline = (Get-Date).AddSeconds($DurationSeconds)
$jobs = @()

Write-Host "LAB FAULT INJECTION — NOT PRODUCTION TELEMETRY"
Write-Host "Applying bounded CPU pressure for $DurationSeconds seconds."

try {
    for ($index = 1; $index -le $WorkerCount; $index++) {
        $jobs += Start-Job -ArgumentList $deadline -ScriptBlock {
            param([datetime]$StopAt)
            $value = 0.5
            while ((Get-Date) -lt $StopAt) {
                $value = [Math]::Sqrt(([Math]::Sin($value) + 1.1) * 100000.0)
            }
        }
    }
    Wait-Job -Job $jobs -Timeout ($DurationSeconds + 15) | Out-Null
}
finally {
    foreach ($job in $jobs) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "LAB FAULT INJECTION completed; inspect genuine RDP telemetry before making any claim."
