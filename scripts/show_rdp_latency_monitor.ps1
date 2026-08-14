<#
RDP LATENCY MONITOR — READ-ONLY OPERATOR/CUSTOMER DISPLAY.

Shows the genuine Windows RemoteFX TCP round-trip time for the active RDP
session so a customer can visually confirm the demonstrated latency change.

Deploy to:  C:\ProgramData\ServiceDeskVDI\Show-RdpLatency.ps1
Shortcut:   "RDP Latency Monitor"

Guarantees:
  * reads only genuine Windows performance counters
  * never changes latency
  * never writes ServiceDesk telemetry
  * never fabricates or substitutes a value
  * never changes the >200 ms customer threshold
  * tolerates unavailable counters and reports them as Unavailable, not zero

This displays the same RemoteFX counter family that ServiceDesk reads
independently. Small timing differences between the two samples are expected
and acceptable; they are separate reads of a live counter.
#>
[CmdletBinding()]
param(
    [ValidateRange(2, 60)]
    [int]$RefreshSeconds = 5
)

$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "RDP Latency Monitor"

# Customer threshold. Strictly greater than 200 ms is a breach; exactly 200 is not.
$ThresholdMs = 200

function Get-ActiveRdpSessions {
    <# Returns the RemoteFX counter instance names and session ids that are Active. #>
    $instances = @()
    $sessionIds = @()
    $lines = & "$env:SystemRoot\System32\qwinsta.exe" 2>$null
    foreach ($line in @($lines | Select-Object -Skip 1)) {
        $normalized = ([string]$line -replace "^\s*>", "").Trim()
        if (-not $normalized) { continue }
        $columns = @($normalized -split "\s+")
        $stateIndex = [Array]::IndexOf($columns, "Active")
        if ($stateIndex -lt 2) { continue }
        $sessionName = [string]$columns[0]
        $sessionId = [string]$columns[$stateIndex - 1]
        if ($sessionName -match "^rdp-tcp(?:#\d+)?$" -and $sessionId -match "^\d+$") {
            # RemoteFX reports "rdp-tcp 1" where qwinsta reports "rdp-tcp#1".
            $instances += (($sessionName -replace "#", " ").Trim().ToLowerInvariant())
            $sessionIds += $sessionId
        }
    }
    return [pscustomobject]@{ Instances = $instances; SessionIds = $sessionIds }
}

function Get-MaxCounterValue {
    param([string]$CounterSet, [string]$PathSuffix, [string[]]$MatchInstances)
    if ($MatchInstances.Count -eq 0) { return $null }
    $set = Get-Counter -ListSet $CounterSet -ErrorAction SilentlyContinue
    if ($null -eq $set) { return $null }
    $paths = @($set.Paths | Where-Object { $_ -match ([regex]::Escape($PathSuffix) + "$") })
    if ($paths.Count -eq 0) { return $null }
    $result = Get-Counter -Counter $paths -MaxSamples 1 -ErrorAction SilentlyContinue
    if ($null -eq $result) { return $null }
    $values = @(
        $result.CounterSamples |
            Where-Object { $MatchInstances -contains ([string]$_.InstanceName).Trim().ToLowerInvariant() } |
            ForEach-Object { [double]$_.CookedValue } |
            Where-Object { $_ -ge 0 }
    )
    if ($values.Count -eq 0) { return $null }
    return ($values | Measure-Object -Maximum).Maximum
}

while ($true) {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "          RDP Latency Monitor           " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $sessions = Get-ActiveRdpSessions
    $rtt = Get-MaxCounterValue -CounterSet "RemoteFX Network" `
                               -PathSuffix "\Current TCP RTT" `
                               -MatchInstances $sessions.Instances
    $inputDelay = Get-MaxCounterValue -CounterSet "User Input Delay per Session" `
                                      -PathSuffix "\Max Input Delay" `
                                      -MatchInstances $sessions.SessionIds

    if ($null -ne $rtt) {
        Write-Host "RDP TCP RTT: " -NoNewline
        if ($rtt -gt $ThresholdMs) {
            Write-Host ("{0} ms" -f $rtt) -ForegroundColor Red
        } else {
            Write-Host ("{0} ms" -f $rtt) -ForegroundColor Green
        }
        Write-Host ("Threshold: >{0} ms" -f $ThresholdMs)
        Write-Host "Status: " -NoNewline
        if ($rtt -gt $ThresholdMs) {
            Write-Host "HIGH LATENCY" -ForegroundColor Red
        } else {
            Write-Host "NORMAL" -ForegroundColor Green
        }
    } else {
        Write-Host "RDP TCP RTT: Unavailable" -ForegroundColor DarkGray
        Write-Host ("Threshold: >{0} ms" -f $ThresholdMs)
        Write-Host "Status: Unavailable" -ForegroundColor DarkGray
    }

    Write-Host ""
    if ($null -ne $inputDelay) {
        Write-Host ("User Input Delay: {0} ms" -f $inputDelay) -ForegroundColor Yellow
    } else {
        Write-Host "User Input Delay: Unavailable" -ForegroundColor DarkGray
    }
    Write-Host "(User Input Delay is a separate supporting metric, not RTT.)" -ForegroundColor DarkGray

    Write-Host ""
    Write-Host ("Press Ctrl+C to exit. Refreshing in {0}s..." -f $RefreshSeconds) -ForegroundColor Gray
    Start-Sleep -Seconds $RefreshSeconds
}
