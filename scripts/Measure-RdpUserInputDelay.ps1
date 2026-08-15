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
$RttCounterAvailable = $false
$RttCounterPaths = @()
try {
    $Capabilities = Get-Content -Path $CapabilityPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $CounterAvailable = $Capabilities.user_input_delay_counter_set_available -eq $true
    $CounterPaths = @($Capabilities.user_input_delay_counter_paths | Where-Object { $_ })
    $RttCounterAvailable = $Capabilities.rdp_tcp_rtt_counter_set_available -eq $true
    $RttCounterPaths = @($Capabilities.rdp_tcp_rtt_counter_paths | Where-Object { $_ })
}
catch {
    $CounterAvailable = $false
    $CounterPaths = @()
    $RttCounterAvailable = $false
    $RttCounterPaths = @()
}

$SessionLines = & "$env:SystemRoot\System32\qwinsta.exe" 2>$null
$ActiveRdpSessionIds = @()
$ActiveRdpCounterInstances = @()
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
        $ActiveRdpCounterInstances += (($SessionName -replace "#", " ").Trim().ToLowerInvariant())
    }
}

$ProbeRecord = [ordered]@{
    session_count = $ActiveRdpSessionIds.Count
    user_input_delay_value = $null
    tcp_rtt_value = $null
}
$ProbeRecord | ConvertTo-Json -Compress | Set-Content -Path $ResultPath -Encoding UTF8

if ($ActiveRdpSessionIds.Count -eq 0) {
    exit 0
}

if ($CounterAvailable -and $CounterPaths.Count -gt 0) {
    $CounterResult = Get-Counter -Counter $CounterPaths -MaxSamples 1 -ErrorAction Stop
    $MaximumDelay = @(
        $CounterResult.CounterSamples |
            Where-Object { $ActiveRdpSessionIds -contains [string]$_.InstanceName } |
            ForEach-Object { [double]$_.CookedValue } |
            Where-Object { $_ -ge 0 }
    ) | Measure-Object -Maximum
    if ($null -ne $MaximumDelay.Maximum) {
        $ProbeRecord.user_input_delay_value = [double]$MaximumDelay.Maximum
    }
}

if ($RttCounterAvailable -and $RttCounterPaths.Count -gt 0) {
    $RttResult = Get-Counter -Counter $RttCounterPaths -MaxSamples 1 -ErrorAction Stop
    $MaximumRtt = @(
        $RttResult.CounterSamples |
            Where-Object {
                $ActiveRdpCounterInstances -contains ([string]$_.InstanceName).Trim().ToLowerInvariant()
            } |
            ForEach-Object { [double]$_.CookedValue } |
            Where-Object { $_ -ge 0 }
    ) | Measure-Object -Maximum
    if ($null -ne $MaximumRtt.Maximum) {
        $ProbeRecord.tcp_rtt_value = [double]$MaximumRtt.Maximum
    }
}
$ProbeRecord | ConvertTo-Json -Compress | Set-Content -Path $ResultPath -Encoding UTF8
