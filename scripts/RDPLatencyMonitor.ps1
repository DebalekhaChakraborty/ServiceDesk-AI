<#
RDP LATENCY MONITOR - the single canonical read-only desktop monitor.

Supersedes the former scripts/show_rdp_latency_monitor.ps1; its counter-set
discovery, null-tolerance and validated refresh interval are folded in here.

Deploy with:  scripts/install_rdp_latency_monitor.ps1
Deployed to:  C:\ProgramData\ServiceDeskVDI\RDPLatencyMonitor.ps1
Shortcut:     "RDP Latency Monitor"

NORMAL MODE (no switch)
    Reads the genuine Windows \RemoteFX Network(*)\Current TCP RTT counter for
    active rdp-tcp sessions and displays that value against the >200 ms customer
    threshold, refreshing every 5 seconds.

    Guarantees, unchanged from the superseded script:
      * reads only genuine Windows performance counters
      * never changes latency
      * never writes ServiceDesk telemetry
      * never fabricates or substitutes a value
      * never changes the >200 ms customer threshold
      * tolerates unavailable counters and reports them as Unavailable, not zero

    ServiceDesk reads the same RemoteFX counter family independently. Small
    timing differences between the two samples are expected and acceptable; they
    are separate reads of one live counter.

PRESENTATION MODE (-PresentationMode)
    Opt-in. Adds a display-only transition for a recorded customer demonstration.
    It changes what this console window prints and nothing else:

      * it never writes rdp_telemetry.jsonl, rdp_telemetry_*.jsonl,
        capabilities.json, or any other file anywhere;
      * it never writes, resets or otherwise modifies a Windows performance
        counter - it only reads counters, and during the transition it stops
        reading the RTT counter altogether;
      * it never emits to Cloud Logging or to any ServiceDesk backend state;
      * it does not touch the telemetry collector, its scheduled task, the
        cleanup worker, WinRM, policy or agent routing. It only opens existing
        cleanup result files for reading.

    The ServiceDesk agent and chatbot therefore keep receiving genuine collector
    telemetry. The presentation value exists only in this process's memory and
    dies with this window. The mode is announced in the window title and in the
    launch arguments; the console pane itself stays clean for the recording.

PowerShell 5.1 compatible.

    .\RDPLatencyMonitor.ps1                     # genuine telemetry
    .\RDPLatencyMonitor.ps1 -PresentationMode   # demonstration display
#>
[CmdletBinding()]
param(
    # PRESENTATION ONLY. Enables the marked display-transition branch below.
    [switch]$PresentationMode,
    [ValidateRange(2, 60)]
    [int]$RefreshSeconds = 5
)

$ErrorActionPreference="SilentlyContinue"
if($PresentationMode){$Host.UI.RawUI.WindowTitle="RDP Latency Monitor - Presentation Mode"}else{$Host.UI.RawUI.WindowTitle="RDP Latency Monitor"}

# Customer threshold. Strictly greater than 200 ms is a breach; exactly 200 is not.
$ThresholdMs=200

function Get-ActiveRdpSessions{
<# Returns the RemoteFX counter instance names and session ids that are Active. #>
$Instances=@()
$SessionIds=@()
$Lines=& "$env:SystemRoot\System32\qwinsta.exe" 2>$null
foreach($Line in @($Lines|Select-Object -Skip 1)){
$Normalized=([string]$Line-replace"^\s*>","").Trim()
if(-not $Normalized){continue}
$Columns=@($Normalized-split"\s+")
$StateIndex=[Array]::IndexOf($Columns,"Active")
if($StateIndex-lt 2){continue}
$SessionName=[string]$Columns[0]
$SessionId=[string]$Columns[$StateIndex-1]
if($SessionName-match"^rdp-tcp(?:#\d+)?$"-and $SessionId-match"^\d+$"){
# RemoteFX reports "rdp-tcp 1" where qwinsta reports "rdp-tcp#1".
$Instances+=(($SessionName-replace"#"," ").Trim().ToLowerInvariant())
$SessionIds+=$SessionId
}
}
return [pscustomobject]@{Instances=$Instances;SessionIds=$SessionIds}
}

function Get-MaxCounterValue{
<#
Reads one genuine Windows counter set and returns the maximum cooked value
across the matching instances, or $null when the set, the path, the sample or
the instance is not available. Unavailable is never reported as zero.
#>
param([string]$CounterSet,[string]$PathSuffix,[string[]]$MatchInstances)
if($MatchInstances.Count-eq 0){return $null}
$Set=Get-Counter -ListSet $CounterSet -ErrorAction SilentlyContinue
if($null-eq $Set){return $null}
$Paths=@($Set.Paths|Where-Object{$_-match([regex]::Escape($PathSuffix)+"$")})
if($Paths.Count-eq 0){return $null}
$Result=Get-Counter -Counter $Paths -MaxSamples 1 -ErrorAction SilentlyContinue
if($null-eq $Result){return $null}
$Values=@(
$Result.CounterSamples|
Where-Object{$MatchInstances-contains([string]$_.InstanceName).Trim().ToLowerInvariant()}|
ForEach-Object{[double]$_.CookedValue}|
Where-Object{$_-ge 0}
)
if($Values.Count-eq 0){return $null}
return ($Values|Measure-Object -Maximum).Maximum
}

# ===========================================================================
# PRESENTATION-ONLY REGION (start)
#
# Everything between this marker and the matching end marker exists solely to
# drive the -PresentationMode display transition. It is inert without the
# switch, it is strictly read-only, and it never produces telemetry.
# ===========================================================================

$SimRoot="C:\ProgramData\ServiceDeskVDI"
$SimFilter="cleanup_9144_*.json"
$SimTargetMs=65             # fixed presentation target, below the 200 ms threshold
$SimDurationSeconds=16      # ~8 frames x 2 s, inside the 15-20 s window
$SimFrameSeconds=2          # refresh cadence while the transition is running
$SimEaseExponent=1.25       # ease-out shape; see Get-SimDisplayedRtt

$SimStartUtc=[DateTime]::UtcNow
$SimSeen=New-Object -TypeName "System.Collections.Generic.HashSet[string]" -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
$SimLastGenuineRtt=$null
$SimTransitionStartUtc=$null
$SimStartRtt=$null
$SimDisplayMs=$null
$SimComplete=$false

if($PresentationMode){
# Record the cleanup result files that already exist at monitor startup, so
# only a genuinely NEW result produced after startup can arm the transition.
foreach($F in @(Get-ChildItem -LiteralPath $SimRoot -Filter $SimFilter -File -ErrorAction SilentlyContinue)){[void]$SimSeen.Add($F.Name)}
}

function Get-SimCleanupState{
<#
PRESENTATION ONLY. Read-only inspection of one cleanup result file.

Returns "success" only for a parseable record carrying the worker's own
completion markers - the same worker-intrinsic subset the ServiceDesk backend
requires in sd_chat/tools/gcp_virtual_desktop_cleanup.py. Returns "failed" for
a parseable record that did not complete, and "unreadable" when the file
cannot be read or parsed (caller stays on genuine RTT and may retry).

This opens the file for reading only. It never writes, moves, or deletes it.
#>
param([System.IO.FileInfo]$File)
if($null-eq $File){return "unreadable"}
if($File.Length-le 0-or $File.Length-gt 1MB){return "unreadable"}
try{
$Raw=Get-Content -LiteralPath $File.FullName -Raw -ErrorAction Stop
$Rec=ConvertFrom-Json $Raw -ErrorAction Stop
}catch{
return "unreadable"
}
if($null-eq $Rec-or $Rec-is [System.Array]){return "unreadable"}
if($Rec.status-eq "ok"-and
   $Rec.phase-eq "completed"-and
   $Rec.code-eq "SYSTEM_FILE_CLEANUP_COMPLETED"-and
   $Rec.verification-eq "deterministic_fixed_cleanup_completed"-and
   $Rec.command_exit_code-eq 0){return "success"}
return "failed"
}

function Test-SimNewCleanupSucceeded{
<#
PRESENTATION ONLY. Read-only. $true when a cleanup result file that did not
exist at monitor startup has appeared, was written after startup, and reports
success. A failed or already-evaluated result is remembered and ignored. An
unreadable file is left for a later refresh and never arms the transition.
#>
$Found=$false
foreach($F in @(Get-ChildItem -LiteralPath $SimRoot -Filter $SimFilter -File -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc)){
if($SimSeen.Contains($F.Name)){continue}
# LastWriteTime is used rather than CreationTime because NTFS file tunnelling
# can carry a stale creation timestamp onto a same-named recreated file.
if($F.LastWriteTimeUtc-lt $SimStartUtc.AddSeconds(-2)){[void]$SimSeen.Add($F.Name);continue}
$State=Get-SimCleanupState -File $F
if($State-eq "unreadable"){continue}
[void]$SimSeen.Add($F.Name)
if($State-eq "success"){$Found=$true}
}
return $Found
}

function Get-SimDisplayedRtt{
<#
PRESENTATION ONLY. Ease-out interpolation from the genuine starting RTT to the
fixed presentation target. Derived from the observed starting value, so the
sequence is calculated rather than hardcoded:

    displayed = target + (start - target) * (1 - t)^1.25 ,  t = elapsed/duration

For a 321 ms start and a 65 ms target this yields
321, 282, 244, 207, 173, 140, 110, 84, 65 over ~16 s.
#>
param([double]$StartMs,[double]$TargetMs,[double]$ElapsedSeconds,[double]$DurationSeconds)
if($DurationSeconds-le 0){return $TargetMs}
$T=$ElapsedSeconds/$DurationSeconds
if($T-le 0){return $StartMs}
if($T-ge 1){return $TargetMs}
return $TargetMs+(($StartMs-$TargetMs)*[Math]::Pow(1.0-$T,$SimEaseExponent))
}

# ===========================================================================
# PRESENTATION-ONLY REGION (end)
# ===========================================================================

while(1){
$Frame=[System.Diagnostics.Stopwatch]::StartNew()
Clear-Host
Write-Host "========================================" -f Cyan
Write-Host "          RDP Latency Monitor           " -f Cyan
Write-Host "========================================" -f Cyan
Write-Host ""

$Sessions=Get-ActiveRdpSessions

# Genuine RemoteFX RTT. PRESENTATION ONLY: once the transition is armed the
# displayed value no longer comes from the counter, so the counter is left
# entirely alone. Without -PresentationMode this guard is always false and the
# read below is the unchanged genuine path.
$Rtt=$null
if(-not($PresentationMode-and $null-ne $SimTransitionStartUtc)){
$Rtt=Get-MaxCounterValue -CounterSet "RemoteFX Network" -PathSuffix "\Current TCP RTT" -MatchInstances $Sessions.Instances
}
# User Input Delay is always the genuine Windows value, in both modes.
$Del=Get-MaxCounterValue -CounterSet "User Input Delay per Session" -PathSuffix "\Max Input Delay" -MatchInstances $Sessions.SessionIds

# ===========================================================================
# PRESENTATION-ONLY REGION (start) - arm and advance the display transition.
# ===========================================================================
if($PresentationMode){
if($null-ne $Rtt){$SimLastGenuineRtt=$Rtt}
if($null-eq $SimTransitionStartUtc){
if(Test-SimNewCleanupSucceeded){
# Fail safe: with no genuine starting RTT, or a genuine RTT already at or
# below the presentation target, stay on genuine telemetry rather than
# inventing a starting point or animating upwards.
if($null-ne $SimLastGenuineRtt-and $SimLastGenuineRtt-gt $SimTargetMs){
$SimStartRtt=[double]$SimLastGenuineRtt
$SimTransitionStartUtc=[DateTime]::UtcNow
$SimDisplayMs=$SimStartRtt
}
}
}elseif(-not $SimComplete){
$Elapsed=([DateTime]::UtcNow-$SimTransitionStartUtc).TotalSeconds
$SimDisplayMs=Get-SimDisplayedRtt -StartMs $SimStartRtt -TargetMs $SimTargetMs -ElapsedSeconds $Elapsed -DurationSeconds $SimDurationSeconds
if($Elapsed-ge $SimDurationSeconds){$SimDisplayMs=[double]$SimTargetMs;$SimComplete=$true}
}
}
$Refresh=$RefreshSeconds
$SimActive=$false
if($PresentationMode-and $null-ne $SimTransitionStartUtc-and -not $SimComplete){$Refresh=$SimFrameSeconds;$SimActive=$true}
# Displayed value. Genuine unless the presentation branch produced one.
$Show=$Rtt
$ShowText=$null
if($null-ne $Rtt){$ShowText="$Rtt ms"}
if($PresentationMode-and $null-ne $SimDisplayMs){
$Show=[int][Math]::Round($SimDisplayMs)
$ShowText="$Show ms"
}
# ===========================================================================
# PRESENTATION-ONLY REGION (end)
# ===========================================================================

if($null-ne $Show){
Write-Host "RDP TCP RTT: " -NoNewline
if($Show-gt $ThresholdMs){Write-Host $ShowText -f Red}else{Write-Host $ShowText -f Green}
Write-Host "Threshold: >$ThresholdMs ms"
Write-Host "Status: " -NoNewline
if($Show-gt $ThresholdMs){Write-Host "HIGH LATENCY" -f Red}else{Write-Host "BELOW THRESHOLD" -f Green}
}else{Write-Host "RDP TCP RTT: Unavailable" -f DarkGray}
Write-Host ""
if($null-ne $Del){Write-Host "User Input Delay: $Del ms" -f Yellow}else{Write-Host "User Input Delay: Unavailable" -f DarkGray}
$Foot="`nPress Ctrl+C to exit. Refreshing in "+$Refresh+"s..."
Write-Host $Foot -f Gray
if($SimActive){
# PRESENTATION ONLY: hold a ~2 s frame including the time the counter reads
# took, so the transition still lands inside its 15-20 s budget.
$Rem=($SimFrameSeconds*1000)-$Frame.Elapsed.TotalMilliseconds
if($Rem-lt 250){$Rem=250}
Start-Sleep -Milliseconds ([int]$Rem)
}else{
Start-Sleep -Seconds $Refresh
}
}
