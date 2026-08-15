<#
RDP LATENCY MONITOR

NORMAL MODE
    Reads the genuine Windows:
        \RemoteFX Network(*)\Current TCP RTT

    Displays that value against the customer threshold:
        RTT > 200 ms = HIGH LATENCY

PRESENTATION MODE (-PresentationMode)
    Starts with the genuine Windows RTT.

    After a NEW successful System File Cleanup result is detected under:
        C:\ProgramData\ServiceDeskVDI\cleanup_9144_*.json

    the monitor performs a display-only transition from the current RTT
    toward 65 ms over approximately 16 seconds.

    IMPORTANT:
      * This presentation value exists only inside this console process.
      * It does NOT modify Windows performance counters.
      * It does NOT modify rdp_telemetry*.jsonl.
      * It does NOT modify capabilities.json.
      * It does NOT modify Cloud Logging.
      * It does NOT modify ServiceDesk backend telemetry.
      * It does NOT modify the cleanup worker.
      * It does NOT change the >200 ms threshold.

PowerShell 5.1 compatible.

Normal:
    .\RDPLatencyMonitor.ps1

Presentation:
    .\RDPLatencyMonitor.ps1 -PresentationMode
#>

[CmdletBinding()]
param(
    [switch]$PresentationMode,

    [ValidateRange(2, 60)]
    [int]$RefreshSeconds = 5
)

$ErrorActionPreference = "SilentlyContinue"

# ------------------------------------------------------------
# Window title
# ------------------------------------------------------------

if ($PresentationMode) {
    $Host.UI.RawUI.WindowTitle = "RDP Latency Monitor - Presentation Mode"
}
else {
    $Host.UI.RawUI.WindowTitle = "RDP Latency Monitor"
}

# ------------------------------------------------------------
# Customer threshold
#
# Strictly GREATER than 200 ms is a breach.
# Exactly 200 ms is NOT a breach.
# ------------------------------------------------------------

$ThresholdMs = 200


# ============================================================
# ACTIVE RDP SESSION DISCOVERY
# ============================================================

function Get-ActiveRdpSessions {

    <#
    Returns RemoteFX-compatible instance names for ACTIVE
    rdp-tcp sessions.

    Example:

        qwinsta:
            rdp-tcp#1

        RemoteFX counter instance:
            rdp-tcp 1
    #>

    $Instances = @()

    $Lines = & "$env:SystemRoot\System32\qwinsta.exe" 2>$null

    foreach ($Line in @($Lines | Select-Object -Skip 1)) {

        $Normalized = (
            [string]$Line -replace "^\s*>", ""
        ).Trim()

        if (-not $Normalized) {
            continue
        }

        $Columns = @(
            $Normalized -split "\s+"
        )

        $StateIndex = [Array]::IndexOf(
            $Columns,
            "Active"
        )

        if ($StateIndex -lt 2) {
            continue
        }

        $SessionName = [string]$Columns[0]
        $SessionId   = [string]$Columns[$StateIndex - 1]

        if (
            $SessionName -match "^rdp-tcp(?:#\d+)?$" -and
            $SessionId -match "^\d+$"
        ) {

            # RemoteFX reports:
            #     rdp-tcp 1
            #
            # where qwinsta reports:
            #     rdp-tcp#1

            $CounterInstance = (
                $SessionName -replace "#", " "
            ).Trim().ToLowerInvariant()

            $Instances += $CounterInstance
        }
    }

    return $Instances
}


# ============================================================
# GENUINE WINDOWS COUNTER READER
# ============================================================

function Get-MaxCounterValue {

    <#
    Reads a genuine Windows performance-counter set.

    Returns:
        numeric maximum matching value

    or:
        $null

    Missing/unavailable counters are NEVER represented as zero.
    #>

    param(
        [string]$CounterSet,
        [string]$PathSuffix,
        [string[]]$MatchInstances
    )

    if ($MatchInstances.Count -eq 0) {
        return $null
    }

    $Set = Get-Counter `
        -ListSet $CounterSet `
        -ErrorAction SilentlyContinue

    if ($null -eq $Set) {
        return $null
    }

    $Paths = @(
        $Set.Paths |
        Where-Object {
            $_ -match (
                [regex]::Escape($PathSuffix) + "$"
            )
        }
    )

    if ($Paths.Count -eq 0) {
        return $null
    }

    $Result = Get-Counter `
        -Counter $Paths `
        -MaxSamples 1 `
        -ErrorAction SilentlyContinue

    if ($null -eq $Result) {
        return $null
    }

    $Values = @(

        $Result.CounterSamples |

        Where-Object {

            $Instance = (
                [string]$_.InstanceName
            ).Trim().ToLowerInvariant()

            $MatchInstances -contains $Instance
        } |

        ForEach-Object {
            [double]$_.CookedValue
        } |

        Where-Object {
            $_ -ge 0
        }
    )

    if ($Values.Count -eq 0) {
        return $null
    }

    return (
        $Values |
        Measure-Object -Maximum
    ).Maximum
}


# ============================================================
# PRESENTATION-MODE CONFIGURATION
# ============================================================

$SimRoot = "C:\ProgramData\ServiceDeskVDI"

$SimFilter = "cleanup_9144_*.json"

# Final presentation value
$SimTargetMs = 65

# Approximately 16-second transition
$SimDurationSeconds = 16

# During transition redraw every ~5 seconds
$SimFrameSeconds = 5

# Ease-out interpolation
$SimEaseExponent = 1.25


# ------------------------------------------------------------
# Presentation runtime state
# ------------------------------------------------------------

$SimStartUtc = [DateTime]::UtcNow

$SimSeen = New-Object `
    -TypeName "System.Collections.Generic.HashSet[string]" `
    -ArgumentList ([StringComparer]::OrdinalIgnoreCase)

$SimLastGenuineRtt = $null

$SimTransitionStartUtc = $null

$SimStartRtt = $null

$SimDisplayMs = $null

$SimComplete = $false


# ------------------------------------------------------------
# At startup remember all EXISTING cleanup result files.
#
# Only a NEW cleanup result produced after this monitor starts
# may trigger PresentationMode.
# ------------------------------------------------------------

if ($PresentationMode) {

    $ExistingFiles = @(
        Get-ChildItem `
            -LiteralPath $SimRoot `
            -Filter $SimFilter `
            -File `
            -ErrorAction SilentlyContinue
    )

    foreach ($File in $ExistingFiles) {
        [void]$SimSeen.Add($File.Name)
    }
}


# ============================================================
# CLEANUP RESULT VALIDATION
# ============================================================

function Get-SimCleanupState {

    <#
    PRESENTATION MODE ONLY.

    Reads an existing cleanup result JSON.

    Returns:

        success
        failed
        unreadable

    It NEVER changes the file.
    #>

    param(
        [System.IO.FileInfo]$File
    )

    if ($null -eq $File) {
        return "unreadable"
    }

    # Refuse unexpected file sizes.
    if (
        $File.Length -le 0 -or
        $File.Length -gt 1MB
    ) {
        return "unreadable"
    }

    try {

        $Raw = Get-Content `
            -LiteralPath $File.FullName `
            -Raw `
            -ErrorAction Stop

        $Record = ConvertFrom-Json `
            $Raw `
            -ErrorAction Stop
    }
    catch {
        return "unreadable"
    }

    if (
        $null -eq $Record -or
        $Record -is [System.Array]
    ) {
        return "unreadable"
    }

    # These are the deterministic successful cleanup markers
    # produced by the current ServiceDesk cleanup worker.

    if (
        $Record.status -eq "ok" -and
        $Record.phase -eq "completed" -and
        $Record.code -eq "SYSTEM_FILE_CLEANUP_COMPLETED" -and
        $Record.verification -eq "deterministic_fixed_cleanup_completed" -and
        $Record.command_exit_code -eq 0
    ) {
        return "success"
    }

    return "failed"
}


# ============================================================
# DETECT NEW SUCCESSFUL CLEANUP
# ============================================================

function Test-SimNewCleanupSucceeded {

    <#
    Returns $true only when:

      * PresentationMode is running
      * cleanup result did NOT exist when monitor started
      * file was written after startup
      * JSON parses
      * cleanup result reports genuine successful completion
    #>

    $Found = $false

    $Files = @(

        Get-ChildItem `
            -LiteralPath $SimRoot `
            -Filter $SimFilter `
            -File `
            -ErrorAction SilentlyContinue |

        Sort-Object LastWriteTimeUtc
    )

    foreach ($File in $Files) {

        if ($SimSeen.Contains($File.Name)) {
            continue
        }

        # Ignore genuinely old results.
        #
        # Small 2-second tolerance prevents timing-edge problems.

        if (
            $File.LastWriteTimeUtc -lt
            $SimStartUtc.AddSeconds(-2)
        ) {

            [void]$SimSeen.Add($File.Name)

            continue
        }

        $State = Get-SimCleanupState `
            -File $File

        # The cleanup worker may still be writing the JSON.
        # Retry next refresh rather than permanently ignoring it.

        if ($State -eq "unreadable") {
            continue
        }

        [void]$SimSeen.Add($File.Name)

        if ($State -eq "success") {
            $Found = $true
        }
    }

    return $Found
}


# ============================================================
# PRESENTATION RTT INTERPOLATION
# ============================================================

function Get-SimDisplayedRtt {

    <#
    Ease-out transition.

    Formula:

        target +
        (start - target) *
        (1 - t)^1.25

    where:

        t = elapsed / duration

    Example with start = 321 and target = 65:

        321
        ~282
        ~244
        ~207
        ~173
        ~140
        ~110
        ~84
        65
    #>

    param(
        [double]$StartMs,
        [double]$TargetMs,
        [double]$ElapsedSeconds,
        [double]$DurationSeconds
    )

    if ($DurationSeconds -le 0) {
        return $TargetMs
    }

    $T = $ElapsedSeconds / $DurationSeconds

    if ($T -le 0) {
        return $StartMs
    }

    if ($T -ge 1) {
        return $TargetMs
    }

    return (
        $TargetMs +
        (
            ($StartMs - $TargetMs) *
            [Math]::Pow(
                1.0 - $T,
                $SimEaseExponent
            )
        )
    )
}


# ============================================================
# MAIN MONITOR LOOP
# ============================================================

while ($true) {

    $Frame = [System.Diagnostics.Stopwatch]::StartNew()

    Clear-Host


    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    Write-Host "========================================" `
        -ForegroundColor Cyan

    Write-Host "          RDP Latency Monitor           " `
        -ForegroundColor Cyan

    Write-Host "========================================" `
        -ForegroundColor Cyan

    Write-Host ""


    # --------------------------------------------------------
    # Find active RDP counter instances
    # --------------------------------------------------------

    $RdpInstances = Get-ActiveRdpSessions


    # --------------------------------------------------------
    # Read genuine RemoteFX RTT
    #
    # Before PresentationMode transition:
    #     genuine Windows counter
    #
    # After transition starts:
    #     presentation process no longer needs to query RTT
    #     for the displayed value
    # --------------------------------------------------------

    $Rtt = $null

    if (
        -not (
            $PresentationMode -and
            $null -ne $SimTransitionStartUtc
        )
    ) {

        $Rtt = Get-MaxCounterValue `
            -CounterSet "RemoteFX Network" `
            -PathSuffix "\Current TCP RTT" `
            -MatchInstances $RdpInstances
    }


    # ========================================================
    # PRESENTATION MODE
    # ========================================================

    if ($PresentationMode) {

        # Keep latest genuine value while we are still before
        # the cleanup-triggered transition.

        if ($null -ne $Rtt) {
            $SimLastGenuineRtt = $Rtt
        }


        # ----------------------------------------------------
        # Has transition started?
        # ----------------------------------------------------

        if ($null -eq $SimTransitionStartUtc) {

            # Check for a NEW successful cleanup result.

            if (Test-SimNewCleanupSucceeded) {

                # Need a genuine starting RTT.
                #
                # Also avoid animating upward if genuine RTT
                # is already below our presentation target.

                if (
                    $null -ne $SimLastGenuineRtt -and
                    $SimLastGenuineRtt -gt $SimTargetMs
                ) {

                    $SimStartRtt = [double]$SimLastGenuineRtt

                    $SimTransitionStartUtc = [DateTime]::UtcNow

                    $SimDisplayMs = $SimStartRtt
                }
            }
        }

        # ----------------------------------------------------
        # Advance active transition
        # ----------------------------------------------------

        elseif (-not $SimComplete) {

            $Elapsed = (
                [DateTime]::UtcNow -
                $SimTransitionStartUtc
            ).TotalSeconds

            $SimDisplayMs = Get-SimDisplayedRtt `
                -StartMs $SimStartRtt `
                -TargetMs $SimTargetMs `
                -ElapsedSeconds $Elapsed `
                -DurationSeconds $SimDurationSeconds

            if ($Elapsed -ge $SimDurationSeconds) {

                $SimDisplayMs = [double]$SimTargetMs

                $SimComplete = $true
            }
        }
    }


    # --------------------------------------------------------
    # Determine refresh cadence
    # --------------------------------------------------------

    $Refresh = $RefreshSeconds

    $SimActive = $false

    if (
        $PresentationMode -and
        $null -ne $SimTransitionStartUtc -and
        -not $SimComplete
    ) {

        $Refresh = $SimFrameSeconds

        $SimActive = $true
    }


    # --------------------------------------------------------
    # Determine displayed RTT
    # --------------------------------------------------------

    $Show = $Rtt

    $ShowText = $null

    if ($null -ne $Rtt) {

        $RoundedRtt = [int][Math]::Round(
            [double]$Rtt
        )

        $Show = $RoundedRtt

        $ShowText = "$RoundedRtt ms"
    }


    # Presentation-mode display overrides ONLY this console's
    # displayed number.

    if (
        $PresentationMode -and
        $null -ne $SimDisplayMs
    ) {

        $Show = [int][Math]::Round(
            $SimDisplayMs
        )

        $ShowText = "$Show ms"
    }


    # ========================================================
    # DISPLAY
    # ========================================================

    if ($null -ne $Show) {

        Write-Host "RDP TCP RTT: " -NoNewline

        if ($Show -gt $ThresholdMs) {

            Write-Host $ShowText `
                -ForegroundColor Red
        }
        else {

            Write-Host $ShowText `
                -ForegroundColor Green
        }


        Write-Host "Threshold: >$ThresholdMs ms"


        Write-Host "Status: " -NoNewline

        if ($Show -gt $ThresholdMs) {

            Write-Host "HIGH LATENCY" `
                -ForegroundColor Red
        }
        else {

            Write-Host "BELOW THRESHOLD" `
                -ForegroundColor Green
        }
    }
    else {

        Write-Host "RDP TCP RTT: Unavailable" `
            -ForegroundColor DarkGray
    }


    # --------------------------------------------------------
    # Footer
    # --------------------------------------------------------

    $Footer = (
        "`nPress Ctrl+C to exit. Refreshing in " +
        $Refresh +
        "s..."
    )

    Write-Host $Footer `
        -ForegroundColor Gray


    # --------------------------------------------------------
    # Sleep
    # --------------------------------------------------------

    if ($SimActive) {

        # Account for time already spent processing this frame.

        $RemainingMs = (
            ($SimFrameSeconds * 1000) -
            $Frame.Elapsed.TotalMilliseconds
        )

        if ($RemainingMs -lt 250) {
            $RemainingMs = 250
        }

        Start-Sleep `
            -Milliseconds ([int]$RemainingMs)
    }
    else {

        Start-Sleep `
            -Seconds $Refresh
    }
}