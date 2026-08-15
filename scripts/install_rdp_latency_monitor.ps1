<#
OPERATOR DEPLOYMENT HELPER for the canonical RDP Latency Monitor.

Run this from the operator's existing secure guest session on the PoC Windows
lab VM. It does exactly two things:

  1. copies scripts\RDPLatencyMonitor.ps1 to
     C:\ProgramData\ServiceDeskVDI\RDPLatencyMonitor.ps1
  2. creates a desktop shortcut named "RDP Latency Monitor" that launches
     powershell.exe against that copy

It is idempotent: re-running it refreshes both.

DELIBERATE LIMITS
  * No executable is built. There is no compiler, no Add-Type, no ps2exe, no
    .exe output of any kind. The shortcut runs the .ps1 through powershell.exe.
  * No credential, password, token, username, project, zone, instance name or
    IP is read, prompted for, embedded in the shortcut, or written anywhere.
  * It does not touch the ServiceDeskVDI telemetry collector, capabilities.json,
    rdp_telemetry*.jsonl, the recurring scheduled task, the cleanup worker,
    Ops Agent configuration, WinRM, domain membership, SCCM/ConfigMgr, DNS, the
    Windows firewall, or any endpoint-management policy. The only paths it
    writes are the one monitor script and the one .lnk.

    .\install_rdp_latency_monitor.ps1                 # presentation-mode shortcut
    .\install_rdp_latency_monitor.ps1 -GenuineOnly    # plain genuine-telemetry shortcut
    .\install_rdp_latency_monitor.ps1 -AllUsers       # shortcut on the Public desktop
#>
[CmdletBinding()]
param(
    # Omit -PresentationMode from the shortcut arguments.
    [switch]$GenuineOnly,
    # Place the shortcut on the Public desktop instead of the current user's.
    [switch]$AllUsers,
    # Explicit desktop folder; overrides -AllUsers.
    [string]$DesktopPath
)

$ErrorActionPreference = "Stop"

$ServiceDeskRoot = "C:\ProgramData\ServiceDeskVDI"
$MonitorName     = "RDPLatencyMonitor.ps1"
$ShortcutName    = "RDP Latency Monitor.lnk"
$Source          = Join-Path $PSScriptRoot $MonitorName
$Destination     = Join-Path $ServiceDeskRoot $MonitorName
$PowerShellExe   = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
    throw "Cannot find $MonitorName next to this installer at '$Source'. Copy the reviewed script alongside it and re-run."
}
if (-not (Test-Path -LiteralPath $PowerShellExe -PathType Leaf)) {
    throw "Windows PowerShell was not found at '$PowerShellExe'."
}

# Refuse to deploy a script that does not parse, rather than leaving a broken
# shortcut on the demo desktop.
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $Source, [ref]$null, [ref]$parseErrors)
if ($parseErrors -and $parseErrors.Count -gt 0) {
    throw "$MonitorName has $($parseErrors.Count) parser error(s); nothing was deployed."
}

if (-not (Test-Path -LiteralPath $ServiceDeskRoot -PathType Container)) {
    New-Item -Path $ServiceDeskRoot -ItemType Directory -Force | Out-Null
}
Copy-Item -LiteralPath $Source -Destination $Destination -Force
Write-Host "Deployed monitor : $Destination"

if (-not $DesktopPath) {
    if ($AllUsers) {
        $DesktopPath = Join-Path $env:PUBLIC "Desktop"
    } else {
        $DesktopPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::Desktop)
    }
}
if (-not (Test-Path -LiteralPath $DesktopPath -PathType Container)) {
    throw "Desktop folder '$DesktopPath' does not exist. Pass -DesktopPath explicitly."
}

# Shortcut arguments. -File keeps the monitor a plain script; nothing sensitive
# is passed, and the mode is visible in the shortcut itself.
$arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $Destination
if (-not $GenuineOnly) { $arguments += " -PresentationMode" }

$ShortcutPath = Join-Path $DesktopPath $ShortcutName
$shell = New-Object -ComObject WScript.Shell
try {
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath       = $PowerShellExe
    $shortcut.Arguments        = $arguments
    $shortcut.WorkingDirectory = $ServiceDeskRoot
    $shortcut.IconLocation     = "$PowerShellExe,0"
    $shortcut.Description      = "Read-only RDP TCP RTT monitor for the ServiceDesk virtual desktop PoC."
    $shortcut.WindowStyle      = 1
    $shortcut.Save()
} finally {
    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
}

Write-Host "Created shortcut : $ShortcutPath"
Write-Host "  Target         : $PowerShellExe"
Write-Host "  Arguments      : $arguments"
if ($GenuineOnly) {
    Write-Host "  Mode           : genuine telemetry only"
} else {
    Write-Host "  Mode           : PRESENTATION MODE (display-only transition after a successful cleanup)"
}
Write-Host "No executable was built and no credential was written."
