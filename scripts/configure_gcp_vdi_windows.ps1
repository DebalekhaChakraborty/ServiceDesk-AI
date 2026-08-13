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
$CleanupPath = Join-Path $ServiceDeskRoot "run_cleanup_9144.ps1"
$CleanupWorkerSourcePath = Join-Path $ServiceDeskRoot "ServiceDeskFixedCleanup.cs"
$CleanupWorkerPath = Join-Path $ServiceDeskRoot "ServiceDeskFixedCleanup.exe"
$CollectorAuditPath = Join-Path $ServiceDeskRoot "rdp_collector_audit.jsonl"
$CapabilityPath = Join-Path $ServiceDeskRoot "capabilities.json"
$SetupStatusPath = Join-Path $ServiceDeskRoot "setup_status.json"
$OpsAgentConfigPath = "C:\Program Files\Google\Cloud Operations\Ops Agent\config\config.yaml"
$OpsAgentBackupPath = "C:\Program Files\Google\Cloud Operations\Ops Agent\config\config.pre-servicedesk.bak"
$OpsAgentManagedSnapshotPath = Join-Path $ServiceDeskRoot "ops_agent_servicedesk_config.yaml"
$OpsAgentOwnershipMarker = "# managed-by: ServiceDeskVDI"
$TaskName = "ServiceDeskVDI-RdpTelemetry"

New-Item -Path $ServiceDeskRoot -ItemType Directory -Force | Out-Null

# This fixed guest-side script is the PoC-only analogue of KB0019144's native
# Disk Cleanup workflow. It is not a production cleanup policy and it accepts no
# user-supplied categories, paths, or commands. The ServiceDesk backend invokes
# it only through its retained GCP offer controller and the existing private
# ServiceDesk WinRM HTTPS transport.
$LegacyCleanupScript = @'
param(
    [Parameter(Mandatory = $true)]
    [string]$InvocationId,
    [switch]$Controller,
    [string]$ExpectedUser
)

$ErrorActionPreference = "Stop"
$ProfileName = "KB screenshot-visible PoC cleanup profile"
$ProfileId = 9144
$WorkerTimeoutMilliseconds = 180000
$ServiceDeskRoot = "C:\ProgramData\ServiceDeskVDI"
$VolumeCachesRoot = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
$StateFlagName = "StateFlags9144"
$AllowedCategories = @(
    "Downloaded Program Files",
    "Temporary Internet Files"
)

if ($InvocationId -notmatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$") {
    throw "Invalid controller invocation identifier."
}
$ResultPath = Join-Path $ServiceDeskRoot ("cleanup_9144_{0}.json" -f $InvocationId)
$TaskName = "SystemFileCleanup9144-$InvocationId"

if ($Controller) {
    function Write-ControllerResult {
        param([string]$Status, [string]$Code, [string]$Message, $Data)
        $record = [ordered]@{status=$Status; code=$Code; message=$Message}
        if ($null -ne $Data) {
            foreach ($property in $Data.PSObject.Properties) {
                $record[$property.Name] = $property.Value
            }
        }
        $record | ConvertTo-Json -Compress -Depth 5 | Write-Output
    }
    try {
        if ($ExpectedUser -notmatch "^[A-Za-z0-9_.-]{1,20}$") {
            Write-ControllerResult "error" "GCP_VDI_CLEANUP_MAPPING_INVALID" "The mapped Windows user is invalid." $null
            exit 0
        }
        $native = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class ServiceDeskInteractiveSession {
  enum WTS_CONNECTSTATE_CLASS { Active, Connected, ConnectQuery, Shadow, Disconnected, Idle, Listen, Reset, Down, Init }
  [StructLayout(LayoutKind.Sequential)] struct WTS_SESSION_INFO { public Int32 SessionID; public IntPtr pWinStationName; public WTS_CONNECTSTATE_CLASS State; }
  [DllImport("wtsapi32.dll")] static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
  [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode)] static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
  [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr memory);
  [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll")] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll")] static extern bool GetTokenInformation(IntPtr token, int tokenClass, out int value, int length, out int returned);
  static string Query(int sessionId, int infoClass) {
    IntPtr buffer; int bytes;
    if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out buffer, out bytes) || buffer == IntPtr.Zero) return "";
    try { return Marshal.PtrToStringUni(buffer) ?? ""; } finally { WTSFreeMemory(buffer); }
  }
  public static string[] ActiveSessions() {
    IntPtr buffer; int count;
    if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out buffer, out count)) throw new InvalidOperationException("WTSEnumerateSessions failed");
    var result = new List<string>(); int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
    try {
      for (int i=0; i<count; i++) {
        var item = (WTS_SESSION_INFO)Marshal.PtrToStructure(IntPtr.Add(buffer, i*size), typeof(WTS_SESSION_INFO));
        if (item.State == WTS_CONNECTSTATE_CLASS.Active && item.SessionID > 0) result.Add(item.SessionID + "|" + Query(item.SessionID, 7) + "|" + Query(item.SessionID, 5));
      }
    } finally { WTSFreeMemory(buffer); }
    return result.ToArray();
  }
  public static int ElevationType(int processId) {
    IntPtr process = OpenProcess(0x1000, false, processId); if (process == IntPtr.Zero) return 0;
    IntPtr token = IntPtr.Zero;
    try {
      if (!OpenProcessToken(process, 0x0008, out token)) return 0;
      int value, returned; return GetTokenInformation(token, 18, out value, 4, out returned) ? value : 0;
    } finally { if (token != IntPtr.Zero) CloseHandle(token); CloseHandle(process); }
  }
}
"@
        Add-Type -TypeDefinition $native -Language CSharp
        $matches = @()
        foreach ($row in [ServiceDeskInteractiveSession]::ActiveSessions()) {
            $parts = @($row -split '\|', 3)
            if ($parts.Count -eq 3 -and $parts[2] -ieq $ExpectedUser) {
                $matches += [pscustomobject]@{session_id=[int]$parts[0]; domain=$parts[1]; username=$parts[2]}
            }
        }
        if ($matches.Count -eq 0) {
            Write-ControllerResult "error" "ACTIVE_RDP_SESSION_REQUIRED" "No active Remote Desktop session exists for the mapped user." $null
            exit 0
        }
        if ($matches.Count -ne 1) {
            Write-ControllerResult "error" "ACTIVE_RDP_SESSION_REQUIRED" "The active mapped user session could not be selected uniquely." $null
            exit 0
        }
        $session = $matches[0]
        $explorers = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object { $_.SessionId -eq $session.session_id })
        $ownedExplorer = @($explorers | Where-Object {
            $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
            $null -ne $owner -and $owner.ReturnValue -eq 0 -and $owner.User -ieq $ExpectedUser
        })
        if ($ownedExplorer.Count -ne 1) {
            Write-ControllerResult "error" "ACTIVE_RDP_SESSION_REQUIRED" "The mapped user's active interactive shell could not be uniquely verified." $null
            exit 0
        }
        $elevationType = [ServiceDeskInteractiveSession]::ElevationType([int]$ownedExplorer[0].ProcessId)
        if ($elevationType -ne 2 -and $elevationType -ne 3) {
            Write-ControllerResult "error" "GCP_VDI_CLEANUP_ACTIVE_USER_PRIVILEGE_REQUIRED" "The active mapped user cannot run System File Cleanup with sufficient privilege." $null
            exit 0
        }
        $principal = if ($session.domain) { "$($session.domain)\$($session.username)" } else { $session.username }
        $scheduler = New-Object -ComObject "Schedule.Service"
        $scheduler.Connect()
        $TaskFolder = "\ServiceDeskVDI"
        try { $folder = $scheduler.GetFolder($TaskFolder) } catch {
            $root = $scheduler.GetFolder("\")
            try { $folder = $root.CreateFolder("ServiceDeskVDI", $null) } catch { $folder = $scheduler.GetFolder($TaskFolder) }
        }
        $definition = $scheduler.NewTask(0)
        $definition.RegistrationInfo.Description = "Fixed ServiceDesk System File Cleanup 9144"
        $definition.Principal.UserId = $principal
        $definition.Principal.LogonType = 3
        $definition.Principal.RunLevel = 1
        $definition.Settings.Enabled = $true
        $definition.Settings.AllowDemandStart = $true
        $definition.Settings.DisallowStartIfOnBatteries = $false
        $definition.Settings.StopIfGoingOnBatteries = $false
        $definition.Settings.ExecutionTimeLimit = "PT4M"
        $action = $definition.Actions.Create(0)
        $action.Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $action.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\ProgramData\ServiceDeskVDI\run_cleanup_9144.ps1" -InvocationId "' + $InvocationId + '"'
        try {
            $registered = $folder.RegisterTaskDefinition($TaskName, $definition, 6, $principal, $null, 3, $null)
        } catch {
            Write-ControllerResult "error" "CLEANUP_TASK_START_FAILED" "The approved interactive cleanup task could not be registered." $null
            exit 0
        }
        try {
            $running = $registered.RunEx($null, 4, [int]$session.session_id, $null)
        } catch {
            try { $folder.DeleteTask($TaskName, 0) } catch {}
            Write-ControllerResult "error" "CLEANUP_TASK_START_FAILED" "System File Cleanup could not start in the active mapped user session." $null
            exit 0
        }
        Write-ControllerResult "ok" "GCP_VDI_CLEANUP_TASK_STARTED" "System File Cleanup started." ([pscustomobject]@{
            invocation_id=$InvocationId
            task_name=$TaskName
            task_path=($TaskFolder + "\" + $TaskName)
            session_id=[int]$session.session_id
            principal=$principal
            privilege_available=$true
            highest_available=$true
            logon_type=3
            run_level=1
            run_flags=4
            task_instance_guid=[string]$running.InstanceGuid
            elevation_type=$elevationType
        })
    } catch {
        Write-ControllerResult "error" "GCP_VDI_CLEANUP_CONTROLLER_FAILED" "The interactive cleanup controller failed safely before completion." $null
    }
    exit 0
}

function Get-FreeDiskBytes {
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
    return [int64]$drive.FreeSpace
}

function Write-CleanupStatus {
    param([System.Collections.IDictionary]$Result)
    $temporary = "$ResultPath.tmp.$PID"
    $Result | ConvertTo-Json -Compress -Depth 6 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $ResultPath -Force
}

function Get-DescendantProcessIds {
    param([int]$RootProcessId)
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $pending = New-Object System.Collections.Generic.Queue[int]
    $pending.Enqueue($RootProcessId)
    $found = @()
    while ($pending.Count -gt 0) {
        $parent = $pending.Dequeue()
        foreach ($child in @($all | Where-Object { $_.ParentProcessId -eq $parent })) {
            $childId = [int]$child.ProcessId
            if ($found -notcontains $childId) {
                $found += $childId
                $pending.Enqueue($childId)
            }
        }
    }
    return $found
}

function Stop-CleanupProcessTree {
    param([int]$RootProcessId)
    $descendants = @(Get-DescendantProcessIds -RootProcessId $RootProcessId)
    for ($index = $descendants.Count - 1; $index -ge 0; $index--) {
        Stop-Process -Id ([int]$descendants[$index]) -Force -ErrorAction SilentlyContinue
    }
    Stop-Process -Id $RootProcessId -Force -ErrorAction SilentlyContinue
}

function Invoke-CompletedCleanmgrUiNudge {
    param([System.Diagnostics.Process]$Process)
    try {
        $Process.Refresh()
        $windowHandle = $Process.MainWindowHandle
        if ($windowHandle -eq [IntPtr]::Zero) {
            return $false
        }
        $root = [System.Windows.Automation.AutomationElement]::FromHandle($windowHandle)
        if ($null -eq $root) {
            return $false
        }
        $condition = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::ProgressBar
        )
        $bars = $root.FindAll(
            [System.Windows.Automation.TreeScope]::Descendants,
            $condition
        )
        foreach ($bar in $bars) {
            $pattern = $null
            if ($bar.TryGetCurrentPattern(
                [System.Windows.Automation.RangeValuePattern]::Pattern,
                [ref]$pattern
            )) {
                $current = $pattern.Current
                if ($current.Maximum -gt $current.Minimum -and $current.Value -ge $current.Maximum) {
                    [ServiceDeskWindowMessage]::PostMouseMove($windowHandle) | Out-Null
                    $childHandle = [IntPtr]$bar.Current.NativeWindowHandle
                    if ($childHandle -ne [IntPtr]::Zero) {
                        [ServiceDeskWindowMessage]::PostMouseMove($childHandle) | Out-Null
                    }
                    return $true
                }
            }
        }
    }
    catch {
        return $false
    }
    return $false
}

function Invoke-CleanmgrThreadNudge {
    param([System.Diagnostics.Process]$Process)
    try {
        $posted = $false
        $Process.Refresh()
        foreach ($thread in @($Process.Threads)) {
            if ([ServiceDeskWindowMessage]::PostThreadMouseMove([uint32]$thread.Id)) {
                $posted = $true
            }
        }
        [ServiceDeskWindowMessage]::PulseMouseWithoutMovement()
        return $true
    }
    catch {
        return $false
    }
}

$startedAt = (Get-Date).ToUniversalTime().ToString("o")
$before = $null
$after = $null
$selected = @()
$previousFlags = @()
$cleanupProcess = $null
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$uiCompletionNudge = $false
$uiAutomationAvailable = $false
$windowMessageAvailable = $false
$cleanupChildObserved = $false
$cleanupChildIds = @()
$idleWindowStartedAt = $null
$idleWindowCpuSeconds = $null
$result = [ordered]@{
    status = "running"
    phase = "started"
    code = "SYSTEM_FILE_CLEANUP_STARTING"
    message = "System File Cleanup is starting."
    invocation_id = $InvocationId
    task_name = $TaskName
    profile = $ProfileName
    profile_id = $ProfileId
    interactive_session_id = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    run_as = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    worker_pid = $PID
    cleanup_pid = $null
    cleanup_started_at = $null
    completion_ui_nudge = $false
    completion_idle_cpu_rate = $null
    window_message_available = $false
    ui_automation_available = $false
    cleanup_child_observed = $false
    cleanup_child_pids = @()
    selected_categories = @()
    command_exit_code = $null
    free_disk_bytes_before = $null
    free_disk_bytes_after = $null
    bytes_reclaimed = $null
    elapsed_seconds = $null
    started_at = $startedAt
    completed_at = $null
    flags_restored = $false
    verification = "not_completed"
}
Write-CleanupStatus $result

try {
    if ([int]$result.interactive_session_id -le 0) {
        $result.code = "GCP_VDI_CLEANUP_INTERACTIVE_SESSION_REQUIRED"
        $result.message = "System File Cleanup was not started in an interactive user session."
        throw "interactive_session_required"
    }
    $cleanmgr = Join-Path $env:SystemRoot "System32\cleanmgr.exe"
    if (-not (Test-Path -LiteralPath $cleanmgr -PathType Leaf)) {
        $result.code = "GCP_VDI_CLEANUP_NATIVE_TOOL_UNAVAILABLE"
        $result.message = "Windows Disk Cleanup is not available on the shared workstation."
        $result.verification = "native_disk_cleanup_unavailable"
        throw "native_disk_cleanup_unavailable"
    }
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class ServiceDeskWindowMessage {
  [DllImport("user32.dll", SetLastError=true)] static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll", SetLastError=true)] static extern bool PostThreadMessage(uint threadId, uint message, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll")] static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);
  public static bool PostMouseMove(IntPtr window) { return PostMessage(window, 0x0200, IntPtr.Zero, new IntPtr(0x00010001)); }
  public static bool PostThreadMouseMove(uint threadId) { return PostThreadMessage(threadId, 0x0200, IntPtr.Zero, new IntPtr(0x00010001)); }
  public static void PulseMouseWithoutMovement() { mouse_event(0x0001, 0, 0, 0, UIntPtr.Zero); }
}
"@ -Language CSharp -ErrorAction Stop
        $windowMessageAvailable = $true
        $result.window_message_available = $true
    }
    catch {
        $windowMessageAvailable = $false
    }
    try {
        Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes -ErrorAction Stop
        $uiAutomationAvailable = $true
        $result.ui_automation_available = $true
    }
    catch {
        $uiAutomationAvailable = $false
    }
    $before = Get-FreeDiskBytes
    # Profile 9144 is ServiceDesk-owned. Snapshot and clear only this profile's
    # flag from every installed handler before selecting the fixed allowlist.
    foreach ($handler in @(Get-ChildItem -LiteralPath $VolumeCachesRoot -ErrorAction Stop)) {
        $path = $handler.PSPath
        $existing = Get-ItemProperty -LiteralPath $path -Name $StateFlagName -ErrorAction SilentlyContinue
        $previousFlags += [pscustomobject]@{
            path = $path
            exists = $null -ne $existing
            value = if ($null -ne $existing) { $existing.$StateFlagName } else { $null }
        }
        Remove-ItemProperty -LiteralPath $path -Name $StateFlagName -ErrorAction SilentlyContinue
        if ($AllowedCategories -contains $handler.PSChildName) {
            New-ItemProperty -LiteralPath $path -Name $StateFlagName -PropertyType DWord -Value 2 -Force | Out-Null
            $selected += $handler.PSChildName
        }
    }
    if ($selected.Count -eq 0) {
        $result.code = "GCP_VDI_CLEANUP_NO_APPROVED_CATEGORY_AVAILABLE"
        $result.message = "No approved Windows Disk Cleanup category is available on the shared workstation."
        $result.verification = "no_approved_native_categories_available"
        throw "no_approved_native_categories_available"
    }
    $result.selected_categories = @($selected)
    $result.free_disk_bytes_before = $before
    $cleanupProcess = Start-Process -FilePath $cleanmgr -ArgumentList "/sagerun:9144" -PassThru
    $result.cleanup_pid = [int]$cleanupProcess.Id
    $result.cleanup_started_at = (Get-Date).ToUniversalTime().ToString("o")
    $result.phase = "running"
    $result.code = "SYSTEM_FILE_CLEANUP_RUNNING"
    $result.message = "System File Cleanup is running."
    Write-CleanupStatus $result
    $cleanupProcess.Refresh()
    $idleWindowStartedAt = (Get-Date).ToUniversalTime()
    $idleWindowCpuSeconds = $cleanupProcess.TotalProcessorTime.TotalSeconds
    $cleanupDeadline = (Get-Date).ToUniversalTime().AddMilliseconds($WorkerTimeoutMilliseconds)
    while (-not $cleanupProcess.HasExited -and (Get-Date).ToUniversalTime() -lt $cleanupDeadline) {
        $currentChildIds = @(Get-DescendantProcessIds -RootProcessId ([int]$cleanupProcess.Id))
        if ($currentChildIds.Count -gt 0) {
            $cleanupChildObserved = $true
            foreach ($childId in $currentChildIds) {
                if ($cleanupChildIds -notcontains [int]$childId) {
                    $cleanupChildIds += [int]$childId
                }
            }
            $result.cleanup_child_observed = $true
            $result.cleanup_child_pids = @($cleanupChildIds)
        }
        $cleanupProcess.Refresh()
        $currentCpuSeconds = $cleanupProcess.TotalProcessorTime.TotalSeconds
        $now = (Get-Date).ToUniversalTime()
        if ($currentChildIds.Count -gt 0) {
            $idleWindowStartedAt = $now
            $idleWindowCpuSeconds = $currentCpuSeconds
        }
        if ($uiAutomationAvailable -and -not $uiCompletionNudge) {
            $uiCompletionNudge = Invoke-CompletedCleanmgrUiNudge -Process $cleanupProcess
            if ($uiCompletionNudge) {
                $result.completion_ui_nudge = $true
                Write-CleanupStatus $result
            }
        }
        $childCompleted = $cleanupChildObserved -and $currentChildIds.Count -eq 0
        $idleCompletionCandidate = $false
        $idleWindowSeconds = ($now - $idleWindowStartedAt).TotalSeconds
        if ($currentChildIds.Count -eq 0 -and $stopwatch.Elapsed.TotalSeconds -ge 15 -and $idleWindowSeconds -ge 5) {
            $cpuRate = ($currentCpuSeconds - $idleWindowCpuSeconds) / $idleWindowSeconds
            $result.completion_idle_cpu_rate = [math]::Round($cpuRate, 4)
            $idleCompletionCandidate = $cpuRate -le 0.05
            $idleWindowStartedAt = $now
            $idleWindowCpuSeconds = $currentCpuSeconds
        }
        if ($windowMessageAvailable -and -not $uiCompletionNudge -and ($childCompleted -or $idleCompletionCandidate)) {
            $uiCompletionNudge = Invoke-CleanmgrThreadNudge -Process $cleanupProcess
            if ($uiCompletionNudge) {
                $result.completion_ui_nudge = $true
                Write-CleanupStatus $result
            }
        }
        if (-not $cleanupProcess.HasExited) {
            Start-Sleep -Milliseconds 500
            $cleanupProcess.Refresh()
        }
    }
    if (-not $cleanupProcess.HasExited) {
        Stop-CleanupProcessTree -RootProcessId ([int]$cleanupProcess.Id)
        $result.status = "error"
        $result.phase = "timed_out"
        $result.code = "SYSTEM_FILE_CLEANUP_TIMED_OUT"
        $result.message = "System File Cleanup exceeded its safe execution time and was stopped."
        $result.verification = "native_disk_cleanup_timeout"
        throw "native_disk_cleanup_timeout"
    }
    $result.command_exit_code = [int]$cleanupProcess.ExitCode
    if ($cleanupProcess.ExitCode -ne 0) {
        $result.code = "SYSTEM_FILE_CLEANUP_FAILED"
        $result.message = "Windows Disk Cleanup returned an error."
        $result.verification = "native_disk_cleanup_failed"
        throw "native_disk_cleanup_failed"
    }
    $after = Get-FreeDiskBytes
    $result.status = "ok"
    $result.phase = "completed"
    $result.code = "SYSTEM_FILE_CLEANUP_COMPLETED"
    $result.message = "System File Cleanup completed successfully."
    $result.free_disk_bytes_after = $after
    $result.bytes_reclaimed = [int64]($after - $before)
    $result.verification = "native_disk_cleanup_completed"
}
catch {
    if ($result.phase -ne "timed_out") {
        $result.status = "error"
        $result.phase = "failed"
    }
    if ($result.verification -eq "not_completed") {
        $result.code = "SYSTEM_FILE_CLEANUP_FAILED"
        $result.message = "System File Cleanup failed safely before completion."
        $result.verification = "native_disk_cleanup_error"
    }
}
finally {
    $restoreSucceeded = $true
    foreach ($previous in $previousFlags) {
        try {
            if ($previous.exists) {
                New-ItemProperty -LiteralPath $previous.path -Name $StateFlagName -PropertyType DWord -Value ([int]$previous.value) -Force | Out-Null
            }
            else {
                Remove-ItemProperty -LiteralPath $previous.path -Name $StateFlagName -ErrorAction SilentlyContinue
            }
        }
        catch {
            $restoreSucceeded = $false
        }
    }
    $result.flags_restored = $restoreSucceeded
    if (-not $restoreSucceeded) {
        $result.status = "error"
        $result.phase = "failed"
        $result.code = "GCP_VDI_CLEANUP_PROFILE_RESTORE_FAILED"
        $result.message = "System File Cleanup finished, but its temporary profile flags could not be fully restored."
        $result.verification = "cleanup_profile_restore_failed"
    }
    $result.selected_categories = @($selected)
    $result.free_disk_bytes_before = $before
    if ($null -ne $before -and $null -eq $after) {
        try { $after = Get-FreeDiskBytes } catch {}
    }
    $result.free_disk_bytes_after = $after
    if ($null -ne $before -and $null -ne $after) {
        $result.bytes_reclaimed = [int64]($after - $before)
    }
    $result.completed_at = (Get-Date).ToUniversalTime().ToString("o")
    $stopwatch.Stop()
    $result.elapsed_seconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
    Write-CleanupStatus $result
}
'@
# The legacy cleanmgr-based prototype above is intentionally not installed or
# invoked. The active deterministic worker is maintained as reviewed repository
# assets so the model can never supply a URL, path, filter, command, or category.
$CleanupControllerAsset = Join-Path $PSScriptRoot "run_cleanup_9144.ps1"
$CleanupWorkerAsset = Join-Path $PSScriptRoot "ServiceDeskFixedCleanup.cs"
if (-not (Test-Path -LiteralPath $CleanupControllerAsset -PathType Leaf) -or
    -not (Test-Path -LiteralPath $CleanupWorkerAsset -PathType Leaf)) {
    throw "Fixed System File Cleanup assets are unavailable."
}
Set-Content -Path $CleanupPath -Value (Get-Content -LiteralPath $CleanupControllerAsset -Raw) -Encoding UTF8
Set-Content -Path $CleanupWorkerSourcePath -Value (Get-Content -LiteralPath $CleanupWorkerAsset -Raw) -Encoding UTF8
$CompilerPath = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path -LiteralPath $CompilerPath -PathType Leaf)) {
    throw "The fixed System File Cleanup compiler is unavailable."
}
$Compiler = Start-Process -FilePath $CompilerPath -ArgumentList @(
    "/nologo",
    "/target:exe",
    "/platform:x64",
    "/optimize+",
    "/out:`"$CleanupWorkerPath`"",
    "`"$CleanupWorkerSourcePath`""
) -Wait -PassThru -NoNewWindow
if ($Compiler.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $CleanupWorkerPath -PathType Leaf)) {
    throw "The fixed System File Cleanup worker could not be compiled."
}

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

function Write-ExistingTaskDiagnostic {
    # Capture the previous task's truth before this idempotent bootstrap replaces
    # it. Only fixed ServiceDesk action/principal values and scheduler metadata are
    # emitted; unexpected executable/argument/principal values are redacted.
    try {
        $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -eq $ExistingTask) {
            return
        }
        $ExistingTaskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        $ExpectedExecute = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $ExpectedArguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SupervisorPath -MaximumIterations 1"
        $ExistingAction = @($ExistingTask.Actions)[0]
        $ExistingTrigger = @($ExistingTask.Triggers)[0]
        $ActualExecute = [string]$ExistingAction.Execute
        $ActualArguments = [string]$ExistingAction.Arguments
        $ActualPrincipal = [string]$ExistingTask.Principal.UserId
        $SafeLastRunTime = $null
        $SafeNextRunTime = $null
        if ($null -ne $ExistingTaskInfo -and $ExistingTaskInfo.LastRunTime.Year -gt 1) {
            $SafeLastRunTime = $ExistingTaskInfo.LastRunTime.ToUniversalTime().ToString("o")
        }
        if ($null -ne $ExistingTaskInfo -and $ExistingTaskInfo.NextRunTime.Year -gt 1) {
            $SafeNextRunTime = $ExistingTaskInfo.NextRunTime.ToUniversalTime().ToString("o")
        }
        $TelemetryFile = Get-ChildItem -Path $ServiceDeskRoot -Filter "rdp_telemetry_*.jsonl" -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
        if ($null -eq $TelemetryFile) {
            $TelemetryFile = Get-Item -Path $TelemetryPath -ErrorAction SilentlyContinue
        }
        $AuditFile = Get-ChildItem -Path $ServiceDeskRoot -Filter "rdp_collector_audit_*.jsonl" -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
        if ($null -eq $AuditFile) {
            $AuditFile = Get-Item -Path $CollectorAuditPath -ErrorAction SilentlyContinue
        }
        [ordered]@{
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
            phase = "existing_task_diagnostic"
            task_state = [string]$ExistingTask.State
            last_run_time = $SafeLastRunTime
            next_run_time = $SafeNextRunTime
            last_task_result = if ($null -ne $ExistingTaskInfo) { [int64]$ExistingTaskInfo.LastTaskResult } else { $null }
            missed_runs = if ($null -ne $ExistingTaskInfo) { [int64]$ExistingTaskInfo.NumberOfMissedRuns } else { $null }
            action_execute = if ($ActualExecute -ieq $ExpectedExecute) { $ExpectedExecute } else { "unexpected_redacted" }
            action_arguments = if ($ActualArguments -ceq $ExpectedArguments) { $ExpectedArguments } else { "unexpected_redacted" }
            trigger_start_boundary = if ($null -ne $ExistingTrigger) { [string]$ExistingTrigger.StartBoundary } else { $null }
            repetition_interval = if ($null -ne $ExistingTrigger) { [string]$ExistingTrigger.Repetition.Interval } else { $null }
            repetition_duration = if ($null -ne $ExistingTrigger) { [string]$ExistingTrigger.Repetition.Duration } else { $null }
            principal_user_id = if ($ActualPrincipal -ieq "SYSTEM") { "SYSTEM" } else { "unexpected_redacted" }
            principal_logon_type = [string]$ExistingTask.Principal.LogonType
            principal_run_level = [string]$ExistingTask.Principal.RunLevel
            telemetry_last_write_time = if ($null -ne $TelemetryFile) { $TelemetryFile.LastWriteTimeUtc.ToString("o") } else { $null }
            telemetry_size_bytes = if ($null -ne $TelemetryFile) { [int64]$TelemetryFile.Length } else { $null }
            audit_last_write_time = if ($null -ne $AuditFile) { $AuditFile.LastWriteTimeUtc.ToString("o") } else { $null }
            audit_size_bytes = if ($null -ne $AuditFile) { [int64]$AuditFile.Length } else { $null }
        } | ConvertTo-Json -Compress | Add-Content -Path $CollectorAuditPath -Encoding UTF8

        $TaskSchedulerEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-TaskScheduler/Operational"
            StartTime = (Get-Date).AddHours(-6)
        } -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -like "*ServiceDeskVDI-RdpTelemetry*"
        } | Select-Object -First 30
        foreach ($TaskEvent in $TaskSchedulerEvents) {
            [ordered]@{
                timestamp = (Get-Date).ToUniversalTime().ToString("o")
                phase = "existing_task_scheduler_event"
                event_time = $TaskEvent.TimeCreated.ToUniversalTime().ToString("o")
                event_id = [int]$TaskEvent.Id
                event_level = [string]$TaskEvent.LevelDisplayName
            } | ConvertTo-Json -Compress | Add-Content -Path $CollectorAuditPath -Encoding UTF8
        }
    }
    catch {
        # Diagnostic collection must not alter or block bootstrap behavior.
    }
}

try {
    Write-ExistingTaskDiagnostic
    $ServiceDeskEventSource = "ServiceDeskVDI"
    if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceDeskEventSource)) {
        New-EventLog -LogName "Application" -Source $ServiceDeskEventSource
    }
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
    $CounterPaths = @()
    if ($null -ne $CounterSet) {
        # Persist the validated wildcard path once. Recurring probes reuse this
        # exact path and never enumerate every Windows performance-counter set.
        $CounterPaths = @($CounterSet.Paths | Where-Object { $_ })
    }
    $CounterAvailable = $CounterPaths.Count -gt 0

    # RemoteFX Network Current TCP RTT is the genuine RDP transport round-trip
    # observation used by the customer threshold. Discover and persist its exact
    # wildcard path once; recurring probes never enumerate counter sets.
    $RttCounterSet = Get-Counter -ListSet "RemoteFX Network" -ErrorAction SilentlyContinue
    $RttCounterPaths = @()
    if ($null -ne $RttCounterSet) {
        $RttCounterPaths = @(
            $RttCounterSet.Paths |
                Where-Object { $_ -match "\\Current TCP RTT$" }
        )
    }
    $RttCounterAvailable = $RttCounterPaths.Count -gt 0

    [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        available_event_channels = $AvailableChannels
        unavailable_event_channels = $UnavailableChannels
        user_input_delay_counter_set_available = $CounterAvailable
        user_input_delay_counter_set = if ($CounterAvailable) { $CounterSet.CounterSetName } else { $null }
        user_input_delay_counter_paths = $CounterPaths
        rdp_tcp_rtt_counter_set_available = $RttCounterAvailable
        rdp_tcp_rtt_counter_set = if ($RttCounterAvailable) { $RttCounterSet.CounterSetName } else { $null }
        rdp_tcp_rtt_counter_paths = $RttCounterPaths
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
'@
    Set-Content -Path $CounterProbePath -Value $CounterProbeScript -Encoding UTF8

    $CollectorScript = @'
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
try {
    $Capabilities = Get-Content -Path $CapabilityPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $CounterAvailable = $Capabilities.user_input_delay_counter_set_available -eq $true
    $RttCounterAvailable = $Capabilities.rdp_tcp_rtt_counter_set_available -eq $true
}
catch {
    $CounterAvailable = $false
    $RttCounterAvailable = $false
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
'@
    Set-Content -Path $CollectorPath -Value $CollectorScript -Encoding UTF8

    $TaskRunnerScript = @'
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
'@
    Set-Content -Path $TaskRunnerPath -Value $TaskRunnerScript -Encoding UTF8

    $SupervisorScript = @'
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
'@
    Set-Content -Path $SupervisorPath -Value $SupervisorScript -Encoding UTF8

    $ChannelYaml = ($AvailableChannels | ForEach-Object {
        "          - '" + ($_ -replace "'", "''") + "'"
    }) -join "`r`n"
    $OpsAgentConfig = @"
$OpsAgentOwnershipMarker
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
        - 'C:\ProgramData\ServiceDeskVDI\rdp_telemetry_*.jsonl'
      record_log_file_path: false
      wildcard_refresh_interval: 10s
    servicedesk_rdp_collector_audit:
      type: files
      include_paths:
        - 'C:\ProgramData\ServiceDeskVDI\rdp_collector_audit.jsonl'
        - 'C:\ProgramData\ServiceDeskVDI\rdp_collector_audit_*.jsonl'
      record_log_file_path: false
      wildcard_refresh_interval: 10s
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
    function Get-NormalizedConfigText {
        param([string]$Text)
        return (($Text -replace "`r`n", "`n").Trim())
    }

    $ExistingOpsAgentConfig = ""
    if (Test-Path $OpsAgentConfigPath) {
        $ExistingOpsAgentConfig = Get-Content -Path $OpsAgentConfigPath -Raw -ErrorAction Stop
    }
    $MeaningfulExistingLines = @(
        $ExistingOpsAgentConfig -split "`r?`n" |
            Where-Object { $_.Trim() -and -not $_.Trim().StartsWith("#") }
    )
    $ExistingConfigIsMeaningful = $MeaningfulExistingLines.Count -gt 0
    $ManagedSnapshotMatches = $false
    if (Test-Path $OpsAgentManagedSnapshotPath) {
        $ManagedSnapshot = Get-Content -Path $OpsAgentManagedSnapshotPath -Raw -ErrorAction Stop
        $ManagedSnapshotMatches =
            (Get-NormalizedConfigText $ExistingOpsAgentConfig) -eq
            (Get-NormalizedConfigText $ManagedSnapshot)
    }
    # Recognize the exact config produced by the earlier PoC revision once, so it
    # can be upgraded to the ownership-marker/snapshot model without treating an
    # unrelated file containing similarly named entries as ServiceDesk-owned.
    $LegacyServiceDeskConfig = $OpsAgentConfig.Replace(
        "$OpsAgentOwnershipMarker`r`n",
        ""
    ).Replace("$OpsAgentOwnershipMarker`n", "")
    $LegacyServiceDeskConfigMatches =
        (Get-NormalizedConfigText $ExistingOpsAgentConfig) -eq
        (Get-NormalizedConfigText $LegacyServiceDeskConfig)

    if ($ExistingConfigIsMeaningful -and
        -not $ManagedSnapshotMatches -and
        -not $LegacyServiceDeskConfigMatches) {
        if (-not (Test-Path $OpsAgentBackupPath)) {
            Copy-Item -Path $OpsAgentConfigPath -Destination $OpsAgentBackupPath -ErrorAction Stop
        }
        throw "Existing Ops Agent user configuration is not ServiceDesk-owned; it was preserved and requires an explicit safe merge."
    }
    if ((Test-Path $OpsAgentConfigPath) -and -not (Test-Path $OpsAgentBackupPath)) {
        Copy-Item -Path $OpsAgentConfigPath -Destination $OpsAgentBackupPath -ErrorAction Stop
    }

    # Windows PowerShell's `Set-Content -Encoding UTF8` writes a BOM. The Ops
    # Agent YAML parser treats that marker as part of the first key (`?logging`)
    # and refuses to start, so write ServiceDesk-owned files explicitly without it.
    $Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    $OpsAgentTempPath = "$OpsAgentConfigPath.servicedesk.tmp"
    [System.IO.File]::WriteAllText($OpsAgentTempPath, $OpsAgentConfig, $Utf8WithoutBom)
    Move-Item -Path $OpsAgentTempPath -Destination $OpsAgentConfigPath -Force
    [System.IO.File]::WriteAllText(
        $OpsAgentManagedSnapshotPath,
        $OpsAgentConfig,
        $Utf8WithoutBom
    )

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
    $TelemetryFile = Get-ChildItem -Path $ServiceDeskRoot -Filter "rdp_telemetry_*.jsonl" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $TelemetryFile) {
        $TelemetryFile = Get-Item -Path $TelemetryPath -ErrorAction SilentlyContinue
    }
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
    # Keep the first boundary comfortably after registration and the Ops Agent
    # restart below. A missed StartWhenAvailable boundary can be queued with a
    # substantial scheduler delay, so it is not a substitute for a future
    # boundary during bootstrap.
    $TaskStartTime = (Get-Date).AddMinutes(2)
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
    $TaskRegistrationCheckedAt = Get-Date
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
        $null -ne $CollectorTaskInfo -and
        $CollectorTaskInfo.NextRunTime -gt $TaskRegistrationCheckedAt
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
        $ConfigFile = Get-Item -Path $OpsAgentConfigPath -ErrorAction SilentlyContinue
        $ConfigHash = Get-FileHash -Path $OpsAgentConfigPath -Algorithm SHA256 -ErrorAction SilentlyContinue
        Write-Output "ServiceDesk Ops Agent config diagnostic: bytes=$($ConfigFile.Length), sha256=$($ConfigHash.Hash)"
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
