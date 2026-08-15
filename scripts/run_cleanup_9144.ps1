param(
    [Parameter(Mandatory = $true)]
    [string]$InvocationId,
    [switch]$Controller,
    [string]$ExpectedUser
)

$ErrorActionPreference = "Stop"
$ServiceDeskRoot = "C:\ProgramData\ServiceDeskVDI"
$CleanupWorkerPath = Join-Path $ServiceDeskRoot "ServiceDeskFixedCleanup.exe"
$ResultPath = Join-Path $ServiceDeskRoot ("cleanup_9144_{0}.json" -f $InvocationId)
$TaskName = "SystemFileCleanup9144-$InvocationId"
$TaskFolder = "\ServiceDeskVDI"

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

if (-not $Controller -or
    $InvocationId -notmatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" -or
    $ExpectedUser -notmatch "^[A-Za-z0-9_.-]{1,20}$") {
    Write-ControllerResult "error" "GCP_VDI_CLEANUP_CONTROLLER_INPUT_INVALID" "The fixed cleanup controller input was invalid." $null
    exit 0
}
if (-not (Test-Path -LiteralPath $CleanupWorkerPath -PathType Leaf)) {
    Write-ControllerResult "error" "GCP_VDI_CLEANUP_WORKER_MISSING" "The fixed System File Cleanup worker is not installed." $null
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
        if (item.State == WTS_CONNECTSTATE_CLASS.Active && item.SessionID > 0)
          result.Add(item.SessionID + "|" + Query(item.SessionID, 7) + "|" + Query(item.SessionID, 5));
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

try {
    Add-Type -TypeDefinition $native -Language CSharp
    $matches = @()
    foreach ($row in [ServiceDeskInteractiveSession]::ActiveSessions()) {
        $parts = @($row -split '\|', 3)
        if ($parts.Count -eq 3 -and $parts[2] -ieq $ExpectedUser) {
            $matches += [pscustomobject]@{session_id=[int]$parts[0]; domain=$parts[1]; username=$parts[2]}
        }
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
    try { $folder = $scheduler.GetFolder($TaskFolder) } catch {
        $folder = $scheduler.GetFolder("\").CreateFolder("ServiceDeskVDI", $null)
    }
    try { $folder.DeleteTask($TaskName, 0) } catch {}
    Remove-Item -LiteralPath $ResultPath -Force -ErrorAction SilentlyContinue
    $definition = $scheduler.NewTask(0)
    $definition.RegistrationInfo.Description = "Fixed ServiceDesk System File Cleanup"
    $definition.Principal.UserId = $principal
    $definition.Principal.LogonType = 3
    $definition.Principal.RunLevel = 1
    $definition.Settings.Enabled = $true
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.ExecutionTimeLimit = "PT2M"
    $action = $definition.Actions.Create(0)
    $action.Path = $CleanupWorkerPath
    $action.Arguments = '--invocation "' + $InvocationId + '" --result "' + $ResultPath + '"'
    $registered = $folder.RegisterTaskDefinition($TaskName, $definition, 6, $principal, $null, 3, $null)
    $running = $registered.RunEx($null, 4, [int]$session.session_id, $null)
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
}
catch {
    Write-ControllerResult "error" "GCP_VDI_CLEANUP_CONTROLLER_FAILED" "The interactive cleanup controller failed safely before completion." $null
}


