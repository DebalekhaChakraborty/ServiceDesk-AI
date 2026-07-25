import os
import winrm # type: ignore
from typing import Dict

# ====== Config via environment ======
WINRM_USER = os.getenv("WINRM_USERNAME")
WINRM_PASS = os.getenv("WINRM_PASSWORD")
WINRM_PORT = int(os.getenv("WINRM_PORT"))                  
WINRM_TRANSPORT = os.getenv("WINRM_TRANSPORT")             
WINRM_CERT_VALIDATE = os.getenv("WINRM_CERT_VALIDATE")   


# ====== Internals ======
def _endpoint(host: str) -> str:
    """
    Build a full HTTPS endpoint for pywinrm unless the caller already provided a URL.
    Accepts:
      - 'windows-instance.us-central1-a.c.ai-and-automation-coe.internal'
      - '10.128.0.3'
      - 'https://host:5986/wsman' (will be used as-is)
    """
    h = host.strip()
    if h.startswith("http://") or h.startswith("https://"):
        return h  # caller passed a full endpoint
    return f"https://{h}:{WINRM_PORT}/wsman"


def _session(host: str) -> winrm.Session:
    """
    Create a WinRM session with configured transport and cert validation policy.
    """
    if not WINRM_USER or not WINRM_PASS:
        raise RuntimeError("WINRM_USER/WINRM_PASS not set in environment.")
    return winrm.Session(
        _endpoint(host),
        auth=(WINRM_USER, WINRM_PASS),
        transport=WINRM_TRANSPORT,
        server_cert_validation=WINRM_CERT_VALIDATE
    )


def _result(res) -> Dict[str, object]:
    """
    Normalize pywinrm response object to a consistent dict.
    """
    return {
        "status": "success" if res.status_code == 0 else "failed",
        "code": res.status_code,
        "stdout": (res.std_out or b"").decode(errors="ignore"),
        "stderr": (res.std_err or b"").decode(errors="ignore"),
    }


def _fail(host: str, err: Exception) -> Dict[str, object]:
    return {
        "status": "failed",
        "code": -1,
        "stdout": "",
        "stderr": f"{type(err).__name__}: {str(err)} (host={host})",
    }


# ====== Public helpers ======
def execute_winrm_cmd(host: str, command: str) -> Dict[str, object]:
    """
    Execute a raw command via cmd.exe on the remote host.
    Prefer PowerShell via execute_winrm_ps() for reliability.
    """
    try:
        ses = _session(host)
        res = ses.run_cmd(command)
        return _result(res)
    except Exception as e:
        return _fail(host, e)


def execute_winrm_ps(host: str, ps_script: str) -> Dict[str, object]:
    """
    Execute a PowerShell script block on the remote host.
    """
    try:
        ses = _session(host)
        res = ses.run_ps(ps_script)
        return _result(res)
    except Exception as e:
        return _fail(host, e)


# ====== Action implementations (used by planner/executor) ======
def time_resync(target_host: str) -> Dict[str, object]:
    """
    Effect: time_synchronized(${target_host})
    Inputs: target_host
    Tries w32tm /resync; falls back to restarting w32time service then resync.
    """
    ps = r"""
    try {
      $out = w32tm /resync /force 2>&1 | Out-String
      if (-not $out) { $out = 'w32tm returned no output' }
      Write-Output $out
      exit 0
    } catch {
      try {
        Restart-Service -Name w32time -Force -ErrorAction Stop
        $out = w32tm /resync /force 2>&1 | Out-String
        Write-Output $out
        exit 0
      } catch {
        Write-Error $_.Exception.Message
        exit 1
      }
    }
    """
    return execute_winrm_ps(target_host, ps)


def restart_service(target_host: str, service_name: str) -> Dict[str, object]:
    """
    Restart a Windows service by name.
    """
    ps = rf"""
    try {{
      Restart-Service -Name '{service_name}' -Force -ErrorAction Stop
      Write-Output "Service '{service_name}' restarted."
      exit 0
    }} catch {{
      Write-Error $_.Exception.Message
      exit 1
    }}
    """
    return execute_winrm_ps(target_host, ps)


def clear_dns_cache(target_host: str) -> Dict[str, object]:
    """
    Flush DNS client cache.
    """
    ps = r"""
    try {
      Clear-DnsClientCache -ErrorAction Stop
      Write-Output "DNS client cache cleared."
      exit 0
    } catch {
      Write-Error $_.Exception.Message
      exit 1
    }
    """
    return execute_winrm_ps(target_host, ps)


def cleanup_temp_files(target_host: str) -> Dict[str, object]:
    """
    Delete temp files in user and system temp folders (best-effort).
    """
    ps = r"""
    $paths = @("$env:TEMP\*", "$env:WINDIR\Temp\*")
    $errors = @()
    foreach ($p in $paths) {
      try {
        Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop
      } catch {
        $errors += $_.Exception.Message
      }
    }
    if ($errors.Count -gt 0) {
      $msg = 'Some items could not be removed: ' + ($errors -join '; ')
      Write-Error $msg
      exit 1
    } else {
      Write-Output 'Temp files cleaned.'
      exit 0
    }
    """
    return execute_winrm_ps(target_host, ps)


from typing import Dict, Optional

# def install_software(
#     target_host: str,
#     software_name: str,
#     installer_url: str,
#     installer_type: str = "msi",          # "msi" or "exe"
#     silent_args: str = "/qn /norestart",  # for MSI; EXE examples: "/S", "/quiet", etc.
#     verify_display_name: Optional[str] = None,
#     verify_exe_path: Optional[str] = None,
# ) -> Dict[str, object]:
#     """
#     Install approved software using governed installer (MSI/EXE) over WinRM.

#     Inputs:
#       - target_host: endpoint hostname/FQDN
#       - software_name: friendly name (for logs/messages)
#       - installer_url: URL to MSI/EXE (prefer internal repo in enterprise)
#       - installer_type: "msi" or "exe"
#       - silent_args: silent install arguments (from SOP)
#       - verify_display_name: optional partial display name to verify via uninstall registry
#       - verify_exe_path: optional full exe path to verify existence (e.g. "C:\\Program Files\\7-Zip\\7zFM.exe")

#     Returns execute_winrm_ps() output.
#     """
#     # Safely embed strings in PS (basic escaping)
#     def _ps_escape(s: str) -> str:
#         return (s or "").replace("`", "``").replace('"', '`"')

#     sw = _ps_escape(software_name)
#     url = _ps_escape(installer_url)
#     typ = _ps_escape(installer_type.strip().lower())
#     args = _ps_escape(silent_args)
#     vname = _ps_escape(verify_display_name or "")
#     vexe = _ps_escape(verify_exe_path or "")

#     ps = rf"""
# $ErrorActionPreference = "Stop"
# $ProgressPreference = "SilentlyContinue"

# $softwareName = "{sw}"
# $url = "{url}"
# $type = "{typ}"
# $silentArgs = "{args}"
# $verifyDisplayName = "{vname}"
# $verifyExePath = "{vexe}"

# Write-Output ("[install] software=" + $softwareName)
# Write-Output ("[install] url=" + $url)
# Write-Output ("[install] type=" + $type)
# Write-Output ("[install] args=" + $silentArgs)

# # ---- Prep download location ----
# $workDir = Join-Path $env:TEMP ("it_software_install_" + [guid]::NewGuid().ToString("N"))
# New-Item -ItemType Directory -Force -Path $workDir | Out-Null

# try {{
#     # ---- Download installer ----
#     $fileName = Split-Path -Path $url -Leaf
#     if (-not $fileName -or $fileName -eq $url) {{
#         # If URL does not end in a filename, choose one
#         $fileName = if ($type -eq "exe") {{ "installer.exe" }} else {{ "installer.msi" }}
#     }}
#     $installerPath = Join-Path $workDir $fileName

#     Write-Output ("[install] downloading to " + $installerPath)
#     Invoke-WebRequest -Uri $url -OutFile $installerPath -UseBasicParsing

#     if (-not (Test-Path $installerPath)) {{
#         throw "Download failed: installer not found at $installerPath"
#     }}

#     # ---- Execute silent install ----
#     if ($type -eq "msi") {{
#         $msiArgs = "/i `"$installerPath`" " + $silentArgs
#         Write-Output ("[install] running: msiexec.exe " + $msiArgs)
#         $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
#         $code = $p.ExitCode
#         Write-Output ("[install] msiexec exit code=" + $code)
#         if ($code -ne 0) {{
#             throw "MSI installation failed with exit code $code"
#         }}
#     }}
#     elseif ($type -eq "exe") {{
#         Write-Output ("[install] running: " + $installerPath + " " + $silentArgs)
#         $p = Start-Process -FilePath $installerPath -ArgumentList $silentArgs -Wait -PassThru
#         $code = $p.ExitCode
#         Write-Output ("[install] exe exit code=" + $code)
#         if ($code -ne 0) {{
#             throw "EXE installation failed with exit code $code"
#         }}
#     }}
#     else {{
#         throw "Unsupported installer_type: $type (expected 'msi' or 'exe')"
#     }}

#     # ---- Verify (optional but recommended) ----
#     $verified = $false
#     $verifyNotes = @()

#     if ($verifyExePath -and (Test-Path $verifyExePath)) {{
#         $verified = $true
#         $verifyNotes += ("Verified EXE path exists: " + $verifyExePath)
#     }}

#     if (-not $verified -and $verifyDisplayName) {{
#         $uninstallKeys = @(
#           "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
#           "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
#         )
#         foreach ($k in $uninstallKeys) {{
#             $hit = Get-ItemProperty $k -ErrorAction SilentlyContinue |
#                    Where-Object {{ $_.DisplayName -and ($_.DisplayName -like ("*" + $verifyDisplayName + "*")) }} |
#                    Select-Object -First 1
#             if ($hit) {{
#                 $verified = $true
#                 $verifyNotes += ("Verified DisplayName found: " + $hit.DisplayName)
#                 break
#             }}
#         }}
#     }}

#     if (-not $verified) {{
#         $verifyNotes += "No verification rule matched (provide verify_exe_path or verify_display_name for strong verification)."
#     }}

#     Write-Output ("[install] verified=" + $verified)
#     if ($verifyNotes.Count -gt 0) {{
#         Write-Output ("[install] verify_notes=" + ($verifyNotes -join " | "))
#     }}

#     Write-Output "INSTALL_OK"
#     exit 0
# }}
# catch {{
#     Write-Error ("INSTALL_FAILED: " + $_.Exception.Message)
#     exit 1
# }}
# finally {{
#     # Cleanup download folder
#     try {{ Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue }} catch {{}}
# }}
# """
#     return execute_winrm_ps(target_host, ps)




from typing import Dict, Optional

def install_software(
    target_host: str,
    software_name: str,
    installer_url: Optional[str] = "",
    installer_type: Optional[str] = "",
    silent_args: Optional[str] = "",
    verify_exe_path: Optional[str] = "",
) -> Dict[str, object]:
    """
    DEMO-SAFE installer-based software install (WinRM-friendly).
    If installer fields are missing, falls back to hardcoded approved mapping for 7-Zip.
    """

    # ---------- DEMO APPROVED INSTALLER MAP ----------
    # Add more apps later if needed.
    DEMO_INSTALL_MAP = {
        "7-zip": {
            "installer_type": "msi",
            "installer_url": "https://www.7-zip.org/a/7z2301-x64.msi",
            "silent_args": "/qn /norestart",
            "verify_exe_path": r"C:\Program Files\7-Zip\7zFM.exe",
        },
        # Optional aliases
        "7zip": {
            "installer_type": "msi",
            "installer_url": "https://www.7-zip.org/a/7z2301-x64.msi",
            "silent_args": "/qn /norestart",
            "verify_exe_path": r"C:\Program Files\7-Zip\7zFM.exe",
        },
        "7 zip": {
            "installer_type": "msi",
            "installer_url": "https://www.7-zip.org/a/7z2301-x64.msi",
            "silent_args": "/qn /norestart",
            "verify_exe_path": r"C:\Program Files\7-Zip\7zFM.exe",
        },
    }

    def _norm(s: str) -> str:
        return (s or "").strip().lower().replace("_", " ").strip()

    name_norm = _norm(software_name)

    # If planner didn’t provide installer fields, fill from demo map
    if not (installer_url and installer_type and silent_args):
        if name_norm in DEMO_INSTALL_MAP:
            m = DEMO_INSTALL_MAP[name_norm]
            installer_type = installer_type or m["installer_type"]
            installer_url = installer_url or m["installer_url"]
            silent_args = silent_args or m["silent_args"]
            verify_exe_path = verify_exe_path or m.get("verify_exe_path", "")
        else:
            return {
                "status": "error",
                "message": (
                    f"Missing installer details for '{software_name}'. "
                    "Demo mapping only supports: 7-Zip."
                ),
                "details": {
                    "software_name": software_name,
                    "installer_url_present": bool(installer_url),
                    "installer_type_present": bool(installer_type),
                    "silent_args_present": bool(silent_args),
                },
            }

    # Basic escaping for PowerShell double-quoted strings
    def _ps_escape(s: str) -> str:
        return (s or "").replace("`", "``").replace('"', '`"')

    sw = _ps_escape(software_name)
    url = _ps_escape(installer_url or "")
    typ = _ps_escape((installer_type or "").strip().lower())
    args = _ps_escape(silent_args or "")
    vexe = _ps_escape(verify_exe_path or "")

    ps = rf"""
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$softwareName = "{sw}"
$url = "{url}"
$type = "{typ}"
$silentArgs = "{args}"
$verifyExePath = "{vexe}"

Write-Output ("[install] software=" + $softwareName)
Write-Output ("[install] url=" + $url)
Write-Output ("[install] type=" + $type)
Write-Output ("[install] args=" + $silentArgs)

$workDir = Join-Path $env:TEMP ("it_install_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

try {{
  $fileName = Split-Path -Path $url -Leaf
  if (-not $fileName) {{
    $fileName = if ($type -eq "exe") {{ "installer.exe" }} else {{ "installer.msi" }}
  }}
  $installerPath = Join-Path $workDir $fileName

  Write-Output ("[install] downloading to " + $installerPath)
  Invoke-WebRequest -Uri $url -OutFile $installerPath -UseBasicParsing
  if (-not (Test-Path $installerPath)) {{
    throw "Download failed: installer not found at $installerPath"
  }}

  if ($type -eq "msi") {{
    $msiArgs = "/i `"$installerPath`" " + $silentArgs
    Write-Output ("[install] running: msiexec.exe " + $msiArgs)
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) {{ throw "MSI install failed exit code: $($p.ExitCode)" }}
  }} elseif ($type -eq "exe") {{
    Write-Output ("[install] running: " + $installerPath + " " + $silentArgs)
    $p = Start-Process -FilePath $installerPath -ArgumentList $silentArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) {{ throw "EXE install failed exit code: $($p.ExitCode)" }}
  }} else {{
    throw "Unsupported installer_type: $type"
  }}

  # Verify (best-effort)
  $verified = $false
  if ($verifyExePath -and (Test-Path $verifyExePath)) {{
    $verified = $true
    Write-Output ("[install] verify: exe exists at " + $verifyExePath)
  }} else {{
    Write-Output ("[install] verify: no exe path provided or not found")
  }}

  Write-Output ("INSTALL_OK verified=" + $verified)
  exit 0
}}
catch {{
  Write-Error ("INSTALL_FAILED: " + $_.Exception.Message)
  exit 1
}}
finally {{
  try {{ Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue }} catch {{}}
}}
"""
    return execute_winrm_ps(target_host, ps)
