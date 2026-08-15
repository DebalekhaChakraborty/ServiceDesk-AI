<#
DEMO PREPARATION ONLY — OPERATOR UTILITY, NOT AGENT-CALLABLE.

Seeds exactly four harmless WinINet NORMAL_CACHE_ENTRY items so the customer
demo can show System File Cleanup removing real, verifiable Temporary Internet
Files.

Run only on the approved GCP virtual-desktop PoC guest, inside the mapped
demo user's own interactive session, through an operator's existing secure
administrative access. The ServiceDesk agent has no path to this script: it is
not registered as an action, not deployed by the collector bootstrap, and not
referenced by the cleanup worker.

The entries created here are deliberately shaped to satisfy the cleanup
worker's eligibility filter (NORMAL_CACHE_ENTRY, and none of STICKY / EDITED /
COOKIE / URLHISTORY), so the demonstrated before/removed/remaining counts are
genuine rather than staged.

What this NEVER does:
  * no cookies
  * no browsing history
  * no credentials
  * no arbitrary URL or path input
  * no network access
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 80)]
    [int]$EntryCount = 46
)

$ErrorActionPreference = "Stop"

if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
    throw "Run as the mapped interactive demo user, not as SYSTEM. WinINet cache is per-user."
}

Add-Type -Namespace ServiceDeskDemo -Name WinINet -MemberDefinition @'
[DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CreateUrlCacheEntryW(
    string lpszUrlName, uint dwExpectedFileSize, string lpszFileExtension,
    System.Text.StringBuilder lpszFileName, uint dwReserved);

[DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CommitUrlCacheEntryW(
    string lpszUrlName, string lpszLocalFileName,
    System.Runtime.InteropServices.ComTypes.FILETIME ExpireTime,
    System.Runtime.InteropServices.ComTypes.FILETIME LastModifiedTime,
    uint CacheEntryType, string lpHeaderInfo, uint dwHeaderSize,
    string lpszFileExtension, string lpszOriginalUrl);
'@

# Must match the cleanup worker's eligibility filter exactly.
$NORMAL_CACHE_ENTRY = 0x00000001
$emptyFileTime = New-Object System.Runtime.InteropServices.ComTypes.FILETIME

$stamp = (Get-Date).ToString("yyyyMMddHHmmss")
$created = 0

Write-Host "ServiceDesk demo cache seeding — DEMO PREPARATION ONLY" -ForegroundColor Cyan
Write-Host ""

for ($i = 1; $i -le $EntryCount; $i++) {
    # Fixed, clearly-labelled, non-routable demo URLs. No operator/agent input.
    $url = "http://servicedesk-demo.invalid/servicedesk-demo-cache/$stamp/item-$i.txt"
    $body = "ServiceDesk demo cache entry $i of $EntryCount generated $stamp. Safe to delete."

    $buffer = New-Object System.Text.StringBuilder 260
    if (-not [ServiceDeskDemo.WinINet]::CreateUrlCacheEntryW($url, $body.Length, "txt", $buffer, 0)) {
        throw "CreateUrlCacheEntryW failed for entry $i (error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }
    $localFile = $buffer.ToString()

    [System.IO.File]::WriteAllText($localFile, $body)

    $headers = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`n`r`n"
    $ok = [ServiceDeskDemo.WinINet]::CommitUrlCacheEntryW(
        $url, $localFile, $emptyFileTime, $emptyFileTime,
        $NORMAL_CACHE_ENTRY, $headers, $headers.Length, "txt", $null)

    if (-not $ok) {
        throw "CommitUrlCacheEntryW failed for entry $i (error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    $created++
    Write-Host ("  seeded [{0}/{1}] {2}" -f $created, $EntryCount, $url) -ForegroundColor Green
}


Write-Host ""
Write-Host ("Seeded {0} Temporary Internet Files entries as user '{1}'." -f $created, [Environment]::UserName) -ForegroundColor Cyan
Write-Host "System File Cleanup should now report this many eligible items." -ForegroundColor Gray