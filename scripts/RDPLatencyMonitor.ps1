$ErrorActionPreference="SilentlyContinue"
$Host.UI.RawUI.WindowTitle="RDP Latency Monitor"
while(1){
Clear-Host
Write-Host "========================================" -f Cyan
Write-Host "          RDP Latency Monitor           " -f Cyan
Write-Host "========================================" -f Cyan
Write-Host ""
$Sl=& "$env:SystemRoot\System32\qwinsta.exe" 2>$null
$C=@();$S=@()
foreach($L in @($Sl|Select -Skip 1)){
$N=([string]$L-replace"^\s*>","").Trim()
if(!$N){continue}
$Cols=@($N-split"\s+")
$Si=[Array]::IndexOf($Cols,"Active")
if($Si-ge 2){
$Sn=[string]$Cols[0];$Sid=[string]$Cols[$Si-1]
if($Sn-match"^rdp-tcp(?:#\d+)?$"-and $Sid-match"^\d+$"){
$S+=$Sid;$C+=(($Sn-replace"#"," ").Trim().ToLowerInvariant())
}
}
}
$Rtt=$null
if($C.Count-gt 0){
$Set=Get-Counter -ListSet "RemoteFX Network"
if($null-ne $Set){
$Paths=@($Set.Paths|?{$_-match"\\Current TCP RTT$"})
if($Paths.Count-gt 0){
$Res=Get-Counter -Counter $Paths -Max 1
$M=@($Res.CounterSamples|?{$C-contains([string]$_.InstanceName).Trim().ToLowerInvariant()}|%{ [double]$_.CookedValue }|?{$_-ge 0})|Measure-Object -Max
if($null-ne $M.Maximum){$Rtt=$M.Maximum}
}
}
}
$Del=$null
if($S.Count-gt 0){
$Set=Get-Counter -ListSet "User Input Delay per Session"
if($null-ne $Set){
$Paths=@($Set.Paths|?{$_-match"\\Max Input Delay$"})
if($Paths.Count-gt 0){
$Res=Get-Counter -Counter $Paths -Max 1
$M=@($Res.CounterSamples|?{$S-contains[string]$_.InstanceName}|%{ [double]$_.CookedValue }|?{$_-ge 0})|Measure-Object -Max
if($null-ne $M.Maximum){$Del=$M.Maximum}
}
}
}
if($null-ne $Rtt){
Write-Host "RDP TCP RTT: " -NoNewline
if($Rtt-gt 200){Write-Host "$Rtt ms" -f Red}else{Write-Host "$Rtt ms" -f Green}
Write-Host "Threshold: >200 ms"
Write-Host "Status: " -NoNewline
if($Rtt-gt 200){Write-Host "HIGH LATENCY" -f Red}else{Write-Host "BELOW THRESHOLD" -f Green}
}else{Write-Host "RDP TCP RTT: Unavailable" -f DarkGray}
Write-Host ""
if($null-ne $Del){Write-Host "User Input Delay: $Del ms" -f Yellow}else{Write-Host "User Input Delay: Unavailable" -f DarkGray}
Write-Host "`nPress Ctrl+C to exit. Refreshing in 5s..." -f Gray
Start-Sleep -s 5
}
