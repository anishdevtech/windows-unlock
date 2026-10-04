[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$RemoveEnrollment)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Unlock-Helpers.ps1')
Assert-UnlockAdmin
$taskManifest=Assert-UnlockManifest
$taskInproc=Join-Path $taskUnlockClsid 'InprocServer32'
if(Test-Path -LiteralPath $taskInproc){if((Get-Item -LiteralPath $taskInproc).GetValue('') -ne (Join-Path $taskUnlockTarget 'CredentialProvider.dll')){throw 'COM registration points outside owned installation.'}}
$taskInstalledService=Get-CimInstance Win32_Service -Filter "Name='$taskUnlockService'"
if($taskInstalledService -and $taskInstalledService.PathName -ne ('"'+(Join-Path $taskUnlockTarget 'PhoneUnlockService.exe')+'"')){throw 'Service points outside owned installation.'}
if(Test-Path -LiteralPath $taskUnlockLsaDll){Assert-UnlockPlainPath $taskUnlockLsaDll;if((Get-FileHash -LiteralPath $taskUnlockLsaDll -Algorithm SHA256).Hash -ne $taskManifest.lsaHash){throw 'Owned LSA file changed. Registration removal/file cleanup requires manual review.'}}
if(-not $PSCmdlet.ShouldProcess('WINDOWS-UNLOCK only','Remove owned tile/service/LSA entry; preserve every Microsoft sign-in method')){return}
if(Test-Path -LiteralPath $taskUnlockProvider){Remove-Item -LiteralPath $taskUnlockProvider}
if(Test-Path -LiteralPath $taskInproc){Remove-Item -LiteralPath $taskInproc}
if(Test-Path -LiteralPath $taskUnlockClsid){Remove-Item -LiteralPath $taskUnlockClsid}
Set-UnlockPackageEntry $false
if($taskInstalledService){Stop-Service -Name $taskUnlockService -ErrorAction SilentlyContinue;& sc.exe delete $taskUnlockService | Out-Null;if($LASTEXITCODE){throw 'Service removal failed. Tile and LSA entry removed; use PIN and retry after reboot.'}}
if($RemoveEnrollment){
  $taskEnrollment=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'WINDOWS-UNLOCK-SignIn'
  if(Test-Path -LiteralPath $taskEnrollment){Assert-UnlockPlainPath $taskEnrollment;foreach($taskFile in @('enrollment.dpapi','trust.json')){$taskPath=Join-Path $taskEnrollment $taskFile;if(Test-Path -LiteralPath $taskPath){Assert-UnlockPlainPath $taskPath;Remove-Item -LiteralPath $taskPath}};Remove-Item -LiteralPath $taskEnrollment -ErrorAction SilentlyContinue}
}
$taskRemaining=@()
foreach($taskPath in (@('CredentialProvider.dll','PhoneUnlockService.exe','PhoneUnlockStage.exe') | ForEach-Object {Join-Path $taskUnlockTarget $_})+@($taskUnlockLsaDll)){
  if(Test-Path -LiteralPath $taskPath){Assert-UnlockPlainPath $taskPath;try{Remove-Item -LiteralPath $taskPath}catch{$taskRemaining+=$taskPath}}
}
if($taskRemaining.Count){Write-Warning 'Owned registrations removed. Loaded DLLs remain: reboot, sign in with PIN/password, and rerun this script. Ownership marker retained. No forced reboot or recursive deletion.';return}
Remove-Item -LiteralPath (Join-Path $taskUnlockTarget 'unlock-install.json')
Remove-Item -LiteralPath $taskUnlockTarget -ErrorAction SilentlyContinue
Write-Output 'WINDOWS-UNLOCK removed. Reboot manually to unload LSA if it was loaded. Built-in Windows providers and PIN/password preserved.'
