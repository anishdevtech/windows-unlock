[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$RemoveVault,[switch]$KeepFiles)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Password-Helpers.ps1')
Assert-PasswordAdmin
$taskManifest=Get-PasswordManifest -SkipPayloadCheck
$taskBefore=Get-PasswordProviderInventory
if(-not $PSCmdlet.ShouldProcess('WINDOWS-UNLOCK password mode','Remove only its extra tile, COM registration and service')){return}
# Stop exposing the extra tile first; no Microsoft provider or LSA settings are touched.
if(Test-Path -LiteralPath $taskPasswordProvider){Remove-Item -LiteralPath $taskPasswordProvider}
if(Test-Path -LiteralPath $taskPasswordClsid){$taskInproc=Join-Path $taskPasswordClsid 'InprocServer32';if(Test-Path -LiteralPath $taskInproc){Remove-Item -LiteralPath $taskInproc};Remove-Item -LiteralPath $taskPasswordClsid}
if(Get-Service -Name $taskPasswordService -ErrorAction SilentlyContinue){Stop-Service -Name $taskPasswordService;(Get-Service -Name $taskPasswordService).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30));& sc.exe delete $taskPasswordService | Out-Null;if($LASTEXITCODE){throw 'Service removal failed. Tile was removed; normal Windows sign-in remains available.'}}
if((Get-PasswordProviderInventory) -ne $taskBefore){throw 'Other provider inventory changed unexpectedly. No Microsoft provider was modified by this script.'}
if($RemoveVault){
  $taskVaultRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'WINDOWS-UNLOCK-Password'
  if(Test-Path -LiteralPath $taskVaultRoot){Assert-PasswordPlainPath $taskVaultRoot;foreach($taskFile in @('vault.dpapi','diagnostics-pending.dpapi')){Remove-Item -LiteralPath (Join-Path $taskVaultRoot $taskFile) -ErrorAction SilentlyContinue};Remove-Item -LiteralPath $taskVaultRoot -ErrorAction SilentlyContinue}
  Write-Output 'Encrypted vault and diagnostics queue removed. In Android select Remove phone sign-in keys. The nonexportable machine signing key has no password-decryption capability.'
}
if(-not $KeepFiles){
  Assert-PasswordTarget
  $taskLocked=$false
  foreach($taskFile in $taskPasswordPayload){$taskPath=Join-Path $taskPasswordTarget $taskFile;if(Test-Path -LiteralPath $taskPath){try{Remove-Item -LiteralPath $taskPath}catch{$taskLocked=$true}}}
  if($taskLocked){Write-Output 'Tile/service removed. A file is still loaded; restart Windows, then remove the remaining Program Files/WINDOWS-UNLOCK-Password folder. Normal PIN/Password are preserved.';return}
  foreach($taskFile in @('password-install.json','Uninstall-PasswordUnlock.ps1','Password-Helpers.ps1')){Remove-Item -LiteralPath (Join-Path $taskPasswordTarget $taskFile) -ErrorAction SilentlyContinue}
  Remove-Item -LiteralPath $taskPasswordTarget -ErrorAction SilentlyContinue
}
Write-Output 'WINDOWS-UNLOCK password mode removed. Normal Windows PIN and Password remain available.'
