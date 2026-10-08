[CmdletBinding(SupportsShouldProcess=$true)]
param([ValidateSet('Status','Prepare','Install')][string]$Stage='Status',[string]$SourceDirectory,[switch]$DevelopmentBuild,[switch]$RecoveryVerified)
$ErrorActionPreference='Stop'
# Keep this script ASCII so Windows PowerShell 5.1 can read it without a UTF-8 BOM.
. (Join-Path $PSScriptRoot 'Password-Helpers.ps1')
if($Stage -eq 'Status'){
  [pscustomobject]@{mode='phone-controlled-password';serviceInstalled=[bool](Get-Service -Name $taskPasswordService -ErrorAction SilentlyContinue);tileRegistered=Test-Path -LiteralPath $taskPasswordProvider;vaultPresent=Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'WINDOWS-UNLOCK-Password\vault.dpapi');customLsaRequired=$false;appControl=Get-PasswordAppControlStatus;systemProviders=Get-PasswordProviderInventory}
  return
}
Assert-PasswordAdmin
if(-not $RecoveryVerified){throw 'First verify normal Windows PIN and Password recovery, then pass -RecoveryVerified. No authentication changes made.'}
if(-not(Test-Path -LiteralPath $taskPasswordProviders)){throw 'Windows Credential Providers are unavailable.'}
$taskPasswordKey=Join-Path $taskPasswordProviders '{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}'
if(-not(Test-Path -LiteralPath $taskPasswordKey) -or (Get-Item -LiteralPath $taskPasswordKey).GetValue('Disabled') -eq 1){throw 'Normal Windows Password provider is unavailable. Nothing changed.'}
$taskPinKey=Join-Path $taskPasswordProviders '{D6886603-9D2F-4EB2-B667-1971041FA96B}'
if(-not(Test-Path -LiteralPath $taskPinKey) -or (Get-Item -LiteralPath $taskPinKey).GetValue('Disabled') -eq 1){throw 'Windows Hello PIN provider is unavailable. Nothing changed.'}
$taskBefore=Get-PasswordProviderInventory
if($Stage -eq 'Prepare'){
  if(-not $SourceDirectory){$taskBundle=Join-Path (Split-Path -Parent $PSScriptRoot) 'Release';if(Test-Path -LiteralPath $taskBundle){$SourceDirectory=$taskBundle}else{$SourceDirectory=Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'build\windows\Release'}}
  Assert-PasswordPlainPath $SourceDirectory
  if((Test-Path -LiteralPath $taskPasswordTarget) -or (Test-Path -LiteralPath $taskPasswordClsid) -or (Test-Path -LiteralPath $taskPasswordProvider) -or (Get-Service -Name $taskPasswordService -ErrorAction SilentlyContinue)){throw 'Existing installation found. Use its uninstall/recovery script before preparing a different build.'}
  $taskHashes=@{}
  foreach($taskFile in $taskPasswordPayload){$taskPath=Join-Path $SourceDirectory $taskFile;Assert-PasswordPlainPath $taskPath;if(-not $DevelopmentBuild -and (Get-AuthenticodeSignature -LiteralPath $taskPath).Status -ne 'Valid'){throw 'Distributed releases require trusted publisher signatures. For your personal prototype use -DevelopmentBuild; Windows security policies remain enforced.'};$taskHashes[$taskFile]=(Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash}
  if(-not $PSCmdlet.ShouldProcess($taskPasswordTarget,'Stage protected binaries; do not register a sign-in tile or service')){return}
  $taskCreated=$false
  try{
    New-PasswordProtectedDirectory;$taskCreated=$true
    foreach($taskFile in $taskPasswordPayload){$taskPath=Join-Path $taskPasswordTarget $taskFile;Copy-Item -LiteralPath (Join-Path $SourceDirectory $taskFile) -Destination $taskPath;if((Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash -ne $taskHashes[$taskFile]){throw 'Build changed during staging.'};if(-not $DevelopmentBuild -and (Get-AuthenticodeSignature -LiteralPath $taskPath).Status -ne 'Valid'){throw 'Copied publisher signature is invalid.'}}
    @{project='WINDOWS-UNLOCK-Password';providerGuid=$taskPasswordGuid;serviceName=$taskPasswordService;developmentBuild=[bool]$DevelopmentBuild;version='0.5.1';wireVersion=4;hashes=$taskHashes} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $taskPasswordTarget 'password-install.json') -Encoding UTF8
    Invoke-PasswordNativeCheck (Join-Path $taskPasswordTarget 'PhoneUnlockPasswordCheck.exe') @('--probe') 'Windows blocked the readiness probe or built-in authentication is unavailable.'
    Invoke-PasswordNativeCheck (Join-Path $taskPasswordTarget 'vault_tests.exe') @('--machine') 'Protected native/machine-key cryptography test failed.'
    Invoke-PasswordNativeCheck (Join-Path $taskPasswordTarget 'password_provider_tests.exe') @((Join-Path $taskPasswordTarget 'CredentialProviderPassword.dll')) 'Windows blocked the DLL or Credential Provider fallback checks failed.'
    Invoke-PasswordNativeCheck (Join-Path $taskPasswordTarget 'password_ipc_tests.exe') @() 'V4 IPC authorization/claim/fallback checks failed.'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Uninstall-PasswordUnlock.ps1') -Destination $taskPasswordTarget
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Password-Helpers.ps1') -Destination $taskPasswordTarget
    Write-Output 'Prepared. No tile/service is registered. Run local password enrollment next.'
  }catch{
    if($taskCreated){Assert-PasswordTarget;foreach($taskFile in ($taskPasswordPayload+@('password-install.json','Uninstall-PasswordUnlock.ps1','Password-Helpers.ps1'))){Remove-Item -LiteralPath (Join-Path $taskPasswordTarget $taskFile) -ErrorAction SilentlyContinue};Remove-Item -LiteralPath $taskPasswordTarget -ErrorAction SilentlyContinue}
    throw
  }
  return
}
$taskManifest=Get-PasswordManifest
if(-not $taskManifest.developmentBuild){foreach($taskFile in $taskPasswordPayload){if((Get-AuthenticodeSignature -LiteralPath (Join-Path $taskPasswordTarget $taskFile)).Status -ne 'Valid'){throw 'Trusted publisher signature is no longer valid. Nothing registered.'}}}
if((Test-Path -LiteralPath $taskPasswordClsid) -or (Test-Path -LiteralPath $taskPasswordProvider) -or (Get-Service -Name $taskPasswordService -ErrorAction SilentlyContinue)){throw 'The tile/service is already registered. Nothing changed.'}
Invoke-PasswordNativeCheck (Join-Path $taskPasswordTarget 'PhoneUnlockPasswordCheck.exe') @() 'Local password vault enrollment is required before registering the tile.'
if(-not $PSCmdlet.ShouldProcess('Windows','Register only WINDOWS-UNLOCK password service and extra Credential Provider; preserve normal sign-in options')){return}
$taskMadeService=$false;$taskMadeCom=$false;$taskMadeProvider=$false
try{
  New-Service -Name $taskPasswordService -DisplayName 'WINDOWS-UNLOCK phone sign-in' -Description 'Phone-controlled encrypted password; normal Windows PIN and Password remain available.' -BinaryPathName ('"'+(Join-Path $taskPasswordTarget 'PhoneUnlockPasswordService.exe')+'"') -StartupType Automatic | Out-Null;$taskMadeService=$true
  Start-Service -Name $taskPasswordService
  (Get-Service -Name $taskPasswordService).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
  New-Item -Path $taskPasswordClsid | Out-Null;$taskMadeCom=$true
  $taskInproc=Join-Path $taskPasswordClsid 'InprocServer32';New-Item -Path $taskInproc | Out-Null;Set-Item -LiteralPath $taskInproc -Value (Join-Path $taskPasswordTarget 'CredentialProviderPassword.dll');New-ItemProperty -LiteralPath $taskInproc -Name ThreadingModel -Value Apartment -PropertyType String | Out-Null
  New-Item -Path $taskPasswordProvider | Out-Null;$taskMadeProvider=$true;Set-Item -LiteralPath $taskPasswordProvider -Value 'Unlock with Phone'
  if((Get-PasswordProviderInventory) -ne $taskBefore){throw 'Other sign-in provider configuration changed unexpectedly.'}
  Write-Output 'Installed additional Unlock with Phone tile. Lock Windows, select Sign-in options > Unlock with Phone, and approve on the phone. Use normal PIN/Password if unavailable.'
}catch{
  if($taskMadeProvider){Remove-Item -LiteralPath $taskPasswordProvider -ErrorAction SilentlyContinue}
  if($taskMadeCom){Remove-Item -LiteralPath (Join-Path $taskPasswordClsid 'InprocServer32') -ErrorAction SilentlyContinue;Remove-Item -LiteralPath $taskPasswordClsid -ErrorAction SilentlyContinue}
  if($taskMadeService){Stop-Service -Name $taskPasswordService -ErrorAction SilentlyContinue;& sc.exe delete $taskPasswordService | Out-Null}
  throw 'Installation failed. Rollback removed only project-owned registry/service entries; protected staging and enrollment remain for retry. Use Windows PIN/Password.'
}
