[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$SourceDirectory,[switch]$DevelopmentBuild,[switch]$RecoveryVerified,[ValidateSet('On','Off','Keep')][string]$AutomaticRequests='Keep')
$ErrorActionPreference='Stop'
# ASCII source for Windows PowerShell 5.1. Updates only an existing owned install.
. (Join-Path $PSScriptRoot 'Password-Helpers.ps1')
Assert-PasswordAdmin
if(-not $RecoveryVerified){throw 'Verify normal Windows PIN and Password first, then pass -RecoveryVerified.'}
$taskManifest=Get-PasswordManifest
$taskBefore=Get-PasswordProviderInventory
foreach($taskGuid in @('{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}','{D6886603-9D2F-4EB2-B667-1971041FA96B}')){
  $taskKey=Join-Path $taskPasswordProviders $taskGuid
  if(-not(Test-Path -LiteralPath $taskKey) -or (Get-Item -LiteralPath $taskKey).GetValue('Disabled') -eq 1){throw 'Normal Windows PIN or Password provider is unavailable. Nothing updated.'}
}
$taskService=Get-CimInstance Win32_Service -Filter "Name='WindowsUnlockPasswordService'"
$taskExe=Join-Path $taskPasswordTarget 'PhoneUnlockPasswordService.exe'
$taskDll=Join-Path $taskPasswordTarget 'CredentialProviderPassword.dll'
$taskInproc=Join-Path $taskPasswordClsid 'InprocServer32'
if(-not $taskService -or $taskService.StartName -ne 'LocalSystem' -or $taskService.PathName -ne ('"'+$taskExe+'"') -or -not(Test-Path -LiteralPath $taskPasswordProvider) -or -not(Test-Path -LiteralPath $taskInproc) -or (Get-Item -LiteralPath $taskInproc).GetValue('') -ne $taskDll){throw 'Owned service/provider registration mismatch. Use recovery; nothing updated.'}
if(Get-Process -Name LogonUI -ErrorAction SilentlyContinue){throw 'The sign-in DLL may be loaded. Sign in normally and retry the update from the unlocked desktop. Do not terminate LogonUI.'}
if(-not $SourceDirectory){$taskBundle=Join-Path (Split-Path -Parent $PSScriptRoot) 'Release';if(Test-Path -LiteralPath $taskBundle){$SourceDirectory=$taskBundle}else{$SourceDirectory=Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'build\windows\Release'}}
Assert-PasswordPlainPath $SourceDirectory
if([IO.Path]::GetFullPath($SourceDirectory).TrimEnd('\') -eq [IO.Path]::GetFullPath($taskPasswordTarget).TrimEnd('\')){throw 'Update source must be separate from the installed directory.'}
$taskHashes=@{}
foreach($taskFile in $taskPasswordPayload){$taskPath=Join-Path $SourceDirectory $taskFile;Assert-PasswordPlainPath $taskPath;if(-not $DevelopmentBuild -and (Get-AuthenticodeSignature -LiteralPath $taskPath).Status -ne 'Valid'){throw 'Trusted publisher signature required, or -DevelopmentBuild for the personal unsigned prototype.'};$taskHashes[$taskFile]=(Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash}
$taskVaultRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'WINDOWS-UNLOCK-Password'
$taskVault=Join-Path $taskVaultRoot 'vault.dpapi'
Assert-PasswordPlainPath $taskVault
foreach($taskPath in @($taskVaultRoot,$taskVault)){
  $taskAcl=Get-Acl -LiteralPath $taskPath
  if(-not $taskAcl.AreAccessRulesProtected -or $taskAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Untrusted vault owner or unprotected ACL.'}
  foreach($taskRule in $taskAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($taskRule.AccessControlType -ne 'Allow' -or $taskRule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Vault or backup would be accessible outside SYSTEM/Administrators.'}}
}
Invoke-PasswordNativeCheck (Join-Path $taskPasswordTarget 'PhoneUnlockPasswordCheck.exe') @() 'Existing encrypted enrollment is invalid. Nothing updated.'
if(-not $PSCmdlet.ShouldProcess($taskPasswordTarget,'Update owned native binaries, preserve encrypted enrollment and Microsoft sign-in options')){return}
$taskId=[Guid]::NewGuid().ToString('N')
$taskStage=Join-Path $taskPasswordTarget ('update-'+$taskId)
$taskBackup=Join-Path $taskStage 'previous'
$taskVaultBackup=Join-Path $taskVaultRoot ('vault-before-update-'+$taskId+'.dpapi')
$taskServiceWasRunning=$taskService.State -eq 'Running'
$taskStopped=$false;$taskChanged=$false;$taskDone=$false
$taskOwnedFiles=$taskPasswordPayload+@('password-install.json','Uninstall-PasswordUnlock.ps1','Password-Helpers.ps1')
try{
  New-Item -ItemType Directory -Path $taskStage | Out-Null
  New-Item -ItemType Directory -Path $taskBackup | Out-Null
  foreach($taskFile in $taskPasswordPayload){$taskPath=Join-Path $taskStage $taskFile;Copy-Item -LiteralPath (Join-Path $SourceDirectory $taskFile) -Destination $taskPath;if((Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash -ne $taskHashes[$taskFile]){throw 'Build changed while staging.'};if(-not $DevelopmentBuild -and (Get-AuthenticodeSignature -LiteralPath $taskPath).Status -ne 'Valid'){throw 'Staged publisher signature is invalid.'}}
  Invoke-PasswordNativeCheck (Join-Path $taskStage 'PhoneUnlockPasswordCheck.exe') @() 'New build cannot read the existing encrypted enrollment.'
  Invoke-PasswordNativeCheck (Join-Path $taskStage 'vault_tests.exe') @('--machine') 'New cryptography checks failed.'
  Invoke-PasswordNativeCheck (Join-Path $taskStage 'password_provider_tests.exe') @((Join-Path $taskStage 'CredentialProviderPassword.dll')) 'New provider COM/fallback checks failed.'
  foreach($taskFile in $taskOwnedFiles){Copy-Item -LiteralPath (Join-Path $taskPasswordTarget $taskFile) -Destination (Join-Path $taskBackup $taskFile)}
  # The encrypted backup stays in the existing SYSTEM/Administrators-only vault folder.
  Copy-Item -LiteralPath $taskVault -Destination $taskVaultBackup
  $taskStopped=$true;Stop-Service -Name $taskPasswordService
  (Get-Service -Name $taskPasswordService).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
  Invoke-PasswordNativeCheck (Join-Path $taskStage 'password_ipc_tests.exe') @() 'New V4 IPC checks failed.'
  if(Get-Process -Name LogonUI -ErrorAction SilentlyContinue){throw 'Windows started its sign-in UI during update. Retry from the unlocked desktop.'}
  # Refuse a loaded image before replacing any file. Never kill Windows sign-in UI.
  foreach($taskFile in $taskPasswordPayload){$taskHandle=$null;try{$taskHandle=[IO.File]::Open((Join-Path $taskPasswordTarget $taskFile),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}finally{if($taskHandle){$taskHandle.Dispose()}}}
  $taskChanged=$true
  foreach($taskFile in $taskPasswordPayload){Copy-Item -LiteralPath (Join-Path $taskStage $taskFile) -Destination (Join-Path $taskPasswordTarget $taskFile) -Force}
  foreach($taskFile in @('Uninstall-PasswordUnlock.ps1','Password-Helpers.ps1')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $taskFile) -Destination (Join-Path $taskPasswordTarget $taskFile) -Force}
  @{project='WINDOWS-UNLOCK-Password';providerGuid=$taskPasswordGuid;serviceName=$taskPasswordService;developmentBuild=[bool]$DevelopmentBuild;version='0.5.1';wireVersion=4;hashes=$taskHashes} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $taskPasswordTarget 'password-install.json') -Encoding UTF8
  $null=Get-PasswordManifest
  if($AutomaticRequests -ne 'Keep'){Invoke-PasswordNativeCheck (Join-Path $taskPasswordTarget 'PhoneUnlockPasswordCheck.exe') @('--automatic-requests',$AutomaticRequests.ToLowerInvariant()) 'Cannot change automatic requests. Use the enrolled Windows account.'}
  Invoke-PasswordNativeCheck (Join-Path $taskPasswordTarget 'PhoneUnlockPasswordCheck.exe') @('--status') 'Updated enrollment validation failed.'
  Start-Service -Name $taskPasswordService
  (Get-Service -Name $taskPasswordService).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
  if((Get-PasswordProviderInventory) -ne $taskBefore){throw 'Another sign-in provider changed during update.'}
  $taskDone=$true
  Write-Output 'Updated to 0.5.1. Encrypted enrollment and pairing preserved. Automatic requests use the protected policy shown above. Normal Windows PIN/Password remain available.'
}catch{
  $taskUpdateFailure=$_
  if($taskStopped){
    try{
      Stop-Service -Name $taskPasswordService -ErrorAction SilentlyContinue
      (Get-Service -Name $taskPasswordService).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
      if($taskChanged){foreach($taskFile in $taskOwnedFiles){Copy-Item -LiteralPath (Join-Path $taskBackup $taskFile) -Destination (Join-Path $taskPasswordTarget $taskFile) -Force};Copy-Item -LiteralPath $taskVaultBackup -Destination $taskVault -Force}
      if($taskServiceWasRunning){Start-Service -Name $taskPasswordService;(Get-Service -Name $taskPasswordService).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))}
      Write-Warning 'Previous native build/enrollment restored. Normal PIN/Password remain available.'
    }catch{throw "Update and rollback could not finish. Use normal Windows PIN/Password and Recover-PasswordUnlock.ps1. Protected backups retained at $taskStage and $taskVaultBackup."}
  }
  throw $taskUpdateFailure
}finally{
  if($taskDone){
    # Checked absolute, task-owned paths only; never recurse outside this install.
    Assert-PasswordTarget
    if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($taskStage)) -ne [IO.Path]::GetFullPath($taskPasswordTarget) -or [IO.Path]::GetFileName($taskStage) -notmatch '^update-[0-9a-f]{32}$'){throw 'Unexpected update staging path.'}
    Assert-PasswordPlainPath $taskStage
    Remove-Item -LiteralPath $taskStage -Recurse -Force
    Remove-Item -LiteralPath $taskVaultBackup -Force
  }
}
