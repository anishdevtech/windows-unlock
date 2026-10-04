[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Register','Activate')][string]$Phase,
  [string]$MicrosoftSignedLsaPath,
  [switch]$DisposableVm,[switch]$RecoveryVerified
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Unlock-Helpers.ps1')
if(-not $DisposableVm -or -not $RecoveryVerified){throw 'Confirm a disposable VM checkpoint and successfully tested Windows PIN/password recovery.'}
Assert-UnlockVm;Assert-UnlockAdmin
$taskRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$taskSource=Join-Path $taskRoot 'build\windows\Release'
$taskPayload=@('CredentialProvider.dll','PhoneUnlockService.exe','PhoneUnlockStage.exe')
$taskBefore=@(Get-ChildItem -LiteralPath $taskUnlockProviders | ForEach-Object PSChildName | Sort-Object)
if($Phase -eq 'Activate'){
  $taskManifest=Assert-UnlockManifest
  if((Test-Path -LiteralPath $taskUnlockProvider) -or (Test-Path -LiteralPath $taskUnlockClsid) -or (Get-Service -Name $taskUnlockService -ErrorAction SilentlyContinue)){throw 'Provider/service already exists. Uninstall before changing this release.'}
  foreach($taskFile in $taskPayload){$taskPath=Join-Path $taskUnlockTarget $taskFile;Assert-UnlockSignature $taskPath;if((Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash -ne $taskManifest.hashes.$taskFile){throw 'Installed payload hash mismatch.'}}
  Assert-UnlockSignature $taskUnlockLsaDll -MicrosoftLsa
  if((Get-FileHash -LiteralPath $taskUnlockLsaDll -Algorithm SHA256).Hash -ne $taskManifest.lsaHash -or -not((Get-UnlockSecurityPackages) -icontains $taskUnlockPackage)){throw 'LSA payload/registration mismatch.'}
  & (Join-Path $taskUnlockTarget 'PhoneUnlockStage.exe') --check-auth-package
  if($LASTEXITCODE){throw 'Reboot and confirm protected LSA loaded the package before activating the tile.'}
  $taskEnrollment=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'WINDOWS-UNLOCK-SignIn'
  foreach($taskFile in @('enrollment.dpapi','trust.json')){Assert-UnlockPlainPath (Join-Path $taskEnrollment $taskFile)}
  if(-not $PSCmdlet.ShouldProcess('Disposable VM','Activate additional phone-unlock tile and LocalSystem broker')){return}
  $taskCreatedService=$false;$taskCreatedCom=$false;$taskCreatedProvider=$false
  try{
    New-Service -Name $taskUnlockService -BinaryPathName ('"'+(Join-Path $taskUnlockTarget 'PhoneUnlockService.exe')+'"') -DisplayName 'WINDOWS-UNLOCK phone sign-in' -StartupType Automatic | Out-Null;$taskCreatedService=$true
    Start-Service -Name $taskUnlockService
    New-Item -Path $taskUnlockClsid | Out-Null;$taskCreatedCom=$true
    $taskInproc=Join-Path $taskUnlockClsid 'InprocServer32';New-Item -Path $taskInproc | Out-Null
    Set-Item -LiteralPath $taskInproc -Value (Join-Path $taskUnlockTarget 'CredentialProvider.dll')
    New-ItemProperty -LiteralPath $taskInproc -Name ThreadingModel -Value Apartment -PropertyType String | Out-Null
    New-Item -Path $taskUnlockProvider | Out-Null;$taskCreatedProvider=$true
    Set-Item -LiteralPath $taskUnlockProvider -Value 'Unlock with Phone'
    $taskAfter=@(Get-ChildItem -LiteralPath $taskUnlockProviders | Where-Object PSChildName -ne $taskUnlockGuid | ForEach-Object PSChildName | Sort-Object)
    if(Compare-Object $taskBefore $taskAfter){throw 'Other providers changed unexpectedly.'}
    Write-Output 'VM tile activated. Test only an existing locked console session. First sign-in after restart uses Windows PIN/password. Microsoft-account compatibility remains to be proven.'
  }catch{
    if($taskCreatedProvider){Remove-Item -LiteralPath $taskUnlockProvider -ErrorAction SilentlyContinue}
    if($taskCreatedCom){Remove-Item -LiteralPath (Join-Path $taskUnlockClsid 'InprocServer32') -ErrorAction SilentlyContinue;Remove-Item -LiteralPath $taskUnlockClsid -ErrorAction SilentlyContinue}
    if($taskCreatedService){Stop-Service -Name $taskUnlockService -ErrorAction SilentlyContinue;& sc.exe delete $taskUnlockService | Out-Null}
    throw 'Activation failed; owned tile/service rollback attempted. LSA registration remains for explicit uninstall. Use normal Windows PIN.'
  }
  return
}
if(-not $MicrosoftSignedLsaPath){throw 'Provide WindowsUnlockAuth.dll downloaded from your Partner Center LSA submission.'}
if([IO.Path]::GetFileName($MicrosoftSignedLsaPath) -ne 'WindowsUnlockAuth.dll'){throw 'Unexpected LSA binary filename.'}
Assert-UnlockSignature $MicrosoftSignedLsaPath -MicrosoftLsa
$taskPackages=Get-UnlockSecurityPackages
if((Test-Path -LiteralPath $taskUnlockTarget) -or (Test-Path -LiteralPath $taskUnlockLsaDll) -or ($taskPackages -icontains $taskUnlockPackage) -or (Test-Path -LiteralPath $taskUnlockClsid) -or (Test-Path -LiteralPath $taskUnlockProvider) -or (Get-Service -Name $taskUnlockService -ErrorAction SilentlyContinue)){throw 'Existing project files/registration found. Refusing overwrite.'}
$taskHashes=@{}
foreach($taskFile in $taskPayload){$taskPath=Join-Path $taskSource $taskFile;Assert-UnlockSignature $taskPath;$taskHashes[$taskFile]=(Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash}
$taskLsaHash=(Get-FileHash -LiteralPath $MicrosoftSignedLsaPath -Algorithm SHA256).Hash
if(-not $PSCmdlet.ShouldProcess('Disposable VM','Copy signed binaries and append the owned LSA Security Packages entry; no tile activation')){return}
$taskFiles=$false;$taskLsaCopied=$false;$taskRegistered=$false
try{
  New-UnlockProtectedDirectory $taskUnlockTarget;$taskFiles=$true
  foreach($taskFile in $taskPayload){$taskPath=Join-Path $taskUnlockTarget $taskFile;Copy-Item -LiteralPath (Join-Path $taskSource $taskFile) -Destination $taskPath;Assert-UnlockSignature $taskPath;if((Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash -ne $taskHashes[$taskFile]){throw 'Payload changed after preflight.'}}
  Copy-Item -LiteralPath $MicrosoftSignedLsaPath -Destination $taskUnlockLsaDll;$taskLsaCopied=$true
  Assert-UnlockSignature $taskUnlockLsaDll -MicrosoftLsa
  if((Get-FileHash -LiteralPath $taskUnlockLsaDll -Algorithm SHA256).Hash -ne $taskLsaHash){throw 'LSA binary changed after preflight.'}
  @{project='WINDOWS-UNLOCK-SignIn';providerGuid=$taskUnlockGuid;serviceName=$taskUnlockService;packageName=$taskUnlockPackage;hashes=$taskHashes;lsaHash=$taskLsaHash} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskUnlockTarget 'unlock-install.json') -Encoding UTF8
  Set-UnlockPackageEntry $true;$taskRegistered=$true
  Write-Output 'Signed LSA package registered in VM. No tile/service activated and no automatic restart. Reboot manually, sign in normally, stage the VM pairing, then run Phase Activate.'
}catch{
  if($taskRegistered){Set-UnlockPackageEntry $false}
  if($taskLsaCopied){Remove-Item -LiteralPath $taskUnlockLsaDll -ErrorAction SilentlyContinue}
  if($taskFiles){foreach($taskFile in ($taskPayload+@('unlock-install.json'))){Remove-Item -LiteralPath (Join-Path $taskUnlockTarget $taskFile) -ErrorAction SilentlyContinue};Remove-Item -LiteralPath $taskUnlockTarget -ErrorAction SilentlyContinue}
  throw 'Registration failed; rollback attempted for project-owned entries only. Keep the VM checkpoint and use Windows PIN/password.'
}
