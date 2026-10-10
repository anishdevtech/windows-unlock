[CmdletBinding()]
param([switch]$UnsignedPrototype)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskOutput=Join-Path $taskRoot 'build\artifacts'
$taskStage=Join-Path $taskOutput ('password-package-'+[Guid]::NewGuid().ToString('N'))
$taskPayload=@('CredentialProviderPassword.dll','PhoneUnlockPasswordService.exe','PhoneUnlockPasswordSetup.exe','PhoneUnlockPasswordCheck.exe','password_provider_tests.exe','password_ipc_tests.exe','vault_tests.exe')
$taskFiles=@{}
foreach($taskName in $taskPayload){$taskFiles["Release/$taskName"]=Join-Path $taskRoot "build\windows\Release\$taskName"}
foreach($taskName in @('Install-PasswordUnlock.ps1','Update-PasswordUnlock.ps1','Uninstall-PasswordUnlock.ps1','Recover-PasswordUnlock.ps1','Password-Helpers.ps1')){$taskFiles["installer/$taskName"]=Join-Path $taskRoot "windows\installer\$taskName"}
foreach($taskName in @('password-unlock-setup.md','password-vault-security.md','password-vault-verification.md','runtime-verification-0.6.md')){$taskFiles["docs/$taskName"]=Join-Path $taskRoot "docs\$taskName"}
$taskFiles['protocol/password-vault-spec.md']=Join-Path $taskRoot 'protocol\password-vault-spec.md'
$taskFiles['scripts/Test-PasswordUnlockReadiness.ps1']=Join-Path $taskRoot 'scripts\Test-PasswordUnlockReadiness.ps1'
# Explicit allowlist: never collect runtime state, pairing, environment or signing files.
foreach($taskEntry in $taskFiles.GetEnumerator()){
  if(-not(Test-Path -LiteralPath $taskEntry.Value -PathType Leaf)){throw "Missing release file: $($taskEntry.Key)"}
  if($taskEntry.Key -match '\.(exe|dll)$' -and -not $UnsignedPrototype -and (Get-AuthenticodeSignature -LiteralPath $taskEntry.Value).Status -ne 'Valid'){throw 'Native release requires trusted publisher signatures. Use -UnsignedPrototype only to package the development build; OS policy remains enforced.'}
}
$taskApkSource=Join-Path $taskRoot 'android\app\build\outputs\apk\debug\app-debug.apk'
if(-not(Test-Path -LiteralPath $taskApkSource -PathType Leaf)){throw 'Build the Android debug APK first.'}
New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
New-Item -ItemType Directory -Path $taskStage | Out-Null
try{
  $taskHashes=@{}
  foreach($taskEntry in $taskFiles.GetEnumerator()){
    $taskDestination=Join-Path $taskStage $taskEntry.Key
    New-Item -ItemType Directory -Path (Split-Path -Parent $taskDestination) -Force | Out-Null
    Copy-Item -LiteralPath $taskEntry.Value -Destination $taskDestination
    $taskHashes[$taskEntry.Key]=(Get-FileHash -LiteralPath $taskDestination -Algorithm SHA256).Hash.ToLowerInvariant()
  }
  $taskCommit=(& git -C $taskRoot rev-parse HEAD).Trim();if($LASTEXITCODE){throw 'Cannot identify source commit.'}
  @{project='WINDOWS-UNLOCK';version='0.6.0';unsignedPrototype=[bool]$UnsignedPrototype;sourceCommit=$taskCommit;sha256=$taskHashes} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $taskStage 'manifest.json') -Encoding UTF8
  @'
WINDOWS-UNLOCK 0.6.0 - automatic phone-request and sign-in handoff update

Start with docs/password-unlock-setup.md. Normal Windows PIN/Password are preserved.
This bundle does not contain or install an LSA authentication package.
No credentials or private configuration are included. Existing pairing is required.
The supplied development binaries are unsigned; Windows can block them.
0xc0e90002 means a Windows integrity-policy violation, not proof of a damaged DLL.
Read the guide for trusted publisher signing or the user-selected Smart App Control
setting for unsigned personal testing. Disabling it reduces protection system-wide.
The installer never changes security settings. Do not rename files or add development
trust roots to evade policy. This bundle has no per-app Smart App Control exemption.
Installer preflight fails before registering a tile if required binaries are blocked.
Real Windows sign-in and Android hardware acceptance remain unverified; see docs.

Run from extracted bundle in administrator PowerShell only after reading the guide:
  .\installer\Install-PasswordUnlock.ps1 -Stage Prepare -DevelopmentBuild -RecoveryVerified
Then use the local masked setup dialog and approve enrollment on the phone.
Register the extra tile only after enrollment succeeds, as described in the guide.

For an existing enrolled 0.5 installation, preserve pairing and encrypted password:
  .\installer\Update-PasswordUnlock.ps1 -DevelopmentBuild -RecoveryVerified -AutomaticRequests On
No new password enrollment is required. Install Android 0.6 for the new UI and overlay.
'@ | Set-Content -LiteralPath (Join-Path $taskStage 'README.txt') -Encoding UTF8
  $taskZip=Join-Path $taskOutput 'WINDOWS-UNLOCK-0.6.0-Windows-prototype.zip'
  Compress-Archive -LiteralPath (Get-ChildItem -LiteralPath $taskStage | ForEach-Object FullName) -DestinationPath $taskZip -Force
  $taskApk=Join-Path $taskOutput 'WINDOWS-UNLOCK-0.6.0-debug.apk'
  Copy-Item -LiteralPath $taskApkSource -Destination $taskApk -Force
  @($taskZip,$taskApk) | ForEach-Object {"$((Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant())  $([IO.Path]::GetFileName($_))"} | Set-Content -LiteralPath (Join-Path $taskOutput 'WINDOWS-UNLOCK-0.6.0-SHA256SUMS.txt') -Encoding ASCII
  Write-Output $taskZip
  Write-Output $taskApk
}finally{
  # Delete only the unique staging directory under the verified artifact output.
  $taskResolved=[IO.Path]::GetFullPath($taskStage)
  if([IO.Path]::GetDirectoryName($taskResolved) -ne [IO.Path]::GetFullPath($taskOutput) -or [IO.Path]::GetFileName($taskResolved) -notmatch '^password-package-[0-9a-f]{32}$'){throw 'Unexpected package staging path.'}
  if(Test-Path -LiteralPath $taskResolved){Remove-Item -LiteralPath $taskResolved -Recurse -Force}
}
