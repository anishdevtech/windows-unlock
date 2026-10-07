[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$PairedConfig=(Join-Path $env:LOCALAPPDATA 'WINDOWS-UNLOCK\hosted\windows-config.dpapi'),[switch]$DevelopmentBuild,[switch]$RecoveryVerified,[switch]$EnrollOnly)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskInstaller=Join-Path $taskRoot 'windows\installer\Install-PasswordUnlock.ps1'
$taskServiceName='WindowsUnlockPasswordService'
$taskSetup=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WINDOWS-UNLOCK-Password\PhoneUnlockPasswordSetup.exe'
if(-not(Test-Path -LiteralPath $PairedConfig)){throw 'Pair the desktop companion and Android app first. Paired DPAPI configuration was not found.'}
if(-not $PSCmdlet.ShouldProcess('This Windows account','Stage native components, open LOCAL masked password enrollment, then register extra phone sign-in tile')){return}
if(-not(Test-Path -LiteralPath $taskSetup)){& $taskInstaller -Stage Prepare -DevelopmentBuild:$DevelopmentBuild -RecoveryVerified:$RecoveryVerified}
$taskInstalledService=Get-Service -Name $taskServiceName -ErrorAction SilentlyContinue
if($taskInstalledService){Stop-Service -Name $taskServiceName;$taskInstalledService.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
try{
  $taskSetupProcess=Start-Process -FilePath $taskSetup -ArgumentList @('--config',('"'+[IO.Path]::GetFullPath($PairedConfig)+'"')) -Wait -PassThru
  if($taskSetupProcess.ExitCode){throw 'Local enrollment did not complete. Normal Windows PIN/Password are unchanged.'}
}finally{if($taskInstalledService){Start-Service -Name $taskServiceName}}
if(-not $EnrollOnly -and -not $taskInstalledService){& $taskInstaller -Stage Install -RecoveryVerified:$RecoveryVerified}
Write-Output 'Enrollment completed. Phone approval can now release the locally encrypted password when the extra tile is selected.'
