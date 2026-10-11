[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$CompanionPath,
  [string]$StateDirectory=(Join-Path $env:LOCALAPPDATA 'WINDOWS-UNLOCK\hosted'),
  [switch]$StartWithWindows
)
$ErrorActionPreference='Stop'
$taskExe=(Resolve-Path -LiteralPath $CompanionPath).Path
if([IO.Path]::GetFileName($taskExe) -ne 'phoneunlock.exe'){throw 'Select the WINDOWS-UNLOCK companion executable.'}
$taskState=[IO.Path]::GetFullPath($StateDirectory)
if(-not(Test-Path -LiteralPath (Join-Path $taskState 'windows-config.dpapi') -PathType Leaf)){throw 'Existing companion configuration is required. Pairing is never reset by shortcut setup.'}
$taskPrograms=[Environment]::GetFolderPath('Programs')
$taskDesktop=[Environment]::GetFolderPath('Desktop')
$taskShell=New-Object -ComObject WScript.Shell
function Set-CompanionShortcut([string]$Path,[bool]$Startup) {
  if(Test-Path -LiteralPath $Path){$taskExisting=$taskShell.CreateShortcut($Path);if([IO.Path]::GetFileName($taskExisting.TargetPath) -ne 'phoneunlock.exe'){throw "An unrelated shortcut already exists at $Path"}}
  $taskLink=$taskShell.CreateShortcut($Path)
  $taskLink.TargetPath=$taskExe
  $taskLink.Arguments='--state "'+$taskState+'"'+$(if($Startup){' --startup'}else{''})
  $taskLink.WorkingDirectory=[IO.Path]::GetDirectoryName($taskExe)
  $taskLink.WindowStyle=1
  $taskLink.Description='Windows Unlock - WINDOWS-UNLOCK phone fingerprint approval and laptop controls'
  $taskLink.IconLocation=$taskExe+',0'
  $taskLink.Save()
}
Set-CompanionShortcut (Join-Path $taskPrograms 'Windows Unlock.lnk') $false
Set-CompanionShortcut (Join-Path $taskDesktop 'Windows Unlock.lnk') $false
if($StartWithWindows){
  $taskStartup=[Environment]::GetFolderPath('Startup')
  # Keep the existing owned shortcut name, preventing two startup launches.
  Set-CompanionShortcut (Join-Path $taskStartup 'WINDOWS-UNLOCK Hosted.lnk') $true
}
Write-Output 'Installed Windows Unlock in Start search and on the desktop. Launching it restores the running app. Pairing is preserved.'
