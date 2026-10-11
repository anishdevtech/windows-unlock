[CmdletBinding()]
param(
  [string]$CompanionPath=(Join-Path (Split-Path -Parent $PSScriptRoot) 'build\windows\Release\phoneunlock.exe'),
  [switch]$Remove
)
$ErrorActionPreference='Stop'
$taskIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not([Security.Principal.WindowsPrincipal]$taskIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run Wi-Fi setup as administrator to add the app-specific firewall rule.'}
$taskExe=(Resolve-Path -LiteralPath $CompanionPath).Path
if([IO.Path]::GetFileName($taskExe) -ne 'phoneunlock.exe' -or -not(Test-Path -LiteralPath $taskExe -PathType Leaf)){throw 'Select the built WINDOWS-UNLOCK companion executable.'}
$taskHash=[Security.Cryptography.SHA256]::Create()
try{$taskSuffix=([BitConverter]::ToString($taskHash.ComputeHash([Text.Encoding]::UTF8.GetBytes($taskExe.ToLowerInvariant())))).Replace('-','').Substring(0,12)}finally{$taskHash.Dispose()}
$taskName="WindowsUnlockDirectMedia-$taskSuffix"
$taskRule=Get-NetFirewallRule -Name $taskName -ErrorAction SilentlyContinue
if($Remove){if($taskRule){Remove-NetFirewallRule -Name $taskName};Write-Output 'WINDOWS-UNLOCK direct media rule removed.';return}
if($taskRule){Remove-NetFirewallRule -Name $taskName}
# Match only this executable, UDP ephemeral ports and devices on directly attached
# subnets. Public Wi-Fi keeps its existing classification; the firewall stays on.
New-NetFirewallRule -Name $taskName -DisplayName 'WINDOWS-UNLOCK encrypted Wi-Fi audio/video' -Direction Inbound -Action Allow -Enabled True -Profile Any -Program $taskExe -Protocol UDP -LocalPort '49152-65535' -RemoteAddress LocalSubnet | Out-Null
Write-Output 'Encrypted Wi-Fi streaming enabled for this companion and local-subnet devices. Network profiles and all other firewall settings are unchanged.'
