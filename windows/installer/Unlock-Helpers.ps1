$taskUnlockGuid='{45BEC8E2-1359-48D6-9587-963FB93D6071}'
$taskUnlockService='WindowsUnlockService'
$taskUnlockPackage='WindowsUnlockAuth'
$taskUnlockLsaKey='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$taskUnlockTarget=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WINDOWS-UNLOCK-SignIn'
$taskUnlockLsaDll=Join-Path ([Environment]::SystemDirectory) 'WindowsUnlockAuth.dll'
$taskUnlockProviders='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$taskUnlockProvider=Join-Path $taskUnlockProviders $taskUnlockGuid
$taskUnlockClsid="HKLM:\SOFTWARE\Classes\CLSID\$taskUnlockGuid"
function Assert-UnlockAdmin {
  $taskIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
  if(-not([Security.Principal.WindowsPrincipal]$taskIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated administrator required.'}
  if(-not [Environment]::Is64BitProcess){throw 'Use 64-bit PowerShell.'}
}
function Assert-UnlockVm {
  $taskComputer=Get-CimInstance Win32_ComputerSystem
  if($taskComputer.Model -notmatch 'Virtual Machine|VMware|VirtualBox|KVM|QEMU|HVM|Parallels'){throw 'Physical machine refused. This release requires a disposable Windows 11 VM.'}
}
function Assert-UnlockPlainPath([string]$Path) {
  $taskItem=Get-Item -LiteralPath $Path
  while($taskItem){if($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse path refused.'};if($taskItem -is [IO.FileInfo]){$taskItem=$taskItem.Directory}else{$taskItem=$taskItem.Parent}}
}
function Assert-UnlockSignature([string]$Path,[switch]$MicrosoftLsa) {
  Assert-UnlockPlainPath $Path
  $taskSignature=Get-AuthenticodeSignature -LiteralPath $Path
  if($taskSignature.Status -ne 'Valid'){throw "Trusted embedded signature required: $([IO.Path]::GetFileName($Path))"}
  if($MicrosoftLsa -and $taskSignature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)'){throw 'Use the Microsoft-returned LSA binary; an ordinary publisher signature is insufficient.'}
  # The final protected-LSA decision belongs to Windows Code Integrity, after reboot.
}
function Get-UnlockSecurityPackages {
  $taskKey=Get-Item -LiteralPath $taskUnlockLsaKey
  if($taskKey.GetValueKind('Security Packages') -ne [Microsoft.Win32.RegistryValueKind]::MultiString){throw 'Unexpected LSA Security Packages registry type. Nothing changed.'}
  return ,([string[]]$taskKey.GetValue('Security Packages'))
}
function Set-UnlockPackageEntry([bool]$Present) {
  $taskPackages=Get-UnlockSecurityPackages
  $taskKept=@($taskPackages | Where-Object {$_ -ine $taskUnlockPackage})
  if($Present){$taskKept+= $taskUnlockPackage}
  # Read current values each time; never restore an old complete list over newer providers.
  Set-ItemProperty -LiteralPath $taskUnlockLsaKey -Name 'Security Packages' -Value ([string[]]$taskKept)
}
function New-UnlockProtectedDirectory([string]$Path) {
  Assert-UnlockPlainPath (Split-Path -Parent $Path)
  New-Item -ItemType Directory -Path $Path | Out-Null
  $taskAcl=New-Object Security.AccessControl.DirectorySecurity
  $taskAcl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
  $taskAcl.SetAccessRuleProtection($true,$false)
  foreach($taskSid in @('S-1-5-18','S-1-5-32-544')){$taskAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($taskSid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
  $taskAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
  Set-Acl -LiteralPath $Path -AclObject $taskAcl
}
function Assert-UnlockManifest {
  Assert-UnlockPlainPath $taskUnlockTarget
  $taskMarker=Join-Path $taskUnlockTarget 'unlock-install.json'
  Assert-UnlockPlainPath $taskMarker
  $taskManifest=Get-Content -Raw -LiteralPath $taskMarker | ConvertFrom-Json
  if($taskManifest.project -ne 'WINDOWS-UNLOCK-SignIn' -or $taskManifest.providerGuid -ne $taskUnlockGuid -or $taskManifest.serviceName -ne $taskUnlockService -or $taskManifest.packageName -ne $taskUnlockPackage){throw 'Owned installation marker missing or invalid. Nothing changed.'}
  return $taskManifest
}
