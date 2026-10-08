$taskPasswordGuid='{59D7E749-F07A-4549-9756-E87C0355B532}'
$taskPasswordService='WindowsUnlockPasswordService'
$taskPasswordTarget=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WINDOWS-UNLOCK-Password'
$taskPasswordProviders='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$taskPasswordProvider=Join-Path $taskPasswordProviders $taskPasswordGuid
$taskPasswordClsid="HKLM:\SOFTWARE\Classes\CLSID\$taskPasswordGuid"
$taskPasswordPayload=@('CredentialProviderPassword.dll','PhoneUnlockPasswordService.exe','PhoneUnlockPasswordSetup.exe','PhoneUnlockPasswordCheck.exe','password_provider_tests.exe','password_ipc_tests.exe','vault_tests.exe')
function Get-PasswordAppControlStatus {
  $taskPolicy=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue
  $taskState='Unknown'
  if($taskPolicy){switch($taskPolicy.VerifiedAndReputablePolicyState){0{$taskState='Off'}1{$taskState='On'}2{$taskState='Evaluation'}}}
  [pscustomobject]@{smartAppControl=$taskState;settingPath='Windows Security > App & browser control > Smart App Control settings';perAppExemptionAvailable=$false;settingsChanged=$false}
}
function Get-PasswordLaunchFailure([string]$Program) {
  $taskPolicy=Get-PasswordAppControlStatus
  if($taskPolicy.smartAppControl -eq 'On'){
    return "Windows could not launch $Program. Smart App Control is On; unsigned files may be blocked. Use a trusted publisher-signed build. For an unsigned personal-development test, the user may choose Off at $($taskPolicy.settingPath); this reduces protection system-wide and is not a per-app exemption. The installer never changes that setting. Normal Windows PIN/Password are preserved."
  }
  return "Windows could not launch $Program. Check Microsoft-Windows-CodeIntegrity/Operational events 3077/3033 for another App Control policy or signing block. No sign-in tile was registered by this preflight; normal Windows PIN/Password remain available."
}
function Invoke-PasswordNativeCheck([string]$Program,[string[]]$Arguments,[string]$Failure) {
  try { & $Program @Arguments; $taskExit=$LASTEXITCODE }
  catch { throw (Get-PasswordLaunchFailure ([IO.Path]::GetFileName($Program))) }
  if($taskExit -ne 0){throw $Failure}
}
function Assert-PasswordAdmin {
  if(-not [Environment]::Is64BitProcess){throw 'Use 64-bit PowerShell.'}
  $taskPrincipal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if(-not $taskPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run 64-bit PowerShell as administrator under your paired Windows account.'}
}
function Assert-PasswordPlainPath([string]$Path) {
  $taskItem=Get-Item -LiteralPath $Path
  while($taskItem){if($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Redirected/reparse path refused.'};if($taskItem -is [IO.FileInfo]){$taskItem=$taskItem.Directory}else{$taskItem=$taskItem.Parent}}
}
function Assert-PasswordTarget {
  $taskExpected=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WINDOWS-UNLOCK-Password'
  if([IO.Path]::GetFullPath($taskPasswordTarget) -ne [IO.Path]::GetFullPath($taskExpected)){throw 'Unexpected installation target.'}
  Assert-PasswordPlainPath $taskPasswordTarget
  $taskAcl=Get-Acl -LiteralPath $taskPasswordTarget
  if(-not $taskAcl.AreAccessRulesProtected -or $taskAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Untrusted installation owner or ACL.'}
  foreach($taskRule in $taskAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($taskRule.AccessControlType -ne 'Allow'){throw 'Unexpected installation ACL.'}
    $taskReadOnly=[Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
    if($taskRule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and ($taskRule.IdentityReference.Value -ne 'S-1-5-32-545' -or ($taskRule.FileSystemRights -band (-bnot $taskReadOnly)))){throw 'Installation grants untrusted modification, deletion or ownership access.'}
  }
}
function Get-PasswordManifest([switch]$SkipPayloadCheck) {
  Assert-PasswordTarget
  $taskMarker=Join-Path $taskPasswordTarget 'password-install.json';Assert-PasswordPlainPath $taskMarker
  $taskManifest=Get-Content -Raw -LiteralPath $taskMarker | ConvertFrom-Json
  if($taskManifest.project -ne 'WINDOWS-UNLOCK-Password' -or $taskManifest.providerGuid -ne $taskPasswordGuid -or $taskManifest.serviceName -ne $taskPasswordService){throw 'Installation marker missing or invalid.'}
  if(-not $SkipPayloadCheck){foreach($taskFile in $taskPasswordPayload){$taskPath=Join-Path $taskPasswordTarget $taskFile;Assert-PasswordPlainPath $taskPath;if((Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash -ne $taskManifest.hashes.$taskFile){throw 'Installed file differs from its enrollment manifest.'}}}
  return $taskManifest
}
function Get-PasswordProviderInventory {
  return @(Get-ChildItem -LiteralPath $taskPasswordProviders | Where-Object PSChildName -ne $taskPasswordGuid | ForEach-Object {
    $taskKey=Get-Item -LiteralPath $_.PSPath
    [pscustomobject]@{id=$_.PSChildName;name=$taskKey.GetValue('');disabled=$taskKey.GetValue('Disabled')}
  } | Sort-Object id | ConvertTo-Json -Compress)
}
function New-PasswordProtectedDirectory {
  Assert-PasswordPlainPath (Split-Path -Parent $taskPasswordTarget)
  New-Item -ItemType Directory -Path $taskPasswordTarget | Out-Null
  $taskAcl=New-Object Security.AccessControl.DirectorySecurity
  $taskAcl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')));$taskAcl.SetAccessRuleProtection($true,$false)
  foreach($taskSid in @('S-1-5-18','S-1-5-32-544')){$taskAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($taskSid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
  $taskAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
  try {
    # Apply only owner and protected DACL. Do not request SACL/audit privileges.
    if(-not ('WindowsUnlockPasswordAcl' -as [type])){Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WindowsUnlockPasswordAcl {
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,out bool present,out IntPtr dacl,out bool defaulted);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetSecurityDescriptorOwner(IntPtr descriptor,out IntPtr owner,out bool defaulted);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint SetNamedSecurityInfoW(string path,int type,uint flags,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
  public static void Apply(string path,byte[] descriptor) {
    var handle=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
    try { bool present,defaulted;IntPtr dacl,owner;
      if(!GetSecurityDescriptorDacl(handle.AddrOfPinnedObject(),out present,out dacl,out defaulted)||!present||dacl==IntPtr.Zero||!GetSecurityDescriptorOwner(handle.AddrOfPinnedObject(),out owner,out defaulted)||owner==IntPtr.Zero)throw new InvalidOperationException("Protected security descriptor unavailable");
      if(SetNamedSecurityInfoW(path,1,0x80000005,owner,IntPtr.Zero,dacl,IntPtr.Zero)!=0)throw new InvalidOperationException("Cannot protect installation owner and DACL");
    } finally { handle.Free(); }
  }
}
'@}
    [WindowsUnlockPasswordAcl]::Apply($taskPasswordTarget,$taskAcl.GetSecurityDescriptorBinaryForm())
    Assert-PasswordTarget
  } catch {
    # This directory was just created above. Remove only this empty, checked target.
    Assert-PasswordPlainPath $taskPasswordTarget
    if([IO.Path]::GetFullPath($taskPasswordTarget) -eq [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WINDOWS-UNLOCK-Password'))){Remove-Item -LiteralPath $taskPasswordTarget -ErrorAction SilentlyContinue}
    throw
  }
}
