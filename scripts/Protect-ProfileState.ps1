param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference="Stop"
$taskState=[IO.Path]::GetFullPath($Path)
$taskSid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$taskExistingAcl=Get-Acl -LiteralPath $taskState
if($taskExistingAcl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $taskSid){throw 'Hosted state must belong to the current Windows user. Existing pairing was preserved.'}
foreach($taskDirectory in @($taskState,(Split-Path -Parent $taskState))){if((Get-Item -LiteralPath $taskDirectory).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Hosted state must not be a redirected directory.'}}
$taskAcl=New-Object Security.AccessControl.DirectorySecurity
$taskAcl.SetAccessRuleProtection($true,$false)
$taskRule=New-Object Security.AccessControl.FileSystemAccessRule($taskSid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
$taskAcl.AddAccessRule($taskRule)
$taskRules=@($taskExistingAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
$taskAclCorrect=$taskExistingAcl.AreAccessRulesProtected -and $taskRules.Count -eq 1 -and
  $taskRules[0].IdentityReference -eq $taskSid -and $taskRules[0].AccessControlType -eq 'Allow' -and
  $taskRules[0].FileSystemRights -eq 'FullControl' -and $taskRules[0].InheritanceFlags -eq 'ContainerInherit, ObjectInherit'
if(-not $taskAclCorrect){
  # Apply only the DACL: PowerShell Set-Acl on a new descriptor can also request
  # audit/owner privileges. No SACL or owner change is needed for this user profile.
  if(-not ('WindowsUnlockProfileAcl' -as [type])){Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WindowsUnlockProfileAcl {
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,out bool present,out IntPtr dacl,out bool defaulted);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint SetNamedSecurityInfoW(string path,int type,uint flags,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
  public static void Apply(string path,byte[] descriptor) {
    var handle=GCHandle.Alloc(descriptor,GCHandleType.Pinned);
    try { bool present,defaulted;IntPtr dacl;
      if(!GetSecurityDescriptorDacl(handle.AddrOfPinnedObject(),out present,out dacl,out defaulted)||!present||dacl==IntPtr.Zero)throw new InvalidOperationException("Protected DACL unavailable");
      if(SetNamedSecurityInfoW(path,1,0x80000004,IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero)!=0)throw new InvalidOperationException("Cannot protect hosted state DACL");
    } finally { handle.Free(); }
  }
}
'@}
  [WindowsUnlockProfileAcl]::Apply($taskState,$taskAcl.GetSecurityDescriptorBinaryForm())
}
