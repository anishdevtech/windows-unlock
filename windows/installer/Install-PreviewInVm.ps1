[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$DisposableVm,[switch]$RecoveryVerified,[switch]$AllowUnsignedDevelopmentBuilds)
$ErrorActionPreference='Stop'
$taskGuid='{8EE2412C-28C7-4F11-A7CD-2A99F95C8C11}'
$taskService='WindowsUnlockPreviewService'
if(-not $DisposableVm -or -not $RecoveryVerified){throw 'Preview only: explicitly confirm a disposable VM and tested Windows PIN/password recovery. Nothing installed.'}
$taskComputer=Get-CimInstance Win32_ComputerSystem
if($taskComputer.Model -notmatch 'Virtual Machine|VMware|VirtualBox|KVM|QEMU|HVM|Parallels'){throw 'Physical machine refused. This installer is only for a disposable VM; no Windows settings changed.'}
$taskIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not([Security.Principal.WindowsPrincipal]$taskIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run elevated inside the disposable VM under the same Windows account used for pairing.'}
$taskRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$taskSource=Join-Path $taskRoot 'build\windows\Release'
$taskTarget=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WINDOWS-UNLOCK-ApprovalPreview'
$taskClsid="HKLM:\SOFTWARE\Classes\CLSID\$taskGuid"
$taskProviders='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$taskProvider=Join-Path $taskProviders $taskGuid
$taskPayload=@('CredentialProviderPreview.dll','PhoneUnlockPreviewService.exe','PhoneUnlockPreviewStage.exe')
$taskExpectedHashes=@{}
foreach($taskFile in $taskPayload){
  $taskPath=Join-Path $taskSource $taskFile
  if(-not(Test-Path -LiteralPath $taskPath)){throw "Build required: $taskFile"}
  if(-not $AllowUnsignedDevelopmentBuilds -and (Get-AuthenticodeSignature -LiteralPath $taskPath).Status -ne 'Valid'){throw 'Trusted publisher signatures required. Unsigned development builds are an explicit VM-only choice; OS security policy is never changed.'}
  $taskExpectedHashes[$taskFile]=(Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash
}
if((Test-Path -LiteralPath $taskTarget) -or (Test-Path -LiteralPath $taskClsid) -or (Test-Path -LiteralPath $taskProvider) -or (Get-Service -Name $taskService -ErrorAction SilentlyContinue)){throw 'Existing installation or project-owned key found. Refusing to overwrite.'}
if(-not(Test-Path -LiteralPath $taskProviders)){throw 'Windows Credential Provider configuration unavailable.'}
$taskBefore=@(Get-ChildItem -LiteralPath $taskProviders | ForEach-Object {$_.PSChildName} | Sort-Object)
if(-not $PSCmdlet.ShouldProcess('Disposable VM only','Install approval-preview service and additional tile; Windows login remains disabled')){return}
$taskCreatedService=$false;$taskCreatedCom=$false;$taskCreatedProvider=$false;$taskCreatedFiles=$false
try{
  New-Item -ItemType Directory -Path $taskTarget | Out-Null;$taskCreatedFiles=$true
  $taskAcl=New-Object Security.AccessControl.DirectorySecurity
  $taskAdministrators=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $taskAcl.SetOwner($taskAdministrators);$taskAcl.SetAccessRuleProtection($true,$false)
  foreach($taskSid in @('S-1-5-18','S-1-5-32-544')){$taskAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($taskSid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
  $taskAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
  Set-Acl -LiteralPath $taskTarget -AclObject $taskAcl
  foreach($taskFile in $taskPayload){
    $taskInstalledPath=Join-Path $taskTarget $taskFile
    Copy-Item -LiteralPath (Join-Path $taskSource $taskFile) -Destination $taskInstalledPath
    if((Get-FileHash -LiteralPath $taskInstalledPath -Algorithm SHA256).Hash -ne $taskExpectedHashes[$taskFile]){throw 'Payload changed after preflight; verification failed'}
    # Authenticate the copied, ACL-protected file, not just the mutable build directory.
    if(-not $AllowUnsignedDevelopmentBuilds -and (Get-AuthenticodeSignature -LiteralPath $taskInstalledPath).Status -ne 'Valid'){throw 'Installed payload signature verification failed'}
  }
  @{project='WINDOWS-UNLOCK-ApprovalPreview';providerGuid=$taskGuid;serviceName=$taskService;windowsSignInEnabled=$false;payload=$taskPayload} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskTarget 'preview-install.json') -Encoding UTF8
  New-Service -Name $taskService -BinaryPathName ('"'+(Join-Path $taskTarget 'PhoneUnlockPreviewService.exe')+'"') -DisplayName 'WINDOWS-UNLOCK approval preview' -StartupType Automatic | Out-Null;$taskCreatedService=$true
  Start-Service -Name $taskService
  New-Item -Path $taskClsid -Force | Out-Null;$taskCreatedCom=$true
  $taskInproc=Join-Path $taskClsid 'InprocServer32';New-Item -Path $taskInproc | Out-Null
  Set-Item -LiteralPath $taskInproc -Value (Join-Path $taskTarget 'CredentialProviderPreview.dll')
  New-ItemProperty -LiteralPath $taskInproc -Name ThreadingModel -Value Apartment -PropertyType String | Out-Null
  New-Item -Path $taskProvider | Out-Null;$taskCreatedProvider=$true;Set-Item -LiteralPath $taskProvider -Value 'WINDOWS-UNLOCK approval preview'
  $taskAfter=@(Get-ChildItem -LiteralPath $taskProviders | Where-Object PSChildName -ne $taskGuid | ForEach-Object {$_.PSChildName} | Sort-Object)
  if(Compare-Object $taskBefore $taskAfter){throw 'Provider inventory changed unexpectedly'}
  Write-Output 'Disposable VM approval preview installed. Select its tile to test transport. Approval does not sign in; choose Windows PIN. No LSA package, provider filter or default-provider override installed.'
}catch{
  if($taskCreatedProvider){Remove-Item -LiteralPath $taskProvider -ErrorAction SilentlyContinue}
  if($taskCreatedCom){Remove-Item -LiteralPath (Join-Path $taskClsid 'InprocServer32') -ErrorAction SilentlyContinue;Remove-Item -LiteralPath $taskClsid -ErrorAction SilentlyContinue}
  if($taskCreatedService){Stop-Service -Name $taskService -ErrorAction SilentlyContinue;& sc.exe delete $taskService | Out-Null}
  if($taskCreatedFiles){foreach($taskFile in ($taskPayload+@('preview-install.json'))){Remove-Item -LiteralPath (Join-Path $taskTarget $taskFile) -ErrorAction SilentlyContinue};Remove-Item -LiteralPath $taskTarget -ErrorAction SilentlyContinue}
  throw 'Preview installation failed; rollback attempted for only project-owned entries. Use normal Windows PIN/password. Check VM recovery before retrying.'
}
