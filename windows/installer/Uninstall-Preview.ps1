[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$RemoveEnrollment)
$ErrorActionPreference='Stop'
$taskGuid='{8EE2412C-28C7-4F11-A7CD-2A99F95C8C11}'
$taskService='WindowsUnlockPreviewService'
$taskTarget=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WINDOWS-UNLOCK-ApprovalPreview'
$taskMarker=Join-Path $taskTarget 'preview-install.json'
if(-not(Test-Path -LiteralPath $taskMarker)){throw 'Owned preview installation marker missing. No registry/service/files changed.'}
if((Get-Item -LiteralPath $taskTarget).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse installation directory refused.'}
$taskManifest=Get-Content -Raw -LiteralPath $taskMarker | ConvertFrom-Json
if($taskManifest.project -ne 'WINDOWS-UNLOCK-ApprovalPreview' -or $taskManifest.providerGuid -ne $taskGuid -or $taskManifest.serviceName -ne $taskService -or $taskManifest.windowsSignInEnabled -ne $false){throw 'Unexpected installation identity. Nothing changed.'}
$taskIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not([Security.Principal.WindowsPrincipal]$taskIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated administrator required to remove this owned preview installation.'}
$taskClsid="HKLM:\SOFTWARE\Classes\CLSID\$taskGuid"
$taskInproc=Join-Path $taskClsid 'InprocServer32'
$taskProvider="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$taskGuid"
if(Test-Path -LiteralPath $taskInproc){if((Get-Item -LiteralPath $taskInproc).GetValue('') -ne (Join-Path $taskTarget 'CredentialProviderPreview.dll')){throw 'Provider registration points outside the owned installation; removal refused.'}}
$taskInstalledService=Get-CimInstance Win32_Service -Filter "Name='$taskService'"
if($taskInstalledService -and $taskInstalledService.PathName -ne ('"'+(Join-Path $taskTarget 'PhoneUnlockPreviewService.exe')+'"')){throw 'Service points outside the owned installation; removal refused.'}
if(-not $PSCmdlet.ShouldProcess('WINDOWS-UNLOCK approval preview only','Remove its tile/service/files; preserve all Microsoft providers')){return}
if(Test-Path -LiteralPath $taskProvider){Remove-Item -LiteralPath $taskProvider}
if(Test-Path -LiteralPath $taskInproc){Remove-Item -LiteralPath $taskInproc}
if(Test-Path -LiteralPath $taskClsid){Remove-Item -LiteralPath $taskClsid}
if($taskInstalledService){Stop-Service -Name $taskService -ErrorAction SilentlyContinue;& sc.exe delete $taskService | Out-Null;if($LASTEXITCODE){throw 'Service deletion failed; tile already removed. Use PIN and finish removal from VM recovery.'}}
if($RemoveEnrollment){
  $taskEnrollment=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'WINDOWS-UNLOCK-ApprovalPreview'
  if(Test-Path -LiteralPath $taskEnrollment){if((Get-Item -LiteralPath $taskEnrollment).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse enrollment directory refused'};Remove-Item -LiteralPath (Join-Path $taskEnrollment 'enrollment.dpapi') -ErrorAction SilentlyContinue;Remove-Item -LiteralPath $taskEnrollment -ErrorAction SilentlyContinue}
}
# No recursive delete: only fixed owned files, leaving unexpected content in place.
$taskRemaining=@()
foreach($taskFile in @('CredentialProviderPreview.dll','PhoneUnlockPreviewService.exe','PhoneUnlockPreviewStage.exe')){
  $taskPath=Join-Path $taskTarget $taskFile
  if(Test-Path -LiteralPath $taskPath){try{Remove-Item -LiteralPath $taskPath}catch{$taskRemaining+=$taskFile}}
}
if($taskRemaining.Count){
  Write-Warning 'Preview tile/service unregistered, but loaded files remain. Ownership marker preserved: sign in with Windows PIN, then retry this uninstaller. No Microsoft provider changed.'
  return
}
Remove-Item -LiteralPath $taskMarker
Remove-Item -LiteralPath $taskTarget -ErrorAction SilentlyContinue
Write-Output 'Preview tile, service and payloads removed. Windows PIN/password and Microsoft providers preserved. Unexpected directory contents, if any, were left in place.'
