[CmdletBinding(SupportsShouldProcess=$true)]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Password-Helpers.ps1')
Assert-PasswordAdmin
if(-not $PSCmdlet.ShouldProcess('WINDOWS-UNLOCK password mode','Disable only its known additional tile and COM registration, even if binaries or manifest are damaged')){return}
if(Test-Path -LiteralPath $taskPasswordProvider){Remove-Item -LiteralPath $taskPasswordProvider}
$taskInproc=Join-Path $taskPasswordClsid 'InprocServer32'
if(Test-Path -LiteralPath $taskInproc){Remove-Item -LiteralPath $taskInproc}
if(Test-Path -LiteralPath $taskPasswordClsid){Remove-Item -LiteralPath $taskPasswordClsid}
$taskService=Get-CimInstance Win32_Service -Filter "Name='WindowsUnlockPasswordService'"
if($taskService -and $taskService.PathName -eq ('"'+(Join-Path $taskPasswordTarget 'PhoneUnlockPasswordService.exe')+'"')){Stop-Service -Name $taskPasswordService -ErrorAction SilentlyContinue;& sc.exe delete $taskPasswordService | Out-Null}
Write-Output 'Project-owned phone tile removed. Normal Windows providers and LSA configuration were not changed. Encrypted vault and files retained.'
