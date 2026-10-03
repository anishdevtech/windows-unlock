$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskFile="$taskRoot\.runtime\certificate-state.json"
if(Test-Path -LiteralPath $taskFile){
  $taskCert=Get-Content -Raw -LiteralPath $taskFile | ConvertFrom-Json
  if($taskCert.caThumbprint -notmatch '^[0-9A-Fa-f]{40}$'){throw 'Invalid recorded certificate thumbprint'}
  $taskPath="Cert:\CurrentUser\Root\$($taskCert.caThumbprint)"
  if(Test-Path -LiteralPath $taskPath){$taskCurrent=Get-Item -LiteralPath $taskPath;if($taskCurrent.Subject -ne 'CN=WINDOWS-UNLOCK Local Development CA'){throw 'Unexpected certificate; refusing removal'};Remove-Item -LiteralPath $taskPath}
  Write-Output 'Removed only this project development CA. Windows authentication is unchanged.'
}
