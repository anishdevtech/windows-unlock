param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CertificateThumbprint,
  [ValidatePattern('^https://')][string]$TimestampUrl='https://timestamp.digicert.com',
  [switch]$IncludeTestHarnesses
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Signing-Helpers.ps1')
Assert-UnlockSigningCertificate $CertificateThumbprint | Out-Null
$taskTool=Get-UnlockSignTool
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskNames=@('CredentialProvider.dll','PhoneUnlockService.exe','PhoneUnlockStage.exe')
if($IncludeTestHarnesses){$taskNames+=@('core_tests.exe','native_tests.exe','provider_tests.exe','enrollment_tests.exe','authority_tests.exe','package_tests.exe','signin_provider_tests.exe','CredentialProviderPreview.dll')}
foreach($taskName in $taskNames){
  $taskFile=Join-Path $taskRoot "build\windows\Release\$taskName"
  if(-not(Test-Path -LiteralPath $taskFile)){throw 'Build the unlock components first.'}
  Invoke-UnlockSign $taskTool $CertificateThumbprint $TimestampUrl $taskFile
}
Write-Output 'Provider, service and stage tool publisher-signed. WindowsUnlockAuth.dll is deliberately excluded: use the unmodified Microsoft-returned binary.'
