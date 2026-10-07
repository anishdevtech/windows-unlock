param([Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CertificateThumbprint,[ValidatePattern('^https://')][string]$TimestampUrl='https://timestamp.digicert.com')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Signing-Helpers.ps1')
Assert-UnlockSigningCertificate $CertificateThumbprint | Out-Null
$taskTool=Get-UnlockSignTool
$taskRoot=Split-Path -Parent $PSScriptRoot
foreach($taskName in @('CredentialProviderPassword.dll','PhoneUnlockPasswordService.exe','PhoneUnlockPasswordSetup.exe','PhoneUnlockPasswordCheck.exe','password_provider_tests.exe','password_ipc_tests.exe','vault_tests.exe')){Invoke-UnlockSign $taskTool $CertificateThumbprint $TimestampUrl (Join-Path $taskRoot "build\windows\Release\$taskName")}
Write-Output 'Password-mode publisher signatures verified. No Microsoft LSA signature or Partner Center submission is required by this architecture; OS application policy remains enforced.'
