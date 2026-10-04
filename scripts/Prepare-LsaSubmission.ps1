param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$EvCertificateThumbprint,
  [Parameter(Mandatory=$true)][switch]$EvCertificateConfirmed,
  [ValidatePattern('^https://')][string]$TimestampUrl='https://timestamp.digicert.com'
)
$ErrorActionPreference='Stop'
if(-not $EvCertificateConfirmed){throw 'Confirm with your issuer that this is your organization EV code-signing certificate registered in Partner Center.'}
. (Join-Path $PSScriptRoot 'Signing-Helpers.ps1')
Assert-UnlockSigningCertificate $EvCertificateThumbprint | Out-Null
$taskTool=Get-UnlockSignTool
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskDll=Join-Path $taskRoot 'build\windows\Release\WindowsUnlockAuth.dll'
if(-not(Test-Path -LiteralPath $taskDll)){throw 'Run Build-WindowsUnlock.ps1 first.'}
$taskOutput=Join-Path $taskRoot ('build\lsa-submission-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskOutput | Out-Null
$taskFrozen=Join-Path $taskOutput 'WindowsUnlockAuth.dll'
Copy-Item -LiteralPath $taskDll -Destination $taskFrozen
$taskCab=Join-Path $taskOutput 'WINDOWS-UNLOCK-LSA.cab'
# Flat cabinet: one DLL, no folders, secrets, debug symbols, config or manifest inside.
& "$env:SystemRoot\System32\makecab.exe" /D Cabinet=ON /D Compress=ON /D CompressionType=LZX $taskFrozen $taskCab
if($LASTEXITCODE){throw 'CAB generation failed.'}
Invoke-UnlockSign $taskTool $EvCertificateThumbprint $TimestampUrl $taskCab
@{binary='WindowsUnlockAuth.dll';sha256=(Get-FileHash -LiteralPath $taskFrozen -Algorithm SHA256).Hash;cabSha256=(Get-FileHash -LiteralPath $taskCab -Algorithm SHA256).Hash;submittedAt=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskOutput 'submission-record.json') -Encoding UTF8
Write-Output "Submit this cabinet using Partner Center / File Signing Services / Submit New LSA: $taskCab"
Write-Output 'Keep the frozen DLL and record. Download the Microsoft-signed result, then follow docs/lsa-signing-and-setup.md. Do not re-sign the returned DLL.'
