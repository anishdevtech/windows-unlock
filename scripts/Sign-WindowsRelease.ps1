param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$CertificateThumbprint,
  [ValidatePattern('^https://')][string]$TimestampUrl='https://timestamp.digicert.com'
)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskBinary=Join-Path $taskRoot 'build\windows\Release\phoneunlock.exe'
if(-not(Test-Path -LiteralPath $taskBinary)){throw 'Build the Windows Release executable first.'}
$taskCertificate=Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction Stop
if(-not $taskCertificate.HasPrivateKey){throw 'The selected publisher certificate has no available private key.'}
if($taskCertificate.NotAfter -le (Get-Date) -or $taskCertificate.NotBefore -gt (Get-Date)){throw 'The selected certificate is outside its validity period.'}
if(-not($taskCertificate.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.3')){throw 'Select a certificate with the Code Signing purpose.'}
$taskRsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($taskCertificate)
if($null -eq $taskRsa){throw 'Smart App Control requires an RSA publisher certificate for this executable.'}
$taskRsa.Dispose()
$taskChain=New-Object Security.Cryptography.X509Certificates.X509Chain
try{
  $taskChain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::Online
  if(-not $taskChain.Build($taskCertificate)){throw 'Publisher certificate trust/revocation verification failed. Use a certificate from a trusted provider; do not add a development root to bypass policy.'}
}finally{$taskChain.Dispose()}
$taskSdk=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$taskSignTool=Get-ChildItem -LiteralPath $taskSdk -Directory | Sort-Object Name -Descending |
  ForEach-Object {Join-Path $_.FullName 'x64\signtool.exe'} | Where-Object {Test-Path -LiteralPath $_} | Select-Object -First 1
if(-not $taskSignTool){throw 'Install the Windows SDK signing tools.'}
# Uses the Windows certificate store/provider; never exports a private key or asks for a PFX password.
& $taskSignTool sign /sha1 $CertificateThumbprint /s My /fd SHA256 /tr $TimestampUrl /td SHA256 $taskBinary
if($LASTEXITCODE){throw 'Publisher signing failed.'}
& $taskSignTool verify /pa /all $taskBinary
if($LASTEXITCODE){throw 'Authenticode verification failed.'}
if((Get-AuthenticodeSignature -LiteralPath $taskBinary).Status -ne 'Valid'){throw 'Windows does not validate this publisher signature.'}
Write-Output 'Release companion signed and verified. OS Application Control makes the final launch decision.'
Write-Output 'This signs only the desktop companion. It does not provide the separate Microsoft LSA-package signature or enable Windows sign-in.'
