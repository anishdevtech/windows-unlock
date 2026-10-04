function Get-UnlockSignTool {
  $taskSdk=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  $taskTool=Get-ChildItem -LiteralPath $taskSdk -Directory | Sort-Object Name -Descending | ForEach-Object {Join-Path $_.FullName 'x64\signtool.exe'} | Where-Object {Test-Path -LiteralPath $_} | Select-Object -First 1
  if(-not $taskTool){throw 'Install Windows SDK SignTool.'};return $taskTool
}
function Assert-UnlockSigningCertificate([string]$Thumbprint) {
  $taskCert=Get-Item -LiteralPath "Cert:\CurrentUser\My\$Thumbprint"
  if(-not $taskCert.HasPrivateKey -or $taskCert.NotAfter -le (Get-Date) -or $taskCert.NotBefore -gt (Get-Date) -or -not($taskCert.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.3')){throw 'A valid Code Signing certificate with an accessible private key is required.'}
  $taskRsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($taskCert)
  if(-not $taskRsa){throw 'Use an RSA publisher certificate supported by Smart App Control.'};$taskRsa.Dispose()
  $taskChain=New-Object Security.Cryptography.X509Certificates.X509Chain
  try{$taskChain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::Online;if(-not $taskChain.Build($taskCert)){throw 'Certificate chain or revocation verification failed.'}}finally{$taskChain.Dispose()}
  return $taskCert
}
function Invoke-UnlockSign([string]$Tool,[string]$Thumbprint,[string]$Timestamp,[string]$Path) {
  & $Tool sign /sha1 $Thumbprint /s My /fd SHA256 /tr $Timestamp /td SHA256 $Path
  if($LASTEXITCODE){throw 'Signing failed. The key stays in the certificate provider; use its PIN/UI if prompted.'}
  & $Tool verify /pa /all $Path
  if($LASTEXITCODE -or (Get-AuthenticodeSignature -LiteralPath $Path).Status -ne 'Valid'){throw 'Signed file verification failed.'}
}
