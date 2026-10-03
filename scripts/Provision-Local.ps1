param([Parameter(Mandatory=$true)][string]$PostgresBin,[string]$RelayAddress='127.0.0.1')
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskRuntime=Join-Path $taskRoot '.runtime'
$taskPgBin=(Resolve-Path -LiteralPath $PostgresBin).Path
if(-not(Test-Path -LiteralPath "$taskPgBin\initdb.exe")){throw 'PostgresBin must contain initdb.exe, pg_ctl.exe and psql.exe'}
$taskIP=$null
if(-not [System.Net.IPAddress]::TryParse($RelayAddress,[ref]$taskIP) -or $taskIP.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork){throw 'RelayAddress must be the laptop IPv4 address (or 127.0.0.1 for desktop-only testing)'}
New-Item -ItemType Directory -Force -Path $taskRuntime | Out-Null
# Owner-restricted inheritance protects every secret created under .runtime.
$taskSid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
$taskAcl=New-Object System.Security.AccessControl.DirectorySecurity
$taskAcl.SetOwner($taskSid);$taskAcl.SetAccessRuleProtection($true,$false)
$taskRule=New-Object System.Security.AccessControl.FileSystemAccessRule($taskSid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
$taskAcl.AddAccessRule($taskRule);Set-Acl -LiteralPath $taskRuntime -AclObject $taskAcl
if(Test-Path -LiteralPath "$taskRuntime\postgres-admin.json"){throw 'Runtime already provisioned. Use Start-Local.ps1, or create a separate checkout for a clean test.'}
function New-TaskSecret { $taskBytes=New-Object byte[] 32; $taskRng=[System.Security.Cryptography.RandomNumberGenerator]::Create();try{$taskRng.GetBytes($taskBytes)}finally{$taskRng.Dispose()}; return ([BitConverter]::ToString($taskBytes)).Replace('-','').ToLowerInvariant() }
$taskAdminPassword=New-TaskSecret;$taskAppPassword=New-TaskSecret
$taskAdmin=@{adminPassword=$taskAdminPassword;appPassword=$taskAppPassword;port=55432;pgBin=$taskPgBin;dataDir="$taskRuntime\pgdata";relayAddress=$RelayAddress}
$taskAdmin | ConvertTo-Json | Set-Content -LiteralPath "$taskRuntime\postgres-admin.json" -Encoding UTF8
[System.IO.File]::WriteAllText("$taskRuntime\init-password.txt",$taskAdminPassword)
try{& "$taskPgBin\initdb.exe" -D "$taskRuntime\pgdata" -U postgres --auth=scram-sha-256 --encoding=UTF8 --locale=C --pwfile="$taskRuntime\init-password.txt";if($LASTEXITCODE){throw 'initdb failed'}}finally{Remove-Item -LiteralPath "$taskRuntime\init-password.txt" -ErrorAction SilentlyContinue}
Add-Content -LiteralPath "$taskRuntime\pgdata\postgresql.conf" -Value "`nlisten_addresses = '127.0.0.1'`nport = 55432`nlog_statement = 'none'`nlog_min_error_statement = 'panic'"
& "$taskPgBin\pg_ctl.exe" -D "$taskRuntime\pgdata" -l "$taskRuntime\postgres.log" -w start
if($LASTEXITCODE){throw 'PostgreSQL startup failed'}
& node "$PSScriptRoot\provision.mjs" $taskRoot
if($LASTEXITCODE){throw 'Relay provisioning failed'}
$taskCert=Import-Certificate -FilePath "$taskRuntime\ca.crt" -CertStoreLocation Cert:\CurrentUser\Root
@{caThumbprint=$taskCert.Thumbprint} | ConvertTo-Json | Set-Content -LiteralPath "$taskRuntime\certificate-state.json" -Encoding UTF8
$taskPublicConfig=Get-Content -Raw -LiteralPath "$taskRuntime\connection.json" | ConvertFrom-Json
$taskExe="$taskRoot\build\windows\Release\phoneunlock.exe"
if(-not(Test-Path -LiteralPath $taskExe)){throw 'Run Build.ps1 before provisioning'}
function Invoke-TaskClient([string[]]$ClientArguments){
  # Windows command-line quoting for paths; arguments here never include bearer tokens.
  $taskQuoted=$ClientArguments | ForEach-Object { '"'+($_ -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1')+'"' }
  $taskProcess=Start-Process -FilePath $taskExe -ArgumentList ($taskQuoted -join ' ') -WindowStyle Hidden -Wait -PassThru
  if($taskProcess.ExitCode){throw 'Windows client provisioning failed'}
}
Invoke-TaskClient -ClientArguments @('--state',$taskRuntime,'--init',$taskPublicConfig.relayUrl,$taskPublicConfig.tlsPin,"$taskRuntime\ca.crt")
Invoke-TaskClient -ClientArguments @('--state',$taskRuntime,'--public',"$taskRuntime\windows-public.json")
$env:PHONEUNLOCK_CONFIG="$taskRuntime\relay.json"
Push-Location "$taskRoot\backend"
try{& npm.cmd run migrate;if($LASTEXITCODE){throw 'Migration failed'};& npm.cmd run bootstrap -- "$taskRuntime\windows-public.json" "$taskRuntime\windows-bootstrap.json";if($LASTEXITCODE){throw 'Bootstrap failed'}}finally{Pop-Location}
Invoke-TaskClient -ClientArguments @('--state',$taskRuntime,'--configure',"$taskRuntime\windows-bootstrap.json")
Remove-Item -LiteralPath "$taskRuntime\windows-bootstrap.json"
Write-Output 'Local runtime provisioned. Run scripts/Start-Local.ps1, then Pair phone in the desktop app.'
