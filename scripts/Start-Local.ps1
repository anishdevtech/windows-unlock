param([switch]$NoDesktop)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot;$taskRuntime=Join-Path $taskRoot '.runtime'
$taskAdmin=Get-Content -Raw -LiteralPath "$taskRuntime\postgres-admin.json" | ConvertFrom-Json
& "$($taskAdmin.pgBin)\pg_ctl.exe" -D $taskAdmin.dataDir status | Out-Null
if($LASTEXITCODE){& "$($taskAdmin.pgBin)\pg_ctl.exe" -D $taskAdmin.dataDir -l "$taskRuntime\postgres.log" -w start;if($LASTEXITCODE){throw 'PostgreSQL start failed'}}
$env:PHONEUNLOCK_CONFIG="$taskRuntime\relay.json"
if(-not $NoDesktop){Start-Process -FilePath "$taskRoot\build\windows\Release\phoneunlock.exe" -ArgumentList @('--state',('"'+$taskRuntime+'"')) -WindowStyle Normal}
Write-Output 'Relay runs in this terminal. Ctrl+C stops it. Android must remain open for Phase 1.'
& node "$taskRoot\backend\dist\src\server.js"
