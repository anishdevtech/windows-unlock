$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskAdmin=Get-Content -Raw -LiteralPath "$taskRoot\.runtime\postgres-admin.json" | ConvertFrom-Json
& "$($taskAdmin.pgBin)\pg_ctl.exe" -D $taskAdmin.dataDir -m fast -w stop
if($LASTEXITCODE){throw 'PostgreSQL stop failed'}
