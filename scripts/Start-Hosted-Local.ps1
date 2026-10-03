param([ValidateRange(1024,65535)][int]$Port=9443)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskBackend=Join-Path $taskRoot 'backend'
$taskRuntime=Join-Path $taskRoot '.runtime'
$taskEnvFile=Join-Path $taskBackend '.env'
foreach($taskRequired in @($taskEnvFile,"$taskRuntime\server.key","$taskRuntime\server.crt")) {
  if(-not(Test-Path -LiteralPath $taskRequired)){throw 'Local test requires backend/.env and the provisioned development TLS files in .runtime.'}
}
if(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
  throw "Port $Port is already in use. Use the running relay or choose a different -Port."
}
$taskConfigPath=Join-Path $taskRuntime 'hosted-local-test.json'
$taskConfigJson=@{host='127.0.0.1';port=$Port;tlsKey="$taskRuntime\server.key";tlsCert="$taskRuntime\server.crt"} | ConvertTo-Json
[IO.File]::WriteAllText($taskConfigPath,$taskConfigJson)
$taskPreviousConfig=$env:PHONEUNLOCK_CONFIG
$taskPreviousPort=$env:PORT
$taskPreviousVercel=$env:VERCEL
Push-Location $taskBackend
try {
  & npm.cmd run build
  if($LASTEXITCODE){throw 'Backend build failed'}
  $env:PHONEUNLOCK_CONFIG=$taskConfigPath
  $env:PORT=[string]$Port
  $env:VERCEL='0'
  Write-Output "Local relay: https://localhost:$Port/health. Ctrl+C stops it."
  Write-Output 'Uses the hosted database/Firebase credentials from ignored backend/.env; internet is required for those services.'
  & node --env-file=$taskEnvFile dist/src/server.js
  if($LASTEXITCODE){throw 'Relay stopped with an error; check the sanitized startup message.'}
}finally {
  $env:PHONEUNLOCK_CONFIG=$taskPreviousConfig
  $env:PORT=$taskPreviousPort
  $env:VERCEL=$taskPreviousVercel
  Pop-Location
}
