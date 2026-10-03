$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskVswhere='C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$taskVs=& $taskVswhere -latest -products '*' -property installationPath
& "$taskVs\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe" --test-dir "$taskRoot\build\windows" -C Release --output-on-failure
if($LASTEXITCODE){throw 'C++ security tests failed'}
Push-Location "$taskRoot\backend"
try{
  if(Test-Path -LiteralPath "$taskRoot\.runtime\postgres-admin.json"){
    $taskDb=Get-Content -Raw -LiteralPath "$taskRoot\.runtime\postgres-admin.json" | ConvertFrom-Json
    $env:PHONEUNLOCK_TEST_DATABASE_URL="postgresql://phoneunlock:$($taskDb.appPassword)@127.0.0.1:$($taskDb.port)/phoneunlock_test"
  }
  & npm.cmd test;if($LASTEXITCODE){throw 'Backend security tests failed'}
  & .\node_modules\.bin\tsx.cmd tests\interop.ts "$taskRoot\build\windows\Release\core_tests.exe" "$taskRoot\.runtime\interop.json"
  if($LASTEXITCODE){throw 'CNG/Node interoperability failed'}
  if(Test-Path -LiteralPath "$taskRoot\.runtime\relay.json"){
    & .\node_modules\.bin\tsx.cmd tests\tls.ts "$taskRoot\build\windows\Release\http_tests.exe" "$taskRoot\.runtime\relay.json" "$taskRoot\.runtime\connection.json" "$taskRoot\.runtime\tls-test.json"
    if($LASTEXITCODE){throw 'Native TLS/pin checks failed'}
  }
}finally{Remove-Item Env:\PHONEUNLOCK_TEST_DATABASE_URL -ErrorAction SilentlyContinue;Pop-Location}
