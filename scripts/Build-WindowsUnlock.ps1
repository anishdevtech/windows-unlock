param([switch]$RunTests)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskVswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$taskVs=& $taskVswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $taskVs){throw 'Install Visual Studio Desktop Development with C++ and the Windows SDK.'}
$taskTools=Join-Path $taskVs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
& (Join-Path $taskTools 'cmake.exe') -S "$taskRoot\windows" -B "$taskRoot\build\windows" -A x64
if($LASTEXITCODE){throw 'Native configuration failed'}
& (Join-Path $taskTools 'cmake.exe') --build "$taskRoot\build\windows" --config Release --target WindowsUnlockAuth CredentialProvider PhoneUnlockService PhoneUnlockStage authority_tests package_tests signin_provider_tests core_tests native_tests provider_tests enrollment_tests
if($LASTEXITCODE){throw 'Native build failed'}
Write-Output 'Authentication package, provider, service and staging tool built. Nothing registered or installed.'
if($RunTests){
  & (Join-Path $taskTools 'ctest.exe') --test-dir "$taskRoot\build\windows" -C Release --output-on-failure
  if($LASTEXITCODE){throw 'A check failed or Application Control blocked execution. Inspect the output; keep Windows security policy enabled.'}
}
