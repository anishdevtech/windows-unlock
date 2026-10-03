param([switch]$RunTests)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskVswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if(-not(Test-Path -LiteralPath $taskVswhere)){throw 'Visual Studio C++ Desktop Development and Windows SDK are required.'}
$taskVs=& $taskVswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $taskVs){throw 'Visual Studio C++ Desktop Development and Windows SDK are required.'}
$taskTools=Join-Path $taskVs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
$taskCmake=Join-Path $taskTools 'cmake.exe'
if(-not(Test-Path -LiteralPath $taskCmake)){throw 'Visual Studio CMake tools are required.'}
& $taskCmake -S "$taskRoot\windows" -B "$taskRoot\build\windows" -A x64
if($LASTEXITCODE){throw 'Native preview configuration failed.'}
# Do not relink/stop a running desktop companion. No registration, services or elevation.
& $taskCmake --build "$taskRoot\build\windows" --config Release --target CredentialProviderPreview PhoneUnlockPreviewService PhoneUnlockPreviewStage core_tests native_tests provider_tests enrollment_tests
if($LASTEXITCODE){throw 'Native preview build failed.'}
Write-Output 'Native preview built. Windows sign-in remains disabled; nothing installed.'
if($RunTests){
  & (Join-Path $taskTools 'ctest.exe') --test-dir "$taskRoot\build\windows" -C Release --output-on-failure
  if($LASTEXITCODE){throw 'Native security checks failed or were blocked by Application Control. Check the output; do not lower Windows security policy.'}
}
