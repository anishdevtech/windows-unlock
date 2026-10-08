param()
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskVswhere='C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$taskVs=& $taskVswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $taskVs){throw 'Install Visual Studio Desktop Development with C++ and Windows SDK.'}
$taskCmake=Join-Path $taskVs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
& $taskCmake -S (Join-Path $taskRoot 'windows') -B (Join-Path $taskRoot 'build\windows') -A x64;if($LASTEXITCODE){throw 'CMake configuration failed.'}
& $taskCmake --build (Join-Path $taskRoot 'build\windows') --config Release --target vault_tests password_provider_tests password_ipc_tests provider_lifecycle_tests PhoneUnlockPasswordService PhoneUnlockPasswordSetup PhoneUnlockPasswordCheck;if($LASTEXITCODE){throw 'Native password mode build failed.'}
& (Join-Path (Split-Path -Parent $taskCmake) 'ctest.exe') --test-dir (Join-Path $taskRoot 'build\windows') -C Release -R 'password_' --output-on-failure;if($LASTEXITCODE){throw 'Native password mode checks failed.'}
Write-Output 'Password-mode binaries built and checked. No authentication settings changed.'
