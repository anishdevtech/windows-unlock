param([switch]$Android)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskVswhere='C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$taskVs=& $taskVswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $taskVs){throw 'Install Visual Studio C++ Desktop Development and Windows SDK'}
$taskCmake=Join-Path $taskVs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
if(-not(Test-Path -LiteralPath $taskCmake)){throw 'CMake is required'}
& $taskCmake -S "$taskRoot\windows" -B "$taskRoot\build\windows" -A x64
if($LASTEXITCODE){throw 'CMake configuration failed'}
& $taskCmake --build "$taskRoot\build\windows" --config Release --parallel
if($LASTEXITCODE){throw 'Windows build failed'}
Push-Location "$taskRoot\backend"
try { & npm.cmd ci --no-audit --no-fund; if($LASTEXITCODE){throw 'npm install failed'}; & npm.cmd run build; if($LASTEXITCODE){throw 'Backend build failed'} } finally { Pop-Location }
if($Android){
  if(-not $env:JAVA_HOME){$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'}
  if(-not $env:ANDROID_HOME){$env:ANDROID_HOME=Join-Path $env:LOCALAPPDATA 'Android\Sdk'}
  Push-Location "$taskRoot\android"
  try{& .\gradlew.bat :app:assembleDebug :app:testDebugUnitTest :app:lintDebug; if($LASTEXITCODE){throw 'Android build/checks failed'}}finally{Pop-Location}
}
