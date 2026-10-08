[CmdletBinding()]
param([switch]$Json)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskHelpers=Join-Path $taskRoot 'windows\installer\Password-Helpers.ps1'
if(-not(Test-Path -LiteralPath $taskHelpers)){$taskHelpers=Join-Path $taskRoot 'installer\Password-Helpers.ps1'}
. $taskHelpers
$taskProbe=Join-Path $taskRoot 'build\windows\Release\PhoneUnlockPasswordCheck.exe'
if(-not(Test-Path -LiteralPath $taskProbe)){$taskProbe=Join-Path $taskRoot 'Release\PhoneUnlockPasswordCheck.exe'}
$taskPolicy=Get-PasswordAppControlStatus
$taskWindows=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$taskReport=[ordered]@{windowsVersion=$taskWindows.DisplayVersion;windowsBuild="$($taskWindows.CurrentBuildNumber).$($taskWindows.UBR)";appControl=$taskPolicy;probeExists=(Test-Path -LiteralPath $taskProbe);probeSignature='Missing';probeResult='Missing';probeExitCode=$null;launchErrorCode=$null;settingsChanged=$false;tileRegistered=(Test-Path -LiteralPath $taskPasswordProvider);serviceInstalled=[bool](Get-Service -Name $taskPasswordService -ErrorAction SilentlyContinue)}
if($taskReport.probeExists){
  $taskReport.probeSignature=(Get-AuthenticodeSignature -LiteralPath $taskProbe).Status.ToString()
  # Suppress only native error dialogs. Policy enforcement remains unchanged.
  if(-not ('WindowsUnlockReadinessErrorMode' -as [type])){Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class WindowsUnlockReadinessErrorMode {
  [DllImport("kernel32.dll")] public static extern uint SetErrorMode(uint mode);
}
'@}
  $taskOldMode=[WindowsUnlockReadinessErrorMode]::SetErrorMode(0x8003)
  $taskProcess=$null
  try{
    $taskStart=[Diagnostics.ProcessStartInfo]::new($taskProbe,'--probe')
    $taskStart.UseShellExecute=$false;$taskStart.CreateNoWindow=$true
    $taskStart.RedirectStandardOutput=$true;$taskStart.RedirectStandardError=$true
    $taskProcess=[Diagnostics.Process]::Start($taskStart)
    if(-not $taskProcess.WaitForExit(10000)){$taskProcess.Kill();$taskProcess.WaitForExit();$taskReport.probeResult='TimedOut'}
    else{$taskReport.probeExitCode=$taskProcess.ExitCode;$taskReport.probeResult=if($taskProcess.ExitCode -eq 0){'Passed'}else{'Failed'}}
  }catch{
    $taskError=$_.Exception
    while($taskError.InnerException){$taskError=$taskError.InnerException}
    $taskReport.probeResult='LaunchFailed'
    if($taskError -is [ComponentModel.Win32Exception]){$taskReport.launchErrorCode=$taskError.NativeErrorCode}
  }finally{
    if($taskProcess){$taskProcess.Dispose()}
    [WindowsUnlockReadinessErrorMode]::SetErrorMode($taskOldMode) | Out-Null
  }
}
$taskReport.appControlAfter=Get-PasswordAppControlStatus
if($Json){[pscustomobject]$taskReport | ConvertTo-Json -Depth 4}
else{
  [pscustomobject]$taskReport | Format-List
  if($taskReport.probeResult -eq 'LaunchFailed'){Write-Output (Get-PasswordLaunchFailure 'PhoneUnlockPasswordCheck.exe')}
  Write-Output 'This read-only check never enrolls a password, installs a service/tile, or changes Windows security settings. A passed probe is not proof of actual phone sign-in.'
}
