param(
  [string]$RelayUrl='https://windows-unlock.vercel.app',
  [switch]$AutoStart,
  [switch]$Launch
)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskExe=Join-Path $taskRoot 'build/windows/Release/phoneunlock.exe'
$taskEnv=Join-Path $taskRoot 'backend/.env'
$taskState=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'WINDOWS-UNLOCK/hosted'
$taskMarker=Join-Path $taskState 'setup.json'
$taskBootstrap=Join-Path $taskState 'operator-bootstrap.json'
$taskPublic=Join-Path $taskState 'windows-public.json'
$taskCA=Join-Path $taskState 'system-ca.pem'
$taskUri=[Uri]$RelayUrl
if(-not $taskUri.IsAbsoluteUri -or $taskUri.Scheme -ne 'https' -or $taskUri.UserInfo -or $taskUri.Query -or $taskUri.Fragment -or $taskUri.AbsolutePath -ne '/') {
  throw 'RelayUrl must be an HTTPS origin without embedded credentials, query, fragment or path.'
}
$RelayUrl=$taskUri.GetLeftPart([UriPartial]::Authority)
if(-not(Test-Path -LiteralPath $taskExe)){throw 'Build the Windows companion first using scripts/Build.ps1.'}
if(-not(Test-Path -LiteralPath $taskMarker) -and -not(Test-Path -LiteralPath $taskEnv)) {
  throw 'First setup needs the trusted operator credentials in ignored backend/.env. They are not used by the installed companion or startup shortcut.'
}
# Verify the public endpoint using normal Windows TLS trust before changing local state.
$taskHealth=Invoke-RestMethod -Uri "$RelayUrl/health" -TimeoutSec 20
$taskDesktopSupported=$taskHealth.mode -eq 'desktop-approval-only' -or ($taskHealth.mode -eq 'approval-relay' -and $taskHealth.protocolPurposes -contains 'desktop-approval')
if($taskHealth.status -ne 'ok' -or -not $taskDesktopSupported){throw 'Hosted relay is not ready or has an unexpected protocol mode.'}
New-Item -ItemType Directory -Force -Path $taskState | Out-Null
& (Join-Path $PSScriptRoot "Protect-ProfileState.ps1") -Path $taskState
function Invoke-TaskCompanion([string[]]$ClientArguments) {
  $taskArgs=@('--state',$taskState)+$ClientArguments
  $taskQuoted=$taskArgs | ForEach-Object { '"'+($_ -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1')+'"' }
  $taskProcess=Start-Process -FilePath $taskExe -ArgumentList ($taskQuoted -join ' ') -WindowStyle Hidden -Wait -PassThru
  if($taskProcess.ExitCode){throw 'Windows companion setup failed. Existing state was preserved; no sign-in settings were changed.'}
}
if(Test-Path -LiteralPath $taskMarker) {
  $taskCompleted=Get-Content -Raw -LiteralPath $taskMarker | ConvertFrom-Json
  if($taskCompleted.relayUrl -ne $RelayUrl){throw 'This hosted state belongs to another relay. Do not overwrite an existing pairing.'}
  if(-not(Test-Path -LiteralPath (Join-Path $taskState 'windows-config.dpapi'))){throw 'Hosted configuration is missing. Restore your protected state or follow recovery.md before re-pairing.'}
}else {
  [IO.File]::WriteAllText($taskCA,'')
  if(-not(Test-Path -LiteralPath (Join-Path $taskState 'windows-config.dpapi'))) {
    Invoke-TaskCompanion -ClientArguments @('--init',$RelayUrl,'system',$taskCA)
  }
  Invoke-TaskCompanion -ClientArguments @('--public',$taskPublic)
  # This one-time operator action registers a new hosted identity. It does not copy
  # the existing local database, Windows pairing, password or PIN to the cloud.
  if(-not(Test-Path -LiteralPath $taskBootstrap)) {
    Push-Location (Join-Path $taskRoot 'backend')
    $taskPreviousEnv=@{}
    foreach($taskEnvName in @('DATABASE_URL','DATABASE_CA_PEM','PHONEUNLOCK_CONFIG')) {
      $taskPreviousEnv[$taskEnvName]=[Environment]::GetEnvironmentVariable($taskEnvName,'Process')
      # PowerShell can retain an empty process variable when .NET is given null.
      # Node --env-file does not override existing variables, including empty ones.
      Remove-Item -LiteralPath "Env:\$taskEnvName" -ErrorAction SilentlyContinue
    }
    try {
      & node --env-file=$taskEnv --import tsx src/cli.ts bootstrap $taskPublic $taskBootstrap
      if($LASTEXITCODE){throw 'Hosted device registration failed. Check the operator database configuration; do not delete protected state.'}
    }finally{
      Pop-Location
      foreach($taskEnvName in $taskPreviousEnv.Keys){
        if($null -eq $taskPreviousEnv[$taskEnvName]){Remove-Item -LiteralPath "Env:\$taskEnvName" -ErrorAction SilentlyContinue}
        else{[Environment]::SetEnvironmentVariable($taskEnvName,$taskPreviousEnv[$taskEnvName],'Process')}
      }
    }
  }
  Invoke-TaskCompanion -ClientArguments @('--configure',$taskBootstrap)
  $taskIdentity=Get-Content -Raw -LiteralPath $taskPublic | ConvertFrom-Json
  [IO.File]::WriteAllText($taskMarker,(@{relayUrl=$RelayUrl;windowsDeviceId=$taskIdentity.id} | ConvertTo-Json))
  # Only this exact transient token file is removed after DPAPI import succeeds.
  Remove-Item -LiteralPath $taskBootstrap
}
Invoke-TaskCompanion -ClientArguments @('--health')
$taskShell=New-Object -ComObject WScript.Shell
$taskShortcutPaths=@((Join-Path ([Environment]::GetFolderPath('Desktop')) 'WINDOWS-UNLOCK Hosted.lnk'))
if($AutoStart){$taskShortcutPaths+=Join-Path ([Environment]::GetFolderPath('Startup')) 'WINDOWS-UNLOCK Hosted.lnk'}
foreach($taskShortcutPath in $taskShortcutPaths) {
  $taskShortcut=$taskShell.CreateShortcut($taskShortcutPath)
  $taskShortcut.TargetPath=$taskExe
  $taskShortcut.Arguments='--state "'+$taskState+'"'
  if((Split-Path -Parent $taskShortcutPath) -eq [Environment]::GetFolderPath('Startup')){$taskShortcut.Arguments+=' --startup'}
  $taskShortcut.WorkingDirectory=Split-Path -Parent $taskExe
  $taskShortcut.Description='WINDOWS-UNLOCK hosted desktop companion; Windows PIN remains available.'
  $taskShortcut.Save()
}
Write-Output 'Hosted setup ready. Existing pairing was preserved. Open the companion; use Pair phone only if this is a new setup.'
Write-Output "Protected state: $taskState"
Write-Output 'No Credential Provider was installed. Windows PIN/password are unchanged.'
if($Launch){Start-Process -FilePath $taskExe -ArgumentList ('--state "'+$taskState+'"') -WindowStyle Normal}
