# Windows Unlock 0.7.2

Companion 0.7.2 adds a searchable Windows launcher and an animated confirmation after successful phone sign-in. Native service/provider 0.6.2 includes the first-boot service/network retry fix. Android remains 0.7.0; this update needs no new APK.

## On the development laptop

The updated companion and shortcuts are already installed. Open Start, type **Windows Unlock**, and open the result. The desktop shortcut works too. Opening either shortcut restores the same running companion, including after its window has been closed to the background.

To install the native boot fix and enable automatic unlock animations:

1. Double-click **Install WINDOWS-UNLOCK boot fix** on the desktop.
2. Choose **Yes** in the Windows administrator prompt.
3. Wait for the installer to report **Installed**. It preserves the existing pairing, encrypted password enrollment, and automatic-request preference.

The previous administrator prompt was canceled, so the native service is still 0.6.0 at the time of this update. Closing the prompt without approving it does not install the fix. Do not unpair or repeat password enrollment to apply this update.

After installation, restart once and test phone fingerprint approval at the first Windows sign-in. The service starts before user login; the companion starts after login. The provider waits for service/network readiness while keeping Windows PIN and Password available. See [first-boot diagnosis](first-boot-sign-in.md).

## Installing the release ZIP

Extract the complete Windows 0.7.2 ZIP to a permanent folder. For an existing paired installation, close its companion before replacing files. In ordinary PowerShell opened in the extracted folder, create the Start, desktop, and startup shortcuts:

```powershell
.\scripts\Install-Companion.ps1 -CompanionPath .\Companion\phoneunlock.exe -StartWithWindows
```

This uses the existing `%LOCALAPPDATA%\WINDOWS-UNLOCK\hosted` pairing. If your state is elsewhere, supply `-StateDirectory` with that directory. The shortcut installer requires existing configuration and never resets pairing.

For an existing native installation, open administrator PowerShell in the extracted folder and run:

```powershell
.\installer\Update-PasswordUnlock.ps1 -DevelopmentBuild -RecoveryVerified -AutomaticRequests Keep
```

Read [password sign-in setup](password-unlock-setup.md) before native installation. A fresh installation needs that guide's enrollment steps; the updater is for an already enrolled laptop. Development binaries remain unsigned and the installer does not change Windows security policy.

## Unlock animation

The companion has **Show animation after phone unlock** and **Preview animation** controls. The preview is explicitly labeled and can be used before updating the native service.

After Windows reports successful sign-in through the phone provider, a small, click-through card draws a teal ring, checkmark, and particles, then fades away. It lasts about 2.6 seconds, does not take keyboard focus, and uses a short static card when Windows animations are disabled. The preference can turn it off.

Phone approval alone does not trigger the success animation. Native 0.6.2 signs a cosmetic receipt only after Windows reports success. The companion verifies the delegation and receipt signatures, current account, session, device, pairing, and a 30-second freshness window. A separate protected local state prevents replaying the same request when the app is reopened. Normal manual reopening does not schedule receipt playback.

The receipt contains no password or decryption key. It has its own file permission granting the enrolled account read access; the password vault directory and vault permissions are unchanged. Receipt failures never change the sign-in result.

## Verification

The companion build, receipt signature/binding/replay-window tests, existing core/vault/provider/lifecycle tests, and PowerShell parsing passed. Windows registers **Windows Unlock** as an app, and launching its shortcut after hiding the window restored the same process. The animation was rendered and previewed in the running app.

Native installation, first-boot phone sign-in, and the automatic animation after a real phone unlock remain physical-device acceptance checks. The service IPC test cannot run alongside the installed production pipe; the native updater runs its checks during installation.
