# Phase 1 setup

These instructions cover local setup. Version 0.2 adds optional background push,
phone power controls and live camera; see [hosting and remote controls](hosting.md)
for Firebase, Vercel/VM deployment and physical acceptance checks.

## Prerequisites

Windows 11 x64, Visual Studio C++ Desktop Development/Windows SDK/CMake, Node 24,
Git for Windows (OpenSSL), native PostgreSQL 18 binaries, Android Studio/JDK 17+
and SDK 36. A physical Android 11+ phone must have a secure screen lock; real-device
acceptance requires a hardware-backed Keystore. No Firebase account is needed yet.

Get native PostgreSQL through https://www.postgresql.org/download/windows/ (EDB
installer or binary archive). Provisioning creates a separate project-local cluster
on loopback port 55432, no Windows service and no changes to an existing database.

From the repository root in PowerShell:

```powershell
.\scripts\Build.ps1 -Android
# Use your laptop's Wi-Fi IPv4 address for phone testing; 127.0.0.1 is desktop-only.
.\scripts\Provision-Local.ps1 -PostgresBin 'C:\path\to\pgsql\bin' -RelayAddress '192.168.1.20'
.\scripts\Test.ps1
.\scripts\Start-Local.ps1
```

Provisioning adds a project development CA to **CurrentUser** trust, creates restricted
`.runtime` configuration, and stores Windows device configuration with DPAPI. The
CA/key are development-only. Do not publish `.runtime`, share its private files, or
use this development CA as a production CA. No authentication registry changes occur.
Changing relay IP/certificate requires a new invitation and configuration; do not
disable TLS validation. Remove development trust with Remove-Development-Trust.ps1.

If Windows Firewall blocks the chosen LAN address, manually allow this relay's TCP
8443 on the private network/local subnet only. Do not expose the database or forward
a router port. Guest/AP-isolated Wi-Fi may prevent phone access.

## Android installation and pairing

Install `android/app/build/outputs/apk/debug/app-debug.apk` on the phone:

```powershell
adb install -r .\android\app\build\outputs\apk\debug\app-debug.apk
```

1. Open WINDOWS-UNLOCK on both devices. Select **Pair phone** on Windows.
2. Transfer `.runtime/phone-invitation.json` to the phone via a trusted USB file transfer
   (or `adb push .runtime/phone-invitation.json /sdcard/Download/phone-invitation.json`).
3. In Android select **Import pairing invitation**, choose the file, explicitly accept,
   and authenticate through the system prompt.
4. Compare the entire 16-character code on both screens; confirm on Windows only if
   they match. Android verifies the Windows-signed receipt before activating pairing.
5. Delete the phone's invitation copy. It contains a five-minute enrollment secret;
   Windows automatically deletes its copy when pairing completes, expires or cancels.

Keep Android open in Phase 1. Press **Unlock with Phone (test)** on Windows, review
the laptop/time on Android, approve and authenticate. Windows must show **Phone approval
verified**. Deny/cancel/expiry must not approve. Nothing signs in to Windows at this stage.

Debug emulator-only software keys can be enabled with
`gradlew.bat :app:assembleDebug -Pphoneunlock.allowSoftwareKeys=true`. This shows a
prominent TEST MODE warning and is never permitted in release builds.

If pairing is lost/reset, select Unpair on Windows before creating another invitation.
If the relay is offline, local trust is removed immediately and remote revocation
retries before the next pairing. Restarting Windows client cancels local pending work.

## Internet relay deployment (later integration)

The backend supports a configured HTTPS host and PostgreSQL connection through
`PHONEUNLOCK_CONFIG`, a path to restricted JSON with databaseUrl, tlsKey, tlsCert,
host and port. A hosted deployment needs a reachable hostname, matching certificate,
TLS >=1.2, controlled database access, backups, monitoring and operator provisioning
of the Windows identity/token. Apps receive the relay hostname, trusted CA and pin
through configuration/invitation. A cloud VM or managed host can supply this role.

FCM and background notifications are Phase 3: Firebase project/app config, restricted
server credentials, phone registration-token update/revocation, Android 13+ notification
permission, and delivery TTL <= challenge expiry. Delivery is not guaranteed; use PIN
when unavailable. Direct internet phone-IP dialing is unnecessary.

## Stop and remove

Exit desktop app through the tray icon (paired v0.2 closes to tray); Ctrl+C in relay
terminal; run Stop-Database.ps1. Remove development
trust using Remove-Development-Trust.ps1. Only then remove project-local runtime/tool
files if desired. Preserve audit data explicitly if needed. Windows keys are scoped to
the current user under `WINDOWS-UNLOCK-<device UUID>`; remove only that project key
when retiring a device. PIN/password settings are independent of every step here.
