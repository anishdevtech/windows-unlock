# One-time phone sign-in setup (0.5)

This mode uses an extra C++ Credential Provider and Windows' built-in password
authentication. No custom LSA DLL, Partner Center account or EV certificate is used.
It stores your Windows password **encrypted locally**. Your phone controls the
decryption key. Your Windows password never goes to Android, Firebase or the relay.
Your Android private key stays in Keystore. Windows PIN remains your normal backup.

The native code is built and partially tested; OS policy blocks some native checks.
Real LogonUI/Microsoft-account sign-in is not
yet an accepted test result. Complete the acceptance steps below before relying on
phone sign-in. This is a security-critical development prototype, not a certified
replacement for Windows Hello. Installing the APK alone does not install the tile.

## Prerequisites

- Windows 11 x64; administrator rights under the **same account** used for pairing.
- Normal Windows PIN **and account password** tested. Enter the Windows/Microsoft
  account password during enrollment, never the Windows Hello PIN. Passwordless-only
  accounts cannot use this mode until a working account password exists; setup fails
  rather than changing your account settings. Safe Mode may require the password.
- Paired desktop companion and updated Android **0.5.0** APK. Install over 0.4 using
  the same app/signing identity to retain pairing. Android 15+ is required for this
  mode's OAEP parameters. Your OPPO A5 Pro/Android 16 meets the OS requirement, but
  actual hardware key and biometric acceptance must still be checked on the phone.
- Relay `/health` reports `runtimeVersion: 0.5.0`; migration 004 is applied; Firebase
  push is configured. Allow Android notifications and tap a notification to approve.
  Android controls background display; the app cannot guarantee a forced popup.
- Leave **test-only lock/startup notifications** off in the companion when using
  the real tile. Its manual approval button remains a transport test.

## From this repository

Open **64-bit PowerShell as Administrator** under your paired account, then run:

```powershell
cd C:\Users\lenovo\Desktop\projects\WINDOWS-UNLOCK
.\scripts\Setup-PasswordUnlock.ps1 -DevelopmentBuild -RecoveryVerified
```

`-RecoveryVerified` means you have actually tested normal Windows PIN and Password.
`-DevelopmentBuild` permits the personal unsigned prototype; it does not disable
Smart App Control, Code Integrity, LSA protection or certificate validation. Windows
can block an untrusted build. Native probe, crypto and COM fallback checks run on
the protected staged files **before** the tile is registered. For distributed releases,
use ordinary trusted publisher signing with `scripts/Sign-PasswordUnlock.ps1` and
omit `-DevelopmentBuild`. Publisher signing is separate from the old LSA submission.

On this laptop, Application Control blocked `PhoneUnlockPasswordCheck.exe`, the new
IPC test executable and an attempted load of `CredentialProviderPassword.dll`. The DLL error
**0xc0e90002** means `STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION`; Code Integrity
events 3077/3033 confirm the signing/policy block. An earlier build's successful
DLL test does not prove the final build is allowed. A rebuilt test harness then
loaded the DLL and passed; the other blocked programs still prevent installation.
No policy was changed.
Installation will stop during preflight until Windows
allows the build, for example through a trusted publisher-signed release. Do not
rename files, add a development root, or disable security policy to bypass the block.
The signing script accepts a normal trusted code-signing identity; it does not
require an EV certificate or Microsoft protected-LSA submission. Certificate trust
does not guarantee acceptance under every App Control policy.

The setup stages binaries under `%ProgramFiles%\WINDOWS-UNLOCK-Password`, with only
SYSTEM/Administrators able to write them. It then opens a local, masked Windows
credential dialog. For your personal Microsoft account, use:

```text
Username: MicrosoftAccount\your-email@outlook.com
Password: your Microsoft account password (not your Windows PIN)
```

The dialog verifies the password locally through Windows and confirms that the
resulting SID is the same account that paired the laptop. It encrypts the password,
wipes plaintext input buffers, and sends a **public-key enrollment** request.
Open the phone notification/app, review **Enable phone sign-in** and approve with
system authentication. Setup expires after five minutes and commits atomically.
Only after successful enrollment does the script register our service/extra tile.

The paired desktop configuration defaults to
`%LOCALAPPDATA%\WINDOWS-UNLOCK\hosted\windows-config.dpapi`. For a different paired
profile, pass `-PairedConfig 'absolute\path\windows-config.dpapi'`.

## From the Windows ZIP

Extract to a normal local folder. In elevated PowerShell, run:

```powershell
.\installer\Install-PasswordUnlock.ps1 -Stage Prepare -DevelopmentBuild -RecoveryVerified
& "$env:ProgramFiles\WINDOWS-UNLOCK-Password\PhoneUnlockPasswordSetup.exe" --config "$env:LOCALAPPDATA\WINDOWS-UNLOCK\hosted\windows-config.dpapi"
# Continue only after the setup success dialog and phone approval:
.\installer\Install-PasswordUnlock.ps1 -Stage Install -RecoveryVerified
```

No operator database/Firebase secrets are included in the Windows ZIP or APK.
Paired DPAPI configuration already contains the laptop's scoped relay token.

## Sign in and acceptance

1. Lock Windows. Select **Sign-in options → Unlock with Phone** for the enrolled
   account. Selection initiates one fresh 60-second request; the provider never
   forces itself to be the default and never filters Microsoft's providers.
2. Tap the Android notification, review the laptop/account and press **Approve**.
   The system fingerprint/strong-face/device-credential prompt authorizes Keystore
   decryption. The phone returns only a signed, encrypted key release.
3. Windows verifies the signature and request digest, decrypts locally, and submits
   native password credentials to built-in Negotiate. The selected tile can then
   submit automatically. A backend `approved` status alone cannot unlock Windows.
4. Repeat with phone mobile data, denial, expiration, phone offline, relay offline,
   service stopped, switching to PIN, and repeated approval. Verify **normal PIN and
   Password still work each time**. Session changes cancel pending work.
5. Test restart separately. The service starts before first sign-in; select the phone
   tile to request approval. This code path does not rely on the tray companion or
   a signed-in user's profile. Validate real first-sign-in and resumed-session behavior.

This mode currently uses the HTTPS/FCM relay; direct LAN delivery is not implemented
for the vault protocol. If networking or approval fails, choose normal Windows PIN.
There is no custom backup PIN, simulated keyboard input or automatic PIN entry.
Phone notifications are hints; authentication always requires explicit review and
system authentication. The camera remains a separately enabled, visible, unlocked-
session feature; this setup does not enable camera access on the lock screen.

## Password changes, key removal, and recovery

After a Windows password change, use PIN/Password and rerun the setup script to
refresh enrollment. It pauses/restarts the owned service around atomic enrollment.
If Android reaches its four-enrollment limit, remove old phone sign-in keys in Android
and reenroll; pairing/remote controls can stay. Key loss or app reset requires new
enrollment. Do not reset your existing pairing just to update the APK.

To uninstall from the repository or ZIP, run in elevated PowerShell:

```powershell
.\windows\installer\Uninstall-PasswordUnlock.ps1 -RemoveVault
# ZIP location: .\installer\Uninstall-PasswordUnlock.ps1 -RemoveVault
```

It unregisters **only** GUID `{59D7E749-F07A-4549-9756-E87C0355B532}` and service
`WindowsUnlockPasswordService`, then removes owned files. A DLL currently loaded in
LogonUI may require restarting before file deletion. Registry removal takes effect
for subsequent sign-in UI enumeration. In Android, choose **Remove phone sign-in
keys** to delete the vault RSA private keys. Nonexportable laptop signing keys left
behind by old enrollments cannot decrypt passwords and are not loaded into LSA.

If binaries/manifest are damaged, use `Recover-PasswordUnlock.ps1` from the installer
folder. It removes only the known extra tile/COM registration and stops the matching
service without needing the DLL or vault to work. If normal Windows UI is unavailable,
use Safe Mode/account password, or Windows recovery with your normal recovery keys,
then remove **only** the project GUID's provider/COM keys. No full provider list,
`Security Packages`, `RunAsPPL`, default sign-in selection or Microsoft provider is
ever overwritten by these scripts. No software can promise immunity from unrelated
Windows, disk, account or firmware failures.

## Diagnostics

The service queues allowlisted codes (`request_sent`, `approval_verified`,
`approval_failed`, `credential_submitted`, etc.) and uploads signed batches every
15 seconds. Seven-day server retention applies. `credential_submitted` means the
credential was handed to Windows, **not** that Windows accepted the sign-in.
No password, key release, token, account name, arbitrary exception, biometric data,
or packed credential is logged. Setup copies the companion's server-diagnostics
preference into the privileged vault configuration; rerun enrollment to change the
service's setting. Logs are best effort and never authorize sign-in.
