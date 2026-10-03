# Windows lock-screen integration status

Phone approval and Windows sign-in are separate operations. The current executable
verifies a phone signature; **it cannot unlock Windows**. The repository now has a
compiled V2 Credential Provider and approval-preview Windows service. Neither is
installed on this laptop. No Windows authentication package is implemented. The
provider always returns an empty credential, even after phone approval. See
[native development](native-development.md) and [verification](native-verification.md).
Successful Firebase delivery, `/health`, or phone approval does not change this.

## This laptop

On 2026-10-04 the user confirmed a personal Microsoft account (Outlook/Hotmail).
Read-only inspection found Windows 11 Home Single Language, build 26200. Microsoft's
Web sign-in/Authenticator route requires an Entra-joined device and a supported
edition; it is not an applicable shortcut for this installation. Do not change the
account, Windows edition, or join status as part of the desktop setup script.

## What works now

After pairing the hosted companion, enable **Send a phone approval prompt when
Windows locks (test only)**. It is off by default and explains its limitations before
enabling. Keep the companion running, including minimized to the tray. It registers
for OS session changes, checks the actual local console session state, then sends
the same signed, 60-second challenge used by the manual test button.

Only one automatic request is sent per lock transition. Rapid relocking has a
60-second cooldown. A lock while pairing or another request is in progress is skipped;
it is never queued for later. Denial, expiry, network failure and duplicate lock events
do not generate retries. Unlocking via Windows PIN cancels any pending approval.
Camera sharing is blocked while the session is locked. Reopening the same companion
identity in the same session does not create another notification sender.

This is a **notification test**, not an `Unlock with Phone` lock-screen tile. Approving
it leaves the Windows screen locked. Select **Sign-in options → PIN** as usual. It
does not run before your first Windows sign-in after a restart, when the tray companion
has not started. No password/PIN is stored or automatically entered.

Enable **popup approvals** and notifications on Android once. Do not force-stop the
app. The companion reports whether Firebase accepted the push, push failed, or no
registered token/Firebase setup is available. Firebase acceptance is not proof that
Android displayed a popup; notification permissions, channel settings, Do Not Disturb
and OPPO background restrictions still apply. This update uses the existing APK.

To inspect this installation without exporting tokens, account names, public keys,
passwords, or biometric data, run:

```powershell
& .\build\windows\Release\phoneunlock.exe `
  --state "$env:LOCALAPPDATA\WINDOWS-UNLOCK\hosted" `
  --diagnostics "$env:TEMP\windows-unlock-status.json"
Get-Content "$env:TEMP\windows-unlock-status.json"
```

The report includes pairing/transport presence, relay health, lock-prompt opt-in and
local session-state availability. Relay health does not verify push registration or
delivery. If the hosted state does not exist, follow `windows-one-time-setup.md` first.

## Required before real Windows sign-in can be enabled

1. Prove a password-free Windows authentication path for the supported account type.
   A Credential Provider gathers/serializes credentials; Windows authentication
   packages decide whether to accept them. A phone ES256 signature is not, by itself,
   a credential for Microsoft's built-in sign-in packages.
2. Validate the implemented V2 provider/service in a disposable VM, and implement
   and audit the actual accepted authentication mechanism. A custom LSA package is
   a substantial security component, not a relay endpoint. Account/SID binding,
   tamper-resistant enrollment, local verification, single-use consumption, Windows
   token/profile/DPAPI behavior, revocation and unlock/logon differences all need proof.
3. For a custom LSA package running under LSA protection, obtain the required
   Microsoft signature through the LSA signing process (including the documented EV
   certificate/submission requirements). An ordinary self-signed or debug DLL is
   insufficient. Signing alone does not establish Microsoft-account compatibility.
4. Complete disposable-VM tests with protected LSA, Windows updates, crashes,
   boot/offline failure, uninstall/rollback and independent PIN/password recovery.
   Preserve every Microsoft provider; use no filter, default-provider replacement,
   PIN simulation, saved Windows password or reduced OS security.

Until these requirements are satisfied, Windows credential serialization remains
disabled in code. The separate preview installer refuses physical machines and only
adds an approval-test tile in a disposable VM. It installs no LSA package. The user
explicitly chose continued development without installation on 2026-10-04. No VM,
service, provider, machine enrollment or signing certificate was installed for this work.

## Application Control on this installation

An interim unsigned companion was blocked by Windows Application Control, with
Code Integrity event 3077 and policy `VerifiedAndReputableDesktop`. The Release
security-test executable ran successfully. A final normal rebuild successfully ran
the hosted CLI diagnostic and was opened as the hosted desktop companion. Its report
showed healthy relay, existing pairing and available session state. No policy,
exclusion, trusted root, LSA protection or PIN setting was changed to get around the
block. The previous companion was stopped for the rebuild and the final hosted
companion was opened. The current user's certificate store has no code-signing certificate
with an available private key at the time of inspection.

Use a trusted publisher signing certificate/provider for distributed desktop releases.
Acceptance of the final unsigned build does not guarantee later builds will launch.
If an appropriate RSA code-signing certificate with its private key is available in
the current user's Windows certificate store, the release workflow is:

```powershell
.\scripts\Sign-WindowsRelease.ps1 -CertificateThumbprint '<publisher certificate thumbprint>'
```

The script checks certificate purpose, validity, chain/revocation and RSA support,
signs with SHA-256 and a HTTPS timestamp, then verifies Authenticode. It exports no
private key and does not modify Windows trust or security settings. A valid publisher
signature is not a guarantee of acceptance under every Application Control policy.
This desktop signing step is separate from Microsoft's LSA-package signing process.
Rebuilds change the binary and require signing again. The signing script was parsed
but could not be exercised without a publisher certificate.

The existing hosted identity and phone pairing were preserved. Read-only checks
confirmed active hosted pairing, a registered FCM token, and Firebase dry-run
acceptance; no notification was sent. The separate local configuration points to a
relay that was unavailable during inspection. Use the **WINDOWS-UNLOCK Hosted** shortcut
for hosted use; it points to the hosted configuration rather than `.runtime`.

## Primary references

- [Credential Providers and the Windows authentication boundary](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [Web sign-in requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/web-sign-in/)
- [LSA authentication model](https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication-model)
- [Protected LSA plugin requirements](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [LSA plugin signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/file-signing-reqs)
- [OS session notification API](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification)
- [Publisher signing for Smart App Control](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control)
