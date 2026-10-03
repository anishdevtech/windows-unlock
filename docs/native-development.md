# Native Windows development: approval preview

The user chose development **without installation** on their laptop. This implements
the native transport/UI boundary, not Windows authentication. No service, provider,
machine enrollment or LSA package has been registered on the development laptop.

```text
V2 Unlock with Phone tile (CredentialProviderPreview.dll)
  -> authenticated local message pipe
  -> PhoneUnlockPreviewService.exe (SCM / LocalSystem)
       -> protected frozen enrollment / enrolled SID
       -> user's existing NCrypt device key
       -> 60-second signed challenge / HTTPS + FCM relay
       -> independent CNG phone verification / one-time consumption
  <- approval-preview status only
Windows credential serialization: always empty
Normal Windows PIN/password: independent
```

Selecting the tile starts an asynchronous approval request. The service requires an
already signed-in, locked, enrolled local console session. It cannot operate before
first sign-in after boot, in RDP, or for another account. Android uses the existing
FCM notification and auth-per-use Keystore/BiometricPrompt flow. This preview reuses
`desktop-approval`; no Android rebuild is required. Actual service/phone delivery
has not yet been tested in a VM. Push acceptance does not guarantee a displayed popup.

Approval displays **Phone signature verified. Windows sign-in is not enabled. Use
Sign-in options → PIN.** A signature alone cannot prove that a fingerprint was used.
Denial, expiry, unavailable service and invalid proofs fail closed. No default-provider
override, provider filter or automatic Windows login is implemented.

## Build without installation

Use Visual Studio C++ Desktop Development, Windows SDK and bundled CMake:

```powershell
.\scripts\Build-NativePreview.ps1
.\scripts\Build-NativePreview.ps1 -RunTests
```

This builds preview/test targets without stopping/relinking the running desktop
companion or changing registry, services, trust, firewall or LSA policies. Artifacts
are in `build/windows/Release`: `CredentialProviderPreview.dll`,
`PhoneUnlockPreviewService.exe`, `PhoneUnlockPreviewStage.exe` and security harnesses.
The COM harness loads the DLL directly without registration; IPC tests use temporary
user-scoped pipes, including a fake production-named pipe that is never a service.
Tests create/remove disposable user CNG keys, not real enrollment. They do not send
pushes, lock the laptop, execute power commands, capture cameras or stage machine data.

See [verification](native-verification.md) for passed and blocked checks. If Application
Control blocks execution, do not disable policy or rename/relocate binaries to bypass
it. With a trusted RSA publisher certificate available, `Sign-WindowsRelease.ps1`
accepts `-IncludeNativePreview`. Authenticode signing is separate from Microsoft's
protected-LSA signing and does not enable authentication.

## IPC and enrollment

Production pipe: `\\.\pipe\WINDOWS-UNLOCK-ApprovalPreview-v1`.
The service keeps the first instance alive, rejects remote clients and grants SYSTEM
only. It verifies the actual SYSTEM LogonUI image in the system directory, in the
active console session. The client verifies server PID against SCM's running
`WindowsUnlockPreviewService` and its LocalSystem token. Identification-only SQOS
prevents a fake pipe from receiving a usable client impersonation token.

Wire v1 uses fixed little-endian Win32 structures: request 404 bytes, reply 564 bytes,
terminated UTF-16 buffers, magic `0x50555731`, version 1. No pointers or credentials
are sent. Operations: Describe/Begin/Poll/Cancel. Begin requires a nonzero GUID;
poll/cancel bind to enrolled SID, session, scenario, caller PID and operation GUID.
Replies echo SID/GUID; reserved bytes and `windowsSignInEnabled` must be zero.
Unknown values, malformed framing and nonterminated strings are rejected. Each
read/write has a 250 ms deadline. The provider does IPC on a cancellable worker and
delivers COM events on the original subscription thread through a message-only window.

Enrollment: `%ProgramData%\WINDOWS-UNLOCK-ApprovalPreview\enrollment.dpapi`.
Machine DPAPI is accompanied by SYSTEM/Administrators-only ownership/DACL checks on
opened directory/file handles. Reparse entries, null/broad ACLs and invalid schemas
fail closed. Writes use create-new and never silently overwrite. The frozen file
contains the enrolled SID, profile/device IDs, HTTPS relay trust, scoped transport
token and public pairing/device keys. No Windows password/PIN or private key is stored.
DPAPI alone is not an access-control boundary; administrator/SYSTEM compromise is
outside the preview threat model.

The worker obtains the existing user's WTS token, opens their NCrypt key under scoped
impersonation, compares its public key to enrollment, signs and reverts before HTTP
IO. Lock/account/session and local expiry are rechecked before consuming approval.
Cancellation and monotonic expiry revoke pending work. Actual SCM/WTS/user-profile
behavior requires VM validation. No placeholder Windows authentication success exists.

Event Log source `WINDOWS-UNLOCK-ApprovalPreview`, event 1001, carries timestamp,
device, authenticationResult, snapshotPath (null), requestId. Verified signatures are
labeled `approval_preview_verified`, never a completed Windows login. No camera
capture, passwords, biometric data, tokens or private keys are logged by this service.

## Future disposable-VM walkthrough

These steps are **unexecuted**, and are not physical-laptop setup instructions. Obtain
a Windows VM/checkpoint; verify PIN, known password and recovery access first. Do not
change LSA protection or Application Control policy.

1. Build inside the VM, use its own hosted desktop identity, and explicitly pair the
   phone. Do not clone the laptop's private keys/config. Disable the desktop's lock-event
   test prompts to avoid duplicate senders. Power/camera opt-ins remain separate.
2. From an elevated shell as that same paired Windows user, stage the existing config:

   ```powershell
   & .\build\windows\Release\PhoneUnlockPreviewStage.exe `
     --stage-preview-from-desktop "$env:LOCALAPPDATA\WINDOWS-UNLOCK\hosted\windows-config.dpapi"
   ```

   Staging does not register a provider/service and refuses existing enrollment.
3. Only in the disposable VM, review and run the preview installer:

   ```powershell
   .\windows\installer\Install-PreviewInVm.ps1 -DisposableVm -RecoveryVerified -WhatIf
   .\windows\installer\Install-PreviewInVm.ps1 -DisposableVm -RecoveryVerified
   ```

   Trusted payload signatures are required by default. An explicit VM-only
   `-AllowUnsignedDevelopmentBuilds` permits unsigned payloads only if existing
   policy allows them; it never changes policy. Physical machines are refused.
4. Manually lock the VM/select the tile and review/authenticate on Android. The
   preview should verify the signature and still require normal Windows PIN.
   Test denial/expiry, malformed/replayed responses, missing FCM, offline relay,
   stopped/crashed service, session switching and independent PIN/password sign-in.
5. Remove enrollment and stop the service before unpairing/replacing the VM identity.
   Frozen preview trust has no privileged revocation UX yet. Use elevated
   `Uninstall-Preview.ps1 -RemoveEnrollment` inside the VM. Loaded payloads retain
   an ownership marker for retry after normal sign-in.

Preview provider GUID/CLSID: `{8EE2412C-28C7-4F11-A7CD-2A99F95C8C11}`.
If LogonUI crashes, use the known password in VM Safe Mode/recovery or restore the
checkpoint. Remove only that GUID from `Authentication\Credential Providers` and
`SOFTWARE\Classes\CLSID` in the affected VM's registry, and stop/remove the
`WindowsUnlockPreviewService` service. Offline registry hives use a different mount
prefix; never apply VM removal instructions to the host's registry. PIN may be
unavailable in recovery. No broad provider/filter/LSA policy change is required.

## Actual Windows authentication gate

A Credential Provider gathers/serializes credentials; it cannot make Microsoft's
packages accept an arbitrary phone signature. Personal Microsoft-account compatibility
must be demonstrated independently. Microsoft signing alone does not establish it.

Before enabling serialization, implement and audit an accepted account-specific
mechanism. Independently bind proof to the enrolled SID, actual session/scenario,
pending nonce and a distinct Windows sign-in purpose; consume once at the authentication
authority and enforce local revocation. Never accept desktop-purpose proof or a service
Boolean as an LSA credential. Prove cold-boot versus unlock, token/profile/DPAPI,
cloud-account, UAC and account-policy behavior. Unsupported accounts fail closed;
no synthesized token, stored password or PIN simulation is an acceptable fallback.

If that mechanism uses a protected-LSA package, Microsoft's signing submission is
required. The user has no Partner Center hardware account/EV certificate. Independent
review, verified Android attestation, signed release builds, VM recovery/update tests
and production installer acceptance are also outstanding. No LSA DLL is implemented.

References: [Credential Provider boundary](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows),
[LSA callback](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-lsa_ap_logon_user_ex2),
[protected LSA](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection),
[LSA signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/file-signing-reqs).
