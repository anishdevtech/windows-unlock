# Native preview verification — 2026-10-04

Scope: develop/build native components without installing them on the physical laptop.
This record does not claim actual Windows sign-in or VM/phone acceptance.

## Built

MSVC x64 Release, Windows SDK 10.0.26100.0, C++20: CredentialProviderPreview.dll,
PhoneUnlockPreviewService.exe, PhoneUnlockPreviewStage.exe, native_tests.exe,
provider_tests.exe, enrollment_tests.exe and existing core_tests.exe. The final
`Build-NativePreview.ps1` invocation completed successfully. No new-source compiler
warnings were reported. Nothing was registered/staged/installed by the build.

## Executed checks

| Check | Result |
|---|---|
| Existing core CNG/JWS/DPAPI/binding/replay/expiry/cancellation suite | Passed on final build |
| Real temporary-pipe IPC roundtrip, wrong server PID, fake production server, unauthorized caller, LogonUI impersonation attempt, first-instance collision, sign-in flag refusal, stalled dispatch deadline | Passed on final build |
| Fixed wire validation, terminated strings, version/scenario/GUID and reserved-byte rejection | Passed on final build |
| COM V2 enumeration/SIDs, no filter/default/autologon, selection starts async work, UI events on subscription thread, bounded submission, zero credential serialization, bitmap and teardown/unload | Passed before final reserved-wire-byte change; final DLL load blocked by Application Control |
| Enrollment schema/SID/UUID/token/HTTPS/private-key rejection executable | Compiled; execution blocked by Application Control |
| Build/install/uninstall/signing PowerShell parsing | Passed |
| Installer `-DisposableVm -RecoveryVerified -WhatIf` on this physical laptop | Refused before elevation/mutation, as intended |
| Own provider/COM registration, preview service, privileged enrollment on laptop | All absent (read-only checks) |

Before the final wire change, CTest core/native/provider all passed. The separately
added enrollment test was blocked. Final CTest: core 0.07s, native IPC 1.80s passed;
provider harness failed to load the DLL, enrollment process did not start. Therefore
the final suite is **not all passing**. Code Integrity event 3077 identified policy
`VerifiedAndReputableDesktop` for both the enrollment executable and final provider
DLL. No policy, exclusion, trust root, LSA protection or PIN setting was changed to
work around it; no binary was renamed/relocated as a workaround. Publisher signing
remains unavailable because no suitable certificate/private key has been supplied.

## Not executed / release gates

- No SCM service installation/start, privileged enrollment staging or Credential
  Provider registration. No real LogonUI, WTS user-key/profile or secure-desktop tests.
- No physical lock/push/BiometricPrompt walkthrough, VM creation, VM recovery,
  rollback/uninstall acceptance, offline/LAN acceptance or Windows-update testing.
- No signing/timestamp validation against an actual publisher certificate; installer
  and uninstaller mutation paths are sources, not tested installations.
- No custom LSA authentication package or Microsoft signing submission. Windows
  Microsoft-account compatibility, token/profile/DPAPI/UAC behavior, local production
  revocation, verified attestation and distinct sign-in-purpose protocol remain gates.
- No actual Windows credentials emitted. Approval-preview verification cannot unlock
  Windows. Windows PIN/password and Microsoft's providers were not modified.

The existing desktop companion, Android APK, backend and hosted enrollment remain
unchanged. This turn did not send an authentication request or access the webcam.
See [native development](native-development.md) for source behavior and future VM steps.
