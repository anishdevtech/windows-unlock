# Native authentication implementation and validation — 2026-10-04

## Implemented source and binaries

- `windows/authentication-package`: SSP/AP function table, LSA initialization and
  authentication callbacks, restricted caller checks, LSA-created ES256 challenge
  authority, atomic consumption, local enrollment revocation, live locked-console
  account/LUID/process binding and OS-derived token information.
- Separate `CredentialProvider.dll` serializes signed proof to the custom package ID
  and requests automatic submission only for the currently selected, approved tile.
  It performs no HTTP/camera/key operation. The old Preview DLL stays hard-disabled.
- `PhoneUnlockService.exe`: registered LocalSystem identity, restricted pipe, CNG
  signing under the paired session user, HTTPS relay/FCM delivery, independent phone
  verification and asynchronous LSA revocation. `PhoneUnlockStage.exe` stages protected
  public trust and machine-DPAPI transport configuration outside LogonUI.
- Relay and Android v0.3 support the separate `windows-unlock` request/response purpose.
  Desktop approvals cannot authorize Windows unlock. Existing remote-camera behavior
  remains in the unlocked desktop companion; the native path does not capture images.
- Build, EV-signed cabinet preparation, publisher signing, two-stage signed VM
  registration/activation and owned-component uninstall scripts.

MSVC x64 Release successfully compiled the actual DLLs, service, stage tool, preview
provider and all seven test executables. Static MSVC runtime; CFG/NX/ASLR/CET flags
enabled for actual DLLs/service/stage. No package/service/provider installation is
performed by a build or test.

## Executed checks

| Check | Result |
|---|---|
| Backend TypeScript build | Passed |
| Backend security suite, in-memory fixtures | 30 passed; includes unlock context and cross-purpose rejection |
| Android debug APK | Built, versionCode 3 / versionName 0.3.0 |
| Android JVM protocol tests | 6 passed, 0 failures/errors/skips |
| Android lint | 0 errors, 12 warnings (dependency/version and existing diagnostics) |
| Native pipe harness | Passed |
| Preview provider ordinary-process COM harness | Passed |
| Preview enrollment validation harness | Passed |
| LSA authority harness | Passed: nonce, account/session/LUID/scenario/LogonUI ID/creation binding, trust replacement, identity-key and desktop-purpose refusal, invented nonce, concurrent single-use consumption, cancellation, termination and monotonic expiry |
| Token information harness | Passed: existing process account SID preserved, explicit valid default DACL, no invented privileges, old logon SID removed; metadata only, no new kernel token |
| Actual SSP/AP ordinary-process DLL harness | Passed: actual exports/table initialization, restricted caller rejection, empty authentication-failure outputs and no session creation |
| Actual provider ordinary-process fallback COM harness | Passed: no provider filter/default/autologon without a verified response, visible PIN fallback, bounded empty serialization, callbacks on UI thread, teardown |
| New PowerShell scripts | Parsed without errors; physical-machine installer guard exercised with WhatIf and refused before mutation |

CTest finished with **6 passed and 1 not run**. `core_security` could not launch;
Code Integrity event 3077 recorded policy `VerifiedAndReputableDesktop` for
`core_tests.exe`. That check is **not a pass** in this run. No rename, trust root,
exclusion or policy change was used to evade the block. The remaining checks do not
substitute for all core tests. New LSA verification directly exercises the changed
cryptographic challenge/response code.

## Not exercised / not a production claim

No real LSASS load, LsaLogonUser, Windows token creation, LogonUI credential submission,
Windows unlock or protected-LSA integration occurred on the physical laptop. The DLL
test ran in a normal process with explicit mock LSA allocation/caller callbacks; it is
not evidence of protected-LSA compatibility. Authority tests use fixture keys/trust
and the current process's token metadata, not a live locked-session acceptance test.

No Microsoft signing account/certificate is present. Signing scripts were not run,
no submission was uploaded and no Microsoft-signed artifact exists yet. No disposable
VM was created. Install/rollback/reboot/uninstall/privileged-storage behavior requires
VM validation. The installer remains VM-only; no physical override is provided.

Personal Microsoft-account/SAM backing resolution, real Winlogon type/lifecycle,
existing-session profile and DPAPI continuity, API reentrancy inside LSASS, audit
behavior, failure/crash recovery and Windows updates remain unproven. Cold-boot phone
sign-in, domain/Entra/RDP support, LAN transport and independent Android key attestation
are not implemented. Hardware approval-key checks are enforced by the honest Android
app, not remotely attested by LSA. Do not label this production-ready or fully working
Windows sign-in until the applicable checks in [setup](lsa-signing-and-setup.md) pass.

No real notification, biometric authentication, power action or webcam capture was
triggered during this work. No ADB phone was attached. The hosted desktop companion
was kept running with its existing pairing and was not relinked/stopped. Local configs,
Firebase/private credentials and transport tokens were not committed.
