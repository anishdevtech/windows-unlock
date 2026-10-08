# Version 0.5 verification — 2026-10-08

Implemented and built: optional encrypted-password Credential Provider/service,
local masked enrollment, Keystore-gated RSA release, delegated pre-logon requests,
relay routes and migration 004, bounded native diagnostics, installer/recovery tools.
Normal Microsoft providers/LSA security configuration were not changed.

**Latest installed state:** the user completed the local enrollment/setup command.
Its elevated machine-key, crypto, COM fallback and V3 IPC checks passed. Read-only
verification confirms the new tile/COM path, `WindowsUnlockPasswordService` running
as LocalSystem with automatic startup, matching hashes for all seven native payloads,
and enabled built-in Hello PIN and Password providers. Smart App Control reports Off
following the user-selected change. No actual lock-screen unlock is claimed yet.

Observed automated results:

- Backend TypeScript build and **38 tests pass**.
- **23 security/vault tests pass against real local PostgreSQL**, including duplicate
  races, nonce uniqueness and terminal-state handling. One additional diagnostics
  test in the same 24-test run uses its isolated memory fixture. Only the explicitly
  named `windowsunlock_vault_test` database was truncated. The project-local test
  cluster was stopped afterward; production data was not used for these tests.
- Native Release build succeeds. An earlier **9-suite CTest run passed**. After the
  final rebuild, **8 suites passed and legacy native IPC was blocked by Application
  Control**. Current new vault cryptography/packing tests pass. The latest rebuilt
  password-provider DLL encountered a policy block during the COM fallback test.
  After rebuilding the harness with modal loader errors suppressed, that COM test
  passed. A subsequent bounded run of the added V3 IPC test also passed. The current
  three new-mode checks (vault crypto/packing, provider fallback, V3 IPC) pass.
  A later run after the user-selected Smart App Control change passes all three
  new-mode tests and the readiness executable. The initial Windows PowerShell 5.1
  staging parse error was corrected. The user then completed elevated staging,
  phone enrollment and installation; see the installed-state evidence above.
- Android 0.5.0 APK builds; **10 JVM tests pass**, including delegated trust, RSA
  release and actual CNG-to-JCA RSA/AES-GCM interoperability. Android lint passes
  with existing warnings. Hardware BiometricPrompt is not exercised by JVM tests.
- **10 setup-related scripts parse in Windows PowerShell 5.1**; installer status and
  the read-only readiness probe run in that shell, and setup `-WhatIf` causes no mutations.
  The Unicode arrow that caused a missing-string-terminator error when a BOM-less
  UTF-8 script was read as ANSI was replaced with ASCII. The packaging script's
  non-ASCII heading was also removed. Installer/service/registry read-only checks
  now confirm installation without changing Microsoft's normal providers.
- Existing hosted desktop pairing is preserved; refreshed companion launches.
- Production migration 004 applied through the existing verified TLS database
  connection, without changing device rows or pairing trust.
- Production relay `/health` returns HTTP 200, `runtimeVersion: 0.5.0`, region
  `bom1`. Unauthenticated vault polling/result/diagnostics routes return HTTP 401.
- APK application ID and signing certificate match 0.4; version code is 5 and
  software-key overrides are disabled. The allowlisted Windows ZIP manifest hashes
  verify; it includes no private configuration, Firebase/server credentials or LSA DLL.

**Actual observed blocker:** Application Control blocked the direct launch of the
unsigned readiness executable, `PhoneUnlockPasswordCheck.exe`, both rebuilt IPC
test executables, and an attempted load of `CredentialProviderPassword.dll`. The DLL loader
reported **0xc0e90002 (`STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION`)**; Windows Code
Integrity events 3077/3033 identify a signing-level/policy violation. The test harness
now suppresses modal loader error dialogs and reports an ordinary test failure;
this does not suppress policy enforcement. The rebuilt harness subsequently loaded
the DLL and passed, and V3 IPC later passed. A final probe still produced Code
Integrity 3077/3033 for `PhoneUnlockPasswordCheck.exe`. This was the original blocker;
the latest read-only probe now passes with Smart App Control reporting Off before
and after the probe on Windows 11 25H2, build 26200.9457. The active blocking policy's
local metadata identifies `VerifiedAndReputableDesktop`. No available trusted code-
signing identity was found in the current-user certificate store. This does not establish OS
acceptance of all installer executables or execution inside LogonUI. No trust roots,
LSA/Code Integrity/App Control settings or policy exemptions
were added by the software. The user-selected Smart App Control state now reads Off;
the software did not write the policy registry or change Windows Security settings.
Installer preflight stops before registering the tile when any required program is
blocked. Trusted publisher signing remains the option for keeping Smart App Control On.

No Windows password was entered through tools or chat during development. The user
entered it only in local enrollment; successful setup verifies it through Windows
and commits the phone-controlled encrypted vault. Machine-key preflight and
LocalSystem service startup are now confirmed. Actual Winlogon credential acceptance,
first sign-in after reboot, resume, failure recovery and the OPPO A5 Pro/Android 16
per-request RSA/biometric release remain physical acceptance steps. No claim of an
already working automatic Windows unlock is made. The user reports installing the
Android 0.5 update; no Android device was attached for automatic installation.

The initial test-cluster startup through a captured shell pipeline retained a child
output handle. The direct bounded SQL test run completed successfully; the cluster
was then stopped explicitly. This was a development harness process issue, not a
relay authentication failure or a production database error.
