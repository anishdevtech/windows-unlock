# Version 0.5 verification — 2026-10-08

Implemented and built: optional encrypted-password Credential Provider/service,
local masked enrollment, Keystore-gated RSA release, delegated pre-logon requests,
relay routes and migration 004, bounded native diagnostics, installer/recovery tools.
Normal Microsoft providers/LSA security configuration were not changed.

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
  passed. The added V3 IPC test builds but is also blocked before execution;
  no success is claimed for that test. Installer preflight requires it to run.
- Android 0.5.0 APK builds; **10 JVM tests pass**, including delegated trust, RSA
  release and actual CNG-to-JCA RSA/AES-GCM interoperability. Android lint passes
  with existing warnings. Hardware BiometricPrompt is not exercised by JVM tests.
- PowerShell scripts parse; one-time setup `-WhatIf` causes no mutations. Installer
  status reports no new provider/service/vault installed or enrolled.
- Existing hosted desktop pairing is preserved; refreshed companion launches.
- Production migration 004 applied through the existing verified TLS database
  connection, without changing device rows or pairing trust.

**Actual observed blocker:** Application Control blocked the direct launch of the
unsigned readiness executable, `PhoneUnlockPasswordCheck.exe`, both rebuilt IPC
test executables, and an attempted load of `CredentialProviderPassword.dll`. The DLL loader
reported **0xc0e90002 (`STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION`)**; Windows Code
Integrity events 3077/3033 identify a signing-level/policy violation. The test harness
now suppresses modal loader error dialogs and reports an ordinary test failure;
this does not suppress policy enforcement. The rebuilt harness subsequently loaded
the DLL and passed. This does not establish OS acceptance of the remaining
executables or execution inside LogonUI. No trust roots, LSA/Code Integrity/App Control settings or policy exemptions
were added. Installer preflight stops before registering the tile when any required
program is blocked. A trusted/OS-permitted release is needed for deployment here.

No Windows password was entered during development. Native vault enrollment, machine
key creation under elevation, LocalSystem execution, real Microsoft-account logon,
first sign-in after reboot, resume, failure recovery and OPPO A5 Pro/Android 16 hardware
RSA/biometric behavior remain physical acceptance steps in the setup guide. No claim
of an already working automatic Windows unlock is made. The new APK is an update
artifact; no Android device was attached for automatic installation.

The initial test-cluster startup through a captured shell pipeline retained a child
output handle. The direct bounded SQL test run completed successfully; the cluster
was then stopped explicitly. This was a development harness process issue, not a
relay authentication failure or a production database error.
