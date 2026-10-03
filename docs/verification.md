# Phase 1 verification — 2026-10-03

Implemented and built the C++ desktop/core, Kotlin Compose APK, TypeScript HTTPS relay,
native PostgreSQL schema/bootstrap, bilateral manual pairing, per-operation approval
signatures, signed denial, local revocation, expiry/cancellation and restricted setup.

## Passed checks

- Windows Release build; CTest security suite: CNG ES256, SHA256 vector, strict JSON/JWS,
  DPAPI roundtrip/corruption, binding rejection, cancellation, expiry and concurrent
  one-time consumption.
- Ten backend tests passed with both dependency-injected memory and native PostgreSQL
  18.3. SQL private-key CHECK, duplicate transactions, replay, wrong bindings/signatures,
  lifetimes, cancellation, revocation and enrollment-secret reuse are covered.
- Android debug APK assembly, four JVM protocol tests, and Android lint (no errors).
  Dependency-update notices are retained because the pinned stack targets installed
  SDK 36; a newer Compose BOM required SDK 37. Dependency upgrades remain reviewed changes.
- Node signatures verified by Windows CNG and CNG signatures verified by Node jose.
- The Android/JCA signing adapter's DER -> 64-byte JWS signature verified by Windows.
  JVM testing validates the adapter, not hardware or BiometricPrompt operation.
- Native WinHTTP connected to the trusted development relay; wrong pin and plaintext
  rejected. An isolated TLS server observed exactly one HTTP request: the incorrect-pin
  request was stopped before HTTP Authorization/body transmission.
- Desktop CLI health check succeeded against the real HTTPS/PostgreSQL relay.
- npm runtime dependency audit reported zero known advisories at the time of checking.
- PowerShell setup scripts parsed; full provisioning completed without registration
  of Credential Providers/filters, LSA packages, or changes to PIN/password configuration.

## Remaining verification and release gates

The planned test phone is an OPPO A5 Pro running Android 16 (user reported), above the
Android 11 minimum. No physical Android phone was attached. System biometric/device-credential prompting,
TEE/StrongBox behavior, paired device UX, Android lifecycle and real Wi-Fi delivery need
the real-device walkthrough in setup.md. No claim of production-ready Windows unlocking
is made. Independent attestation is still required before real sign-in integration.

FCM/background notifications, WSS/direct LAN optimization, QR scanning, snapshots,
Credential Provider/authentication-package integration and release installer belong to
the subsequent documented phases. Internet deployment and Firebase are not provisioned.

Current runtime is local development only; sensitive data is in ignored owner-restricted
`.runtime`. A development CA was added to CurrentUser trust and can be removed with the
provided script. PostgreSQL is a project-local cluster, not a Windows service. Test relay
and database are stopped after verification; Start-Local.ps1 restarts them.

Portable PostgreSQL test archive was fetched over HTTPS from EDB:
https://get.enterprisedb.com/postgresql/postgresql-18.3-1-windows-x64-binaries.zip

Observed SHA256: `4da1a93cbc69e99936616d53c34466f79e4295fc56134ce4a395e88351213d60`.
This is an audit record, not an independently supplied publisher signature; the portable
postgres.exe is unsigned. Production dependency sourcing and patch review remain release
requirements. The archive/tool extraction is ignored and is not part of the source repo.
