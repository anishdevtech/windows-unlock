# v0.2 verification — 2026-10-03

Implemented hosted Fastify configuration/Vercel entry point, strict cloud PostgreSQL
TLS, shared SQL rate buckets, indexed device token lookups, Firebase Admin delivery,
Android FCM service/heads-up channel/notification permission/WorkManager token rotation,
biometric signed remote controls, tray companion, Media Foundation camera capture,
visible local camera permission and independent expiry/privacy watchdog, RSA-OAEP-256
and AES-256-GCM live preview. Windows configuration stays DPAPI-protected.

Passed checks:
- Windows Release build and CTest: local remote-lease bindings/disabled actions,
  expiry, replay and atomic duplicate consumption, plus existing CNG/DPAPI tests.
- Fifteen backend tests with memory and real native PostgreSQL: wrong signing key,
  changed action/bindings, duplicate races, expired/superseded offers, private viewer
  keys, ciphertext-only frame fields, counters/revocation and FCM failure after commit.
- CNG->Node RSA-OAEP(SHA256/MGF1-SHA256) and AES-256-GCM interoperability.
- Android/JCA decrypts CNG camera envelope and rejects a tampered GCM frame; this
  exercises the same CameraCrypto adapter used with Android Keystore.
- Android debug APK build, five JVM tests and lint with no errors (dependency notices
  retained). Native and JVM interoperability uses disposable software test keys.
- Existing ES256 and native WinHTTP HTTPS/pin rejection checks passed during the
  initial v0.2 run. The latest companion CLI HTTPS health check also passed. A final
  repeat of the separate rebuilt http_tests.exe was blocked by Windows Application
  Control (PowerShell reported the policy block; Node spawn reported UNKNOWN).
  Test.ps1 consequently reports failure for that final repeat. No OS security policy
  was changed or bypassed. A trusted/signed diagnostic build is a remaining check.
- npm runtime dependency audit: zero known advisories. Firebase Admin pulls an optional
  Storage dependency with gaxios 6/old uuid; a narrow uuid 11.1.1 override addresses the
  reported advisory without changing our protocol/crypto APIs. Storage is not used.

Not tested: an actual Vercel/VM/container deployment, real Firebase credentials/message
delivery, actual OPPO Android 16 hardware/Keystore/BiometricPrompt behavior, webcam
driver/indicator interactions, or sleep/shutdown/restart. Automated tests never execute
those OS power actions or activate the real webcam. Complete the physical acceptance
walkthrough in hosting.md before depending on these features.

The APK here is a debug build without google-services.json, so real background push
requires the documented Firebase project setup and rebuild. No Firebase project/cloud
host was created or billed, and no credentials were invented. The local database was
migrated for v0.2. The companion remains a desktop approval prototype; protected Windows
sign-in integration still has its separate account/LSA compatibility gate. Microsoft's
PIN/password/providers are untouched.

After verification the local test relay and PostgreSQL cluster were stopped. Run
scripts/Start-Local.ps1 to restart them and launch the updated companion. No active
camera or remote power request was created during this implementation.
