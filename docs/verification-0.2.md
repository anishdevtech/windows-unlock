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

## Vercel entry-point correction — 2026-10-04

The first cloud build reported that src/server.ts did not import Fastify directly.
Vercel's Fastify detector examines that file, not its transitive imports. server.ts
now directly constructs Fastify with shared serverOptions and then registers the
same protected routes through configureApp. TypeScript build and 17 backend tests
passed, including the entry-point detection contract and route-registration checks.
Native/Android code was unchanged; those builds were not repeated. Cloud redeployment
of this correction has not been performed by the agent.

## Hosted PostgreSQL certificate correction — 2026-10-04

The operator's subsequent Vercel build/deployment succeeded, but runtime startup
reported a self-signed certificate chain. The local operator configuration identifies
Aiven PostgreSQL; Aiven's official Node.js guide requires its project CA with
certificate verification enabled. The host's actual environment and database connection
have not been inspected or tested by the agent.

CA configuration now validates PEM certificate bundles and accepts multiline or
quoted/escaped-newline dashboard values. Empty environment values can fall back to
the protected operator config. Remote connections retain certificate/hostname
verification and remove URL parameters that could override the explicit TLS settings.
Startup errors explain missing trust without logging provider messages or credentials.
The hosting guide includes the Aiven CA download and Vercel redeployment steps.

TypeScript build and all 23 backend tests passed, including six new database
configuration/error regression checks. These are local tests, not confirmation of
a successful hosted connection. Native and Android code were unchanged and were
not rebuilt. The operator must supply the correct CA in Vercel, redeploy and verify
/health; migrations and device/Firebase setup remain required before real-device use.

## Firebase credential startup correction — 2026-10-04

The next operator-provided Vercel log reaches Firebase initialization and exits because
the supplied service-account object lacks a string project_id. Push initialization
now validates the downloaded Admin credential shape, checks that its project_id
matches FIREBASE_PROJECT_ID, and isolates invalid/absent credentials from relay startup.
Warnings contain fixed setup guidance without SDK exceptions or credential contents.
Vercel with no service-account credential keeps push disabled; other hosts retain
support for Google application-default credentials. Project-specific named Firebase
apps avoid reusing an unrelated application's credentials.

TypeScript build and all 26 local backend tests passed. New checks exercise malformed
JSON, Android client JSON, missing fields, bad keys, mismatched projects, healthy and
protected relay routes despite invalid push configuration, and valid initialization
with a generated test-only RSA key. No private service account or live FCM call was
used. Actual hosted deployment and delivery still require operator configuration,
redeployment and physical-phone checks. Native/Android files were unchanged.

## Local run with operator-provided hosted credentials — 2026-10-04

The operator supplied an ignored backend/.env for local testing. Node's environment
parser loaded only four characters of the service-account value because its JSON was
wrapped with conflicting double quotes. The original file was preserved in an
access-restricted ignored runtime backup; the credential object was normalized to a
single-quoted JSON environment value and verified to round-trip without changing
its contents. Credential contents were not printed or committed.

The real Aiven PostgreSQL connection succeeded with encrypted transport and a verified
certificate. Firebase Admin initialized and exchanged the supplied service-account
credential for an access token successfully. This authenticates the account; it does
not confirm FCM permissions or notification delivery to the physical phone.

The hosted app schema was absent. Both repository migrations were applied, creating
the app tables and indexes without deleting existing data. The relay was started
locally on loopback with HTTPS at https://localhost:9443. Verified TLS HTTP requests
returned 200 and status ok on /health, and 401 on both protected pending-approval and
remote-offer routes without credentials. These requests exercised the real hosted
database rate-limit path. The local process was left running for the operator.

Start-Hosted-Local.ps1 supplies a repeatable local run using explicit .env loading and
the provisioned development certificates. This local-host test still needs internet
to reach the hosted database and Firebase. No Windows account, PIN, companion pairing,
camera or power setting was changed. Vercel execution remains a separate check.

## Vercel intercepted-listen startup correction — 2026-10-04

The signed-in Vercel dashboard showed the latest cea17bd deployment still returning
INTERNAL_FUNCTION_INVOCATION_FAILED with no application exception and requests waiting
for a response. The upstream Node handler intercepts http.Server.listen during module
import and returns the server without invoking its callback/listening event.

A local reproduction using the actual compiled entry point and operator credentials
captured the server but never completed module import before the diagnostic timeout.
The managed startup path now completes route readiness, starts listening without
awaiting the intercepted promise, and allows module import to finish. Standalone TLS
startup retains its awaited bind behavior. A regression test reproduces the capture,
then starts the captured server as Vercel does and checks health/protected routes.

TypeScript build and all 28 backend tests passed. The corrected actual entry point was
also exercised with the real hosted database under the interception harness: module
import completed, /health returned 200 and unauthenticated approval polling returned
401. Neither harness sends push messages or changes laptop power/camera state.
