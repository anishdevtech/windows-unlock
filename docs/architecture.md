# Architecture and exact stack

## Phase 1

Native Win32 desktop UI -> reusable C++ authentication core -> HTTPS relay -> open
Android application -> Android Keystore Signature + system BiometricPrompt ->
signed response -> relay -> independent CNG verification on Windows.

Windows owns request creation, expiry and one-time consumption. Backend database
status is delivery information, never authority to unlock. Windows also signs
requests, so a compromised relay cannot invent a request from the paired laptop.

Windows: C++20, MSVC, CMake, Win32, WinHTTP, BCrypt, NCrypt, Crypt32, DPAPI,
nlohmann/json 3.12.0. Android: API 30+, Kotlin 2.2.10, AGP 9.1.1, Gradle 9.3.1,
API 36, Compose Material 3 (BOM 2025.10.01), AndroidX Biometric 1.1.0, OkHttp and Nimbus JOSE.
Backend: Node 24, strict TypeScript, Fastify 5, pg, jose, PostgreSQL 18. Exact
dependencies are pinned in package manifests, wrapper and lockfiles.

Phase 1 uses bounded HTTPS polling for delivery (one second, foreground app only).
This is deliberately simpler than two concurrent delivery transports. WSS becomes
a transport optimization alongside FCM; all transports share the same signed
messages and one-time request state. No test-only plaintext HTTP mode is provided.

## Production Windows boundary

CredentialProvider.dll -> restricted local IPC -> PhoneUnlockService -> core.
The DLL describes a tile, observes state and serializes accepted credentials; it
does not perform networking, snapshots, pairing or cryptography on LogonUI's thread.

A Credential Provider is not an authentication authority. An ES256 phone signature
is not a credential accepted by built-in Negotiate. Password-free local/MSA sign-in
requires a separately validated authentication path. Until that exists, real login
is disabled. Never disable LSA protection to load an unsigned package. Personal
Microsoft-account support and protected-LSA signing are unresolved release gates.

The native development implementation is `CredentialProviderPreview.dll` ->
SYSTEM-only message pipe -> `PhoneUnlockPreviewService.exe` -> existing CNG/WinHTTP
core. The service creates/verifies desktop-purpose challenges for a frozen enrolled
SID in an already signed-in, locked local console session. The provider reports
approval status and **always returns no credential**. It never selects itself as the
default, requests automatic sign-in, or filters other providers. Setup staging is a
separate elevated CLI, outside LogonUI. See [native development](native-development.md)
for identity checks, enrollment protections and release boundaries.

## Internet operation

Both apps connect outbound to a configured HTTPS hostname. DNS resolves the server
address; pairing maps the laptop to a phone installation. FCM registration tokens
are notification addresses, not authentication proofs. Internet deployment needs
an always-available relay, a hostname/certificate, PostgreSQL backups, secret
management, monitoring, and a Firebase project with restricted server credentials.
VM hosting is optional; the hosted relay role is necessary for this internet design.

The relay cannot sign as either endpoint. It can withhold messages and observe
metadata. TLS does not protect against a compromised endpoint or local administrator.

## Research sources (checked 2026-10-03)

Version 0.2 adds FCM/WorkManager background hints, a tray companion with signed remote
control offers, and encrypted live-camera envelopes. Hosting can use Vercel Fastify
or a TLS server/VM; state and rate limits stay in PostgreSQL. HTTP polling avoids any
dependency on a long-running host process. See hosting.md and the protocol's v0.2
sections. These additions do not resolve or install the Windows sign-in integration.

- https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows
- https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
- https://developer.android.com/reference/androidx/biometric/BiometricPrompt
- https://developer.android.com/privacy-and-security/security-key-attestation
- https://firebase.google.com/docs/cloud-messaging/android/get-started
- https://firebase.google.com/docs/cloud-messaging/send/v1-api
- https://firebase.google.com/docs/cloud-messaging/customize-messages/setting-message-lifespan
- https://www.rfc-editor.org/rfc/rfc7515.html
- https://www.rfc-editor.org/rfc/rfc7518.html
