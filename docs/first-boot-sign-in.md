# Phone approval at first Windows boot

The desktop companion starts after Windows sign-in. Phone sign-in uses a separate
LocalSystem service and Credential Provider; it does not require the companion.
The service is configured for Automatic startup, without delayed start.

On the reported boot, Windows recorded startup at 20:20:10 IST on 11 October 2026.
The service process and `native_ready` diagnostic appeared at 20:20:28, followed
by `approval_failed` at 20:20:31 without `request_sent`. This confirms the service
started before login; it does not identify the exact failed network/crypto step.
The two retry gaps below were reproduced independently with controlled tests.

Native sign-in 0.6.1 fixes two startup failure paths found in the code:

- LogonUI previously attempted service discovery once. If the automatic service
  was still starting, the tile never rediscovered it. Discovery now retries on a
  cancellable worker for up to 90 seconds. It checks the protected automatic-request
  policy before sending a request. A disabled policy still sends nothing automatically.
- Wi-Fi/DNS can become ready later than the sign-in service. Temporary connection,
  DNS, timeout and server-availability failures now retry within the original
  60-second approval window. A lost POST response probes the same request ID before
  retrying; no new nonce/challenge or duplicate notification is created by recovery.

TLS certificate errors, authorization failures, invalid protocol data, denial,
expiry, cancellation and session changes still fail closed. Waiting does not block
LogonUI or normal Windows PIN/Password. Enrollment and signing keys are preserved.
The installer configures service recovery after crashes or service-reported failures.

Android 0.7.0 and the Windows companion 0.7.0 work with this native-only update.
On boot, ensure Wi-Fi is connected at the Windows sign-in screen. Phone approval
needs Internet access on both devices. If the request expires, select the phone
tile again or use normal Windows PIN/Password. No startup-folder application can
run before the user's first login, and no automatic password login is configured.

Validation covers a mock service appearing after tile enumeration, temporary
unavailable responses, disabled automatic policy, UI refresh, cancellation,
denial/expiry, one-time credential handoff, network recovery and uncertain POST
delivery. Real WinHTTP TLS trust, incorrect-pin rejection and HTTPS-only behavior
were checked against the live relay. Native installer checks verify machine-key
cryptography, provider fallback and IPC authorization before replacing binaries.
A real cold boot and phone approval remain a device acceptance check; the laptop
is not restarted automatically by this update.
