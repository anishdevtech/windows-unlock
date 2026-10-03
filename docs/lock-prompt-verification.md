# Lock-event prompt verification — 2026-10-04

The rebuilt companion adds an opt-in OS session-lock notification trigger. The
Credential Provider and actual Windows authentication mechanism remain unimplemented.
See `windows-sign-in-status.md` for the exact release gates.

## Passed

- MSVC x64 Release build of `phoneunlock.exe` and `core_tests.exe`.
- Release CTest security suite, including existing CNG, strict JWS/JSON, DPAPI,
  binding, expiry, cancellation and concurrent replay checks.
- New lock scheduling cases: off by default, pairing required, local console only,
  busy transition skipped without later retry, duplicate lock suppression, cooldown,
  next legitimate lock and no automatic request on observing an already locked session.
- OS session-state query available in the pre-final diagnostic build. Existing local
  state paired/transport configured, but its relay was unavailable. Hosted DPAPI state
  paired to the production URL and retained unchanged.
- Production relay `/health` returned HTTP 200 and `desktop-approval-only`.
- Read-only hosted DB check: active pairing and registered phone FCM token.
- Firebase dry-run validation accepted the token using the local operator credentials;
  no actual notification or authentication challenge was sent during this check.
- PowerShell parsing for setup/signing scripts and empty-variable removal behavior.

## Blocked or unverified

- Windows Application Control rejected the unsigned Release companion (event 3077,
  `VerifiedAndReputableDesktop`); it is not running. Its final UI/lock event delivery
  could not be exercised on this machine. A RelWithDebInfo test executable was also
  blocked. The normal Release security tests ran; no binary was relocated or policy
  changed to evade a denial.
- Publisher signing not executed: no current-user code-signing certificate with a
  private key was available. The signing workflow needs a real trusted publisher.
- No physical OPPO notification-display, tap/BiometricPrompt or actual session-lock
  acceptance test. A Firebase dry run is not a delivered popup.
- No real Windows unlock, Credential Provider registration, sign-in service, LSA
  package, VM sign-in/recovery validation or Microsoft signing submission.

Windows PIN/password and Microsoft Credential Providers were not changed.
