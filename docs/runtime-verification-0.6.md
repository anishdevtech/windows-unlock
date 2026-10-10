# Android redesign and Windows handoff repair, 0.6

## Observed failure

Read-only hosted diagnostics on October 11, 2026 (India time) show a native vault
request with phone approval and `approval_verified`, followed by no
`credential_submitted` event. Other recent approvals were desktop transport tests,
which cannot sign in to Windows. The installed Credential Provider DLL's SHA-256
differs from the existing build containing the LogonUI handoff/lifecycle fixes.
That update had been built but was still pending elevated installation.

Windows uses native credential serialization to submit the locally decrypted
password to Negotiate. Typing into the ordinary Password tile or simulating Enter
is not part of this flow. Select the additional **Unlock with Phone** option for
manual requests. With automatic requests enabled, the protected service and
provider share the request and use the supported one-time autologon callback.

## Changes

- Android 0.6 adds Unlock, Controls and Settings navigation, a device card,
  animated screen/request transitions, a smooth expiry bar and full-width approval
  buttons. Transport tests say explicitly that they cannot unlock Windows.
- Settings has opt-in **Floating approvals**, using Android's **Display over other
  apps** permission. A small animated card offers Review and Dismiss. Review opens
  the app to fetch/verify the request; approval still requires an explicit button
  and Android system authentication. The card has no account/password data and
  expires within 60 seconds. It is suppressed while the phone is locked or the app
  is in the foreground, and removed before system authentication.
- Signed push registration advertises `appHandledPush: true`. The relay sends
  data-only high-priority messages to those clients so FirebaseMessagingService
  can show the overlay and a normal notification. Older registrations retain the
  existing system-rendered notification payload. Both approval protocols use the
  capability; unauthenticated requests cannot set it. This change needs deployment
  to the hosted relay before background overlays can work.
- Android accepts the five-minute enrollment hint as well as 60-second sign-in
  hints. Denied notification permission does not prevent an explicitly enabled
  overlay. Android/OPPO restrictions can still affect delivery.
- Windows 0.6 retains the existing handoff/lifecycle repair and fixes explicit
  retry after Windows rejects a consumed credential. Rejection does not send a
  new request until the user retries. Desktop startup tests are suppressed while
  the password sign-in service is running, as lock-event tests already were.
  Both test settings show that they are paused while native sign-in is active.
  Companion diagnostics now detect the password service as well as the legacy
  service, fixing a misleading `native_unavailable` report.
- Android activity now names credential submission and Windows result events.

## Verification and rollout

- Windows native build and all four password-mode CTest groups passed, including
  background/manual approvals, late event attachment, UI re-enumeration,
  one-time claim, rejection, expiry and explicit retry. Tests use a mock service
  and test-only provider; they do not sign in to Windows.
- Backend TypeScript build and all 39 tests passed with an injected test store.
  Coverage includes signed capability registration and both push payload formats.
  An existing excessive-lifetime test now fixes both timestamps, avoiding a
  second-boundary race in its input.
- Android APK build, unit tests and lint passed. The debug APK preserves the
  existing application ID/signing key and keeps hardware-key enforcement on.
  No Android device or emulator is attached; on-device layout, overlay and OPPO
  delivery remain unverified.
- The native updater completed from the unlocked desktop with Windows administrator
  elevation. It checks existing registration/ACLs/hashes, stages and tests both
  native IPC sides, preserves encrypted enrollment, supports rollback and restarts
  only the project's service. Verify installed hashes and service status after it
  completes. This installation now reports 0.6.0, automatic requests enabled,
  matching installed/build hashes and a running WindowsUnlockPasswordService.
  Normal Windows PIN/Password remain available.

Install `WINDOWS-UNLOCK-0.6.0-debug.apk` over the existing phone app; do not uninstall
or reset pairing. Open **Settings → Floating approvals**, grant **Display over
other apps**, and allow ordinary notifications as fallback. The relay must report
`runtimeVersion: 0.6.0`; opening the app registers its new delivery capability.

From an already enrolled Windows installation, the update command is:

```powershell
.\windows\installer\Update-PasswordUnlock.ps1 -DevelopmentBuild -RecoveryVerified -AutomaticRequests On
```

`-RecoveryVerified` requires normal PIN and Password already verified by the owner.
Check a real lock-screen approval after updating. `approval_verified` alone is
insufficient: confirm Windows actually signs in, then inspect `credential_submitted`
and the Windows result. Do not describe physical sign-in as verified until that
test succeeds. Use PIN/Password if unavailable; refresh enrollment only if Windows
rejects a stale account password.

Primary references: [Android overlay windows](https://developer.android.com/reference/android/view/WindowManager.LayoutParams#TYPE_APPLICATION_OVERLAY),
[Firebase background message routing](https://firebase.google.com/docs/cloud-messaging/android/receive-messages),
[Windows credential autologon contract](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovider-getcredentialcount).
