# Runtime update 0.4

See [verification results and remaining device checks](runtime-verification-0.4.md).

This update improves the desktop companion and Android approval app. It does not
activate Windows sign-in. The native provider, broker and authentication package
are separate components. On the current laptop they remain uninstalled. A
Microsoft signature, protected-LSA testing and account compatibility validation
are still required; see [native setup](lsa-signing-and-setup.md). The implemented
native design targets an existing locked session, not first sign-in after reboot.
Windows PIN/password continue to work independently.

## Update the server and both clients

1. From `backend`, with protected operator settings in `.env`, run
   `node --env-file=.env --import tsx src/cli.ts migrate`. This adds migration 003
   without resetting identities or pairings. Deploy the updated backend.
2. Build Windows using `scripts/Build.ps1`. Exit the existing companion from its
   tray menu before replacing its executable.
3. Install the new Android APK as an update over the old app. Keep the same signing
   key and application ID to retain pairing. Do not clear its storage.
4. Run `scripts/Setup-HostedWindows.ps1 -AutoStart -Launch`. Existing hosted pairing
   is preserved. The startup shortcut starts the companion **after Windows sign-in**.
5. In the companion, use **Check connection** to verify relay health and whether
   the phone has registered an FCM token. Uploading diagnostics is visibly enabled
   by default in this update and can be disabled in the permissions section.

## Notifications

The relay sends a high-priority FCM notification plus an untrusted request ID.
Android renders notifications when the app is in the background. Tapping one opens
the app to fetch and verify the laptop's challenge before showing approval controls;
Approve still invokes the system BiometricPrompt. No background automatic approval
or unrestricted full-screen activity is used.

In Android, select **Enable popup approvals**, then **Open notification settings**.
Allow notifications and banners and keep the approval channel at high importance.
On OPPO, allow this application's background activity if its battery management
delays delivery. Force-stopping the app, disabling notifications or Do Not Disturb
can suppress banners. FCM acceptance is not proof of on-screen display. The app's
status distinguishes channel/permission problems and registration failures.

The lock-event switch sends one desktop test per eligible lock event, with cooldown
and OS session-state validation. The optional startup switch sends one test after
the startup shortcut runs following sign-in. Neither event unlocks Windows with the
desktop companion; the UI states this explicitly.

## Live camera preview

Enable camera sharing explicitly in the Windows companion. Windows must be
unlocked. Allow camera access and desktop-app access in Windows Camera privacy;
close another camera application if it holds exclusive access.

The companion can stay in the tray. When a biometrically signed camera command
arrives, it creates a separate visible, topmost sharing indicator **before** opening
the camera. Capture requires that indicator to remain visible. Its **Stop sharing**
button immediately revokes permission; the watchdog shuts down the camera even
while a network request is waiting. Locking Windows, exiting the companion or the
60-second deadline also ends capture. Re-enable sharing after using the local Stop
button to authorize another session.

Media Foundation captures frames; WIC generates a 320×240 JPEG preview at up to
2 frames/second. This remains a bounded live preview, not full-frame-rate WebRTC.
RSA-OAEP SHA-256/MGF1-SHA-256 wraps an AES-256-GCM session key to a temporary
hardware-backed Android Keystore key. A Windows-signed camera envelope binds the
wrapped key to the exact phone command and pairing. The phone verifies that
signature before unwrapping the key. This prevents a compromised relay from
substituting its own encryption key. Frames are authenticated, counter-checked and
expire; only the latest ciphertext is held by the relay. No recording is written.
Both clients must be updated for this signed envelope protocol.

## Diagnostics and performance

The companion uploads signed, bounded batches of application event codes every
15 seconds. Each event includes an ID, time, level, optional request ID and optional
duration. A DPAPI-protected queue retains at most 256 events while offline.
Disabling uploads clears the queue and stops future collection. An already-sent
batch cannot be withdrawn. Android **Activity & diagnostics** reads recent events
only for its active pairing.

The server rejects free-form messages and extra fields. Windows credentials,
transport tokens, private keys, biometric data, camera images and arbitrary Windows
event logs are excluded. Seven-day-old diagnostics are pruned on uploads for that
device; reads exclude them immediately. For devices that never upload again, run
`node --env-file=.env --import tsx src/cli.ts prune` daily from your protected
operator job to remove retained expired rows. This update does not silently create
an external scheduler or transmit unrelated system logs.

WinHTTP reuses connection/session handles while still checking TLS and certificate
pins on every request. Approval tests no longer stop the remote-control worker.
Read polling uses bounded indexed pending-row queries rather than loading the
complete historical request/command lists. Camera command polling is separated
from frame uploads, and offline retries back off. Network RTT, Vercel cold starts,
FCM delivery and OS battery restrictions still affect latency.

## Verification limits

Builds and automated protocol checks cannot prove a popup appeared or that this
OPPO model's hardware Keystore supports the viewer key. Test notification tapping,
approval, denial, lock transitions, camera start/stop and local permission revocation
on the actual phone. Test native sign-in only in a recovery-equipped VM after the
signed-package and account compatibility gates have passed. Never disable App
Control or LSA protection to make unsigned development binaries run.
