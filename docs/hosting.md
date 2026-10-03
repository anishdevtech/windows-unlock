# Hosted relay, Android popups and laptop controls

This version supports an internet-reachable HTTPS relay, FCM background notification
handling, signed laptop power controls and an encrypted low-frame-rate live webcam
preview. It still does not sign in to Windows. No PIN/password settings are changed.

## Deploy to Vercel

1. Create a managed PostgreSQL database. Use a production database separate from the
   local `_test` database. Use a pooled connection URL and TLS with certificate validation.
   If the provider has a private CA, supply its PEM as `DATABASE_CA_PEM`.
2. Import the repository into Vercel and choose **backend** as the Root Directory.
   Node 24, Fastify framework and `backend/vercel.json` are provided. `src/server.ts`
   is the server entry point. Vercel terminates HTTPS; this code accepts HTTP internally
   only when its `VERCEL=1` platform environment is present. Clients always require HTTPS.
3. Set `DATABASE_URL`, `FIREBASE_PROJECT_ID`, and `FIREBASE_SERVICE_ACCOUNT_JSON` in
   Vercel's protected environment settings. Do not put service credentials in Android,
   invitations, frontend bundles, Git or chat. Preview deployments must use separate DBs
   and Firebase projects, or be disabled for this personal relay.
4. Before serving real traffic, run migrations from a trusted operator machine. Set
   `DATABASE_URL` in that terminal through your secret manager or protected environment;
   from `backend` run `npm ci` then `npm run migrate`. Commands do not print the URL.
5. Deploy and verify `https://YOUR-HOST/health`. Turn off deployment-login protection
   only for the intended production API; every device route still requires its own
   scoped bearer token and cryptographic proof. Add hosting firewall/rate limits.
6. Run `npm run bootstrap -- <windows-public.json> <restricted-bootstrap.json>` against
   the hosted database to register your laptop's public key. Import that bootstrap file
   with the Windows client `--configure` command and then delete it securely from the
   transfer locations. There is deliberately no public self-service registration route.

If Vercel reports **No entrypoint found which imports fastify**, update to the fixed
`src/server.ts` which directly imports and constructs Fastify. The builder checks the
entry-point file's text, so a Fastify import only in `relay.ts` is insufficient. Keep
Root Directory **backend**, Framework **Fastify**, Build Command **npm run build**,
and Output Directory unset. Commit/push the fix and deploy the new commit; redeploying
the old failed commit does not pick up local changes. Verified against Vercel's
[Fastify builder source](https://github.com/vercel/vercel/blob/main/packages/fastify/src/build.ts).

There are no long-running server tasks or local state required on the host. State and
rate-limit buckets are PostgreSQL-backed. FCM delivery occurs after challenge commit;
failure cannot approve, roll back or extend a request. HTTP polling also works on
serverless hosting. Budget for database connections and live-preview request bandwidth;
preview is at most two frames/second, and normally slower over a distant relay.

Run `npx tsx src/cli.ts prune` daily from a trusted scheduled operator environment to
remove expired encrypted frames, old transport rows and rate buckets. The read routes
reject expired sessions even before pruning. The database holds one latest encrypted
frame per session, not a playable video recording. Backups may retain ciphertext until
their own retention expires; do not describe cloud storage as zero-retention.

## Regular server / VM alternative

`backend/Dockerfile` builds a non-root Node image. Supply a restricted relay config via
`PHONEUNLOCK_CONFIG`, a PostgreSQL URL, and mounted TLS certificate/private-key paths
(`tlsCert`, `tlsKey`, `host: "0.0.0.0"`, `port: 8443`). Expose only HTTPS; keep database
access private. Run the built CLI migrations before traffic, renew TLS certificates and
restart/reload the relay as appropriate. Never set `VERCEL=1` on a public standalone VM.
The Docker recipe is supplied; a container/cloud deployment has not been exercised here.

## Point Windows and Android at your hosted URL

Close the Windows companion (right-click tray -> Exit). Unpair on the old relay before
switching, and reset Android pairing. Export the Windows identity using `--public`.
After operator bootstrap, configure the same identity for the hosted URL:

```powershell
# Run from the project folder; create an empty CA file for public system trust.
New-Item -ItemType File .runtime\system-ca.pem
Start-Process .\build\windows\Release\phoneunlock.exe -ArgumentList '--state .runtime --relay https://YOUR-HOST system .runtime/system-ca.pem' -Wait
Start-Process .\build\windows\Release\phoneunlock.exe -ArgumentList '--state .runtime --configure .runtime/hosted-bootstrap.json' -Wait
Start-Process .\build\windows\Release\phoneunlock.exe -ArgumentList '--state .runtime'
```

`system` uses normal OS certificate-chain and hostname checks; it does **not** disable
TLS validation. Hosted certificates may rotate, so pinning a shared Vercel edge leaf
key permanently is unsuitable. Device signatures are still verified with the keys
confirmed during trusted bilateral pairing. The local development relay retains its
explicit SPKI pin and project CA. Re-pair Android using a newly exported invitation.
Do not keep using the old LAN invitation or copy the full local database to the cloud.

## Firebase setup (needed before background popups can work)

1. Create a Firebase project. Add an Android app with package `dev.windowsunlock.phone`.
2. Put its `google-services.json` in `android/app/`. It contains client project identifiers,
   not your server's private key. This file is ignored in Git. Rebuild/install the APK.
   Builds without the file still support foreground approval and explain that push needs setup.
3. Enable Firebase Cloud Messaging HTTP v1 and create a narrowly scoped server service
   account for message delivery. Prefer managed workload credentials where supported;
   otherwise place its private JSON only in the host's protected environment variable.
4. On the phone select **Enable popup approvals**, allow notification permission, and
   leave the approval notification channel at High importance. Keep Google Play services
   available. Token refresh is registered with signed identity-key proof via WorkManager.
5. Background the app and request approval from Windows. Tap **Review & approve** on
   the heads-up popup, check the verified laptop request, then press Approve to open the
   real system BiometricPrompt. Notifications alone never authorize anything.

Android decides whether a heads-up popup appears (DND, channel settings, battery policies,
network availability). Force-stopping the app prevents FCM delivery until it is reopened.
OPPO battery restrictions may delay delivery; test default settings first, then use the
phone's app battery settings if needed. No overlay or full-screen-intent permission is used.
Android reserves automatic full-screen interruptions mainly for calls and alarms.

## Phone controls and live camera

Enable **Allow phone lock / sleep / shutdown / restart** on the laptop. The signed
commands need a fresh system biometric/device-credential approval each time. Windows
uses its native APIs; no shell command supplied by the phone can run. Shutdown/restart
are not forced and Windows/apps can decline them. Sleep, shutdown and restart terminate
connectivity; Wake-on-LAN and automatic startup after reboot are not implemented.
Start the companion again after reboot. Close-to-tray keeps power controls available.

Live camera additionally requires **Allow live camera** on Windows, an unlocked active
session, a visible companion window, an available webcam, and Windows camera privacy
permission. It opens the selected webcam only for the approved viewing session; it
cannot extract another application's camera stream or bypass its privacy controls.
The desktop shows **CAMERA STREAMING TO YOUR PHONE**. Untick sharing, minimize/hide
the window, lock Windows or exit the companion to stop. Sessions expire after 60 seconds.
The phone's Stop camera button stops local viewing immediately and sends an authenticated
stop command if an offer is available. Otherwise the laptop's expiry remains the stop bound.

Preview is 320x240 JPEG, up to 2 fps over HTTPS, not WebRTC/audio or a smooth 30 fps stream.
Windows encrypts every frame with a fresh AES-256-GCM session key and unique IV/AAD.
That key is wrapped with RSA-OAEP(SHA256, MGF1-SHA256) to an ephemeral **Android Keystore**
public key bound into the biometric-signed command. The server sees ciphertext only.
Android rejects tampering and duplicate frames. Live camera requires Android 15+ for
explicit OAEP MGF1 authorization; your reported Android 16 meets this version gate.
Physical Keystore, webcam and notification checks are still required before release.

## Acceptance checks

- Start with Lock, then recover using normal Windows PIN. Save your work before testing
  Sleep / Shutdown / Restart. These power actions were not executed during automated tests.
- With permissions off, controls must be unavailable. Replay a command, alter an action
  or sign with the identity key: the laptop must reject it.
- Test FCM with Android backgrounded, locked, DND, denied notification permission,
  delayed messages and token refresh. Expired requests must never approve.
- Explicitly enable camera, view from your OPPO, then stop from both devices; minimize,
  lock and unplug the webcam during viewing. Check the visible indicator and 60s limit.
- Repeat over mobile data after deployment. No port-forwarding or inbound laptop listener
  is required; both devices make outbound HTTPS requests.

Sources checked 2026-10-03:
- https://vercel.com/docs/frameworks/backend/fastify
- https://firebase.google.com/docs/cloud-messaging/android/receive-messages
- https://firebase.google.com/docs/cloud-messaging/android-message-priority
- https://developer.android.com/about/versions/14/behavior-changes-14
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-lockworkstation
- https://learn.microsoft.com/en-us/windows/win32/api/powrprof/nf-powrprof-setsuspendstate
