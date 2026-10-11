# Audio, video and Android updates — 0.7

Install Android 0.7.0 over the existing app; keep its data and pairing. Replace the
Windows companion with 0.7.0. The installed 0.6.0 Windows password provider/service
and encrypted enrollment do not need reinstalling.

## One-time Windows setup

Open the existing **WINDOWS-UNLOCK Hosted** desktop shortcut. Choose **Wi-Fi setup**
and approve Windows elevation. This adds an inbound UDP rule for this executable
only, ephemeral ports 49152–65535, with remote addresses limited to LocalSubnet.
It supports Wi-Fi classified Public without changing that classification or
disabling the firewall. Extract the complete release bundle so the setup script is
available. The source checkout also contains `scripts/Enable-DirectMedia.ps1`.
Pass `-Remove` to that script to remove the rule for the selected companion path.

Enable **Allow my phone to play audio through laptop speakers** and/or **Allow
laptop microphone sharing**. Each permission is initially off and separate from
camera sharing. Windows must be unlocked. Sharing starts only after a signed
phone command authenticated using Android system authentication. A visible
sharing window appears before device activation; close it to stop/revoke that
permission. Locking Windows, disabling the permission or exiting the companion
stops media capture/playback. No audio/video recording is saved.

## Phone audio → laptop speakers

Connect both devices to the same Wi-Fi. In Android **Controls**, choose **Play
phone audio on laptop**, grant Android's audio/capture permission and authenticate.
Choose the entire screen in Android's capture dialog for audio across apps. The
app creates no virtual display and sends no screen images. Start music after the
notification reports connected. Audio continues while other apps are open; stop
from the notification, Controls or the Windows sharing window. Maximum duration
is ten minutes. Output uses the Windows default speaker device.

Playback capture copies permitted media/game audio. Apps can prohibit capture;
calls, protected/DRM content and other unsupported usages are not captured. Audio
may also continue playing locally on the phone. This feature does not bypass an
app's capture restrictions. Android's capture indicator and consent are required.

## Laptop microphone → phone

Choose **Listen to laptop microphone**, confirm and authenticate. Sound uses the
Windows default input device and phone's current media output (speaker/headset).
Windows desktop microphone privacy permission must allow access. Audio continues
in the Android foreground service for up to ten minutes. No phone microphone is
used in either mode. Only one audio/video mode is active per laptop at a time.

Direct media requires private IPv4 addresses, compatible routes, and Wi-Fi that
permits device-to-device traffic. Guest Wi-Fi/client isolation can block it. Audio
has no Internet relay fallback. There is no router port forwarding requirement.

## Faster video

Direct encrypted Wi-Fi preview targets 640×480 at up to 15 fps. A continuous Media
Foundation reader keeps only the newest sample; capture selects a small native
mode, reuses its WIC factory, and reduces JPEG quality for oversized images. No
old-frame queue grows behind a slow connection. UDP fragments stay below common
network MTUs and late/incomplete frames are discarded.

If a verified LAN handshake is unavailable, camera preview falls back to encrypted
HTTPS at 320×240 and up to 5 fps. Unchanged frames return an empty response when
the viewer supplies its last sequence number. Relay latency can reduce this rate;
this is not a 30/60 fps video codec. Install both 0.7 clients: old Android viewers
accept only 120 relay frames and may stop early with the newer sender. Each camera
session still expires after 60 seconds. Closing the view sends UDP and authenticated
relay stop requests; an interrupted relay-only viewer may leave capture active
until its deadline if no stop request can reach Windows.

## Android updates

Install 0.7.0 manually once to acquire the updater. Settings then provides automatic
checks/downloads on unmetered networks (daily and when opened), a manual check,
and **Install** for a downloaded update. Android battery/network scheduling can
delay background checks. Notification permission is needed for update alerts;
downloaded updates are also shown in Settings. The first installation from this
app requires enabling Android's **Allow from this source**; return and tap Install.
Android always retains its installation confirmation in this distribution.

The public feed is `android-updates/stable.json` on this repository's main branch.
APK downloads come from this repository's GitHub Releases. The downloader checks
bounded size, SHA-256, exact package name, increasing version code and the same
APK signing certificate as the installed app. Checks run again before opening
the system installer. Cache eviction can require downloading the APK again.
Keep the existing Android signing key for future updates; do not commit that key.

## Verification

Backend tests cover signed command/descriptor binding, key substitution, restricted
LAN endpoints, delivery after Windows acceptance, expiration, idempotent stop,
revocation and frame counter/polling limits. Native tests exercise real UDP
handshake authentication, replay rejection and valid/forged stop packets. JVM tests
cover bounded fragment reassembly, packet tampering/directional keys, update feed
restrictions and CNG↔JCA packet interoperability. Android assembly/lint are checked.

No physical phone is attached through ADB in the development session. Real phone
capture, OEM foreground-service behavior, audio quality, actual frame rate and
the complete Android installation UI still need device acceptance. Do not treat
the target frame rates or automated protocol tests as measured phone performance.
