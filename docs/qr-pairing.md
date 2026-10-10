# Pair by scanning a QR code (Android and companion 0.6.1)

Existing paired devices do not need to pair again. Install the APK over the old app
to preserve pairing and phone sign-in keys.

For a new pairing:

1. Open the Windows companion and click **Pair phone**. A separate window displays
   the invitation QR code and its five-minute countdown.
2. In Android, tap **Scan laptop QR code** on the Unlock screen or in Settings.
   Point the scanner at the Windows code. Google Play services supplies the scanner;
   its first use may download the scanner module. If unavailable, retry with internet
   access and updated Play services, or choose **Import invitation file**.
3. Review the laptop name and approve pairing using Android system authentication.
4. Compare the code shown on Android with Windows' confirmation dialog. Confirm
   on Windows only when both match.

The QR code carries the same invitation as the JSON file. Both inputs enter one
strict parser, signature/expiry validation, review, authentication and comparison
flow. Scanning does not auto-approve trust. QR generation happens locally on Windows;
no invitation is uploaded to a QR-image service. The display closes on proposal,
completion, cancellation, expiry or companion shutdown. Oversized invitations fall
back to the file option.

Verification: Windows companion Release build passed; Android APK build, lint and
all 14 unit tests passed, including compact/file invitation equivalence, stale and
substituted signatures, unsafe relay origins and invalid QR inputs. Generated
1,046-byte and 2,196-byte sample QR payloads were independently decoded exactly with
ZXing-C++ at the integer pixel scales used by the Windows renderer. OpenCV could
not decode the larger-density samples, so this does not guarantee every third-party
scanner will work. Live Google scanner/phone-camera acceptance remains unverified
because no phone is attached.

Sources: [Google code scanner](https://developers.google.com/ml-kit/vision/barcode-scanning/code-scanner),
[Nayuki QR generator](https://www.nayuki.io/page/qr-code-generator-library).
