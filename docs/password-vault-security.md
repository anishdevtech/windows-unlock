# Password-vault architecture and acceptance

The user chose this alternative after reviewing the encrypted-password approach
used by other phone unlock applications. Earlier password-free/no-stored-password
design notes remain historical; this explicitly authorized mode changes that tradeoff.

```text
Lock/startup event or Unlock with Phone tile (native COM, enrolled account)
  → SYSTEM-only local V4 pipe
  → PhoneUnlockPasswordService (SYSTEM, pre-logon)
  → delegated signed challenge → HTTPS/PostgreSQL relay → FCM notification
  → Android review → system BiometricPrompt → hardware Keystore RSA decryption
  → AES key wrapped to ephemeral Windows RSA → identity-signed response
  → Windows signature/expiry/binding/RSA/GCM checks
  → one-time Claim → OS-protected native credential → built-in Negotiate
```

New targets are `CredentialProviderPassword.dll`, `PhoneUnlockPasswordService.exe`,
`PhoneUnlockPasswordSetup.exe`, and `PhoneUnlockPasswordCheck.exe`. Existing stack:
C++20/MSVC/Win32/CNG/WinHTTP/DPAPI; Kotlin/Compose/AndroidX Biometric/Android Keystore;
Node 24/TypeScript/Fastify/PostgreSQL/FCM. API 35+ is required for the RSA Keystore MGF1
configuration. No custom authentication package is registered; protected LSA remains on.
No vendor code is copied. Publisher signing for distribution is separate from
Microsoft's signing of custom protected-LSA packages.

| Threat | Protection and limit |
|---|---|
| Replay/duplicate approval | Fresh UUID, random nonce, signed full challenge digest, unique DB nonce, locked terminal transitions, per-request ephemeral RSA, monotonic+wall-clock expiry, one-time Claim. |
| MITM/relay compromise | OS TLS/hostname validation; paired Windows root signs machine delegation; machine signs full request; pinned phone key signs exact release; GCM authenticates local password. The relay can suppress requests and observe metadata, but cannot decrypt the password or generate a working release. |
| Stolen transport token/phone identity signature | Cannot forge root/machine requests or decrypt phone-wrapped AES key. Identity key alone may cause denial of service with invalid responses, but GCM verification prevents sign-in. |
| Enrolling an attacker key | Requires a valid paired root delegation, explicit account review, and a biometric approval-key signature. Verified hardware attestation remains a production gate; the relay does not independently attest a malicious phone client's claims. |
| Password/key theft from disk | Password AES-GCM encrypted; AES key only phone-wrapped; machine DPAPI and SYSTEM/Admin protected storage. Machine signing key cannot decrypt the password. |
| Fake local pipe/client | First-instance pipe name ownership, remote clients rejected, SYSTEM-only DACL, exact System32 LogonUI image and console session, SCM-verified LocalSystem service PID, identification SQOS, enrolled SID and operation/caller binding. |
| Forgotten claim/dead LogonUI/session changes | Independent watchdog, explicit session cancellation, volatile RSA private key, bounded lifetime, cleared/wiped plaintext and packed buffers. |
| Tampered enrollment/binaries | Protected ProgramData/ProgramFiles, owner/DACL/reparse checks, signed delegation validation, hash manifest, load/crypto/COM preflight, fail-closed setup. Unsigned personal development still depends on the OS allowing the binary; no security policy is lowered. |
| Service/provider failure | Extra provider only; Microsoft providers preserved. No filter, permanent default override or PIN interception. Only verified approval requests the supported one-time automatic submission. Recovery disables only project GUID/service. Real Windows failure/backup testing still required. |
| Password changes/phone key loss | Windows rejects stale password; use normal PIN/password and reenroll. No silent password update or new PIN database. |

Administrator/SYSTEM compromise, a compromised OS/Keystore, same-user malware that
steals the password while it is typed, physical password observation and coercion
are outside these cryptographic guarantees. This is still password authentication:
existing Windows passwords remain phishable. After legitimate approval the password
briefly exists in privileged laptop memory. The AES key briefly exists in phone memory
while being rewrapped. Wiping buffers reduces exposure; it does not prove that an OS,
crash dump, library or hostile process cannot retain copies. No secret logging or
password upload is implemented. Hardware attestation is not presented as verified.

No guarantee of delivery latency: network, FCM, OPPO restrictions and Windows policy
can delay/drop notifications. The app requires tapping the notification/reviewing
the request before authentication; it cannot force an unsolicited system biometric
prompt from the background. Direct LAN is not implemented in this mode. Camera
sharing remains explicit, visible, time-limited and available only while Windows is
unlocked; sign-in does not start covert capture.

## Validation boundary

Automated tests cover actual CNG RSA/AES-GCM, tampered keys/tags/AAD, wrong recipient,
expired/misbound/extra-field responses, V4 status-vs-Claim frames, protected local
logon/unlock packing, OS online-identity credential packing, and COM fallback behavior.
Actual COM lifecycle tests with a different test-only provider GUID/mock pipe verify
unselected automatic requests, unchanged-user refresh, late Advise, field detach,
one-time serialization and rejection/expiry behavior. That test DLL and executable
are excluded from installation and packaging. A delayed pipe reader verifies that
responses survive until consumed; bounded acknowledgement prevents a stalled
caller from holding the server indefinitely.
Android JVM checks verify delegated trust, exact enrolled delegation, RSA rewrap and
CNG-to-JCA interoperability. Relay tests check authentication scope, forged messages,
secret/private-key fields, expiry, revocation, cancellation, duplicate races and logs.

These tests do **not** prove LogonUI/Winlogon accepted the credential on this personal
Microsoft account, that this phone's Keystore/biometrics work for RSA, or that boot,
resume, RDP/fast-user-switch and power-loss recovery are safe in production. RDP and
remote/disconnected sessions are intentionally rejected. A local physical-device
walkthrough and independent security review are still required. The provider is
not installed/enrolled merely by building, deploying the relay or installing the APK.

Microsoft documents the native formats and separate authentication authority:
[Credential Providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows),
[CredPackAuthenticationBufferW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credpackauthenticationbufferw),
[Credential Provider sample](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider).
