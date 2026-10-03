# Threat model

Version 0.2 extends the attack surface to remote power commands and live webcam:
every command requires a fresh approval-key signature over a locally pending
Windows offer and action allowlist. Identity/token/notification possession alone
cannot operate the laptop. Camera requires separate local consent, visible window,
unlocked session, a short watchdog deadline and public-recipient key binding.
The relay stores only encrypted latest frames; it can suppress/replay delivery but
cannot decrypt or forge camera data. Existing frame counters/AAD reject tampering
and replay. Device/OS administrator compromise remains outside this trust boundary.
FCM/hosting credentials require restricted server storage and rotation. Force-stop,
DND, OS battery policies, network outages and unavailable cameras cause availability
failures. No remote wake or forced shutdown is implemented. Physical acceptance is
required before enabling these controls; Windows PIN is independent throughout.

Assets: approval key, Windows identity key, local pairing trust, outstanding request,
transport tokens, future Windows account/session binding, audit metadata and snapshots.
Boundaries: Android hardware/OS, Windows user process (later service), untrusted network,
relay/database, and eventually LogonUI/LSA. The Phase 1 UI has no Windows logon authority.

| Threat | Control and remaining limitation |
|---|---|
| Replay, races, late reply | 32-byte nonce, unique UUID, exact request digest, 60s expiry, monotonic Windows deadline, terminal-state checks. Restart discards outstanding requests. |
| MITM | TLS >=1.2, hostname/chain validation and certificate pin. Peer keys confirmed on both screens. Never accept all certificates. |
| Compromised relay | Signed laptop requests and phone responses; trust anchors stored locally. Relay can cause denial of service and expose metadata. |
| Stolen transport token | Scoped and hashed tokens, signed messages, revocation and rate limits. Token alone never signs approval. |
| Malicious pairing client | Single-use 5-minute invitation, proof of key possession, 64-bit displayed transcript comparison, explicit confirmation on both screens. |
| False hardware/biometric claim | Phase 1 only reports Android KeyInfo; verified attestation and signed application distribution are production gates. Signature alone does not prove which biometric was used. |
| Tampered local config | DPAPI current-user protection and owner ACL. Corrupt configuration fails closed; same-user malware/admin remains outside this boundary. |
| Privilege escalation | No privileged service/CP in Phase 1. Later IPC must reject remote callers, impersonate and authorize OS tokens, distinguish setup and LogonUI APIs. |
| Private data leaks | No secret logging, public-key-only backend, short-lived pairing artifacts, no camera permission in Phase 1. |

Never transmit biometric data, phone screen credentials, Windows PIN/password, or
Android private keys. Android backup is disabled for pairing configuration. Key loss
requires explicit pairing again. Reinstalling must not silently trust backend keys.

Future sign-in: bind approval to Windows account, session, usage scenario and selected
tile; do not reuse desktop-demo signatures. Validate locally inside the authentication
boundary, rather than accepting a service Boolean. Keep all Microsoft providers.

Production requires independent key-attestation chain/revocation/application-identity
verification; trusted roots must account for Android root rotation. A compromised
trusted endpoint, administrator/kernel or dishonest enrolled application is not
defeated by this desktop prototype. Audit files are diagnostic, not tamper-proof.
