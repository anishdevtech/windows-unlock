# Threat model

> Current 0.5 phone sign-in uses a locally encrypted password vault and built-in Windows authentication. See [one-time setup](password-unlock-setup.md) and [vault protocol](../protocol/password-vault-spec.md). Earlier no-password LSA/preview descriptions below refer to those separate modes.


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
| Privilege escalation | Phase 1 remains unprivileged. Native preview uses a SYSTEM-only, remote-rejecting pipe, validates actual LogonUI process/session and registered LocalSystem server PID, and keeps enrollment staging outside IPC. Preview always emits no Windows credential. VM validation remains required. |
| Private data leaks | No secret logging, public-key-only backend, short-lived pairing artifacts, no camera permission in Phase 1. |

Never transmit biometric data, phone screen credentials, Windows PIN/password, or
Android private keys. Android backup is disabled for pairing configuration. Key loss
requires explicit pairing again. Reinstalling must not silently trust backend keys.

Version 0.3 implements that sign-in boundary in a separate LSA package: approval is
bound to account SID, active locked console session, usage scenario, existing logon
LUID and the selected LogonUI process ID/creation time. LSA creates/consumes the nonce
and independently checks public trust and both signatures; a service Boolean cannot
authorize. Desktop-demo signatures have a different purpose and are rejected. The
SSP/AP rejects ordinary/restricted/impersonating callers and unsupported logon types.
Token information comes from the existing Windows-authenticated user context; no
invented administrator groups/privileges or broad default DACL. The installer appends
only the owned Security Packages entry and provider GUID, preserves built-in methods,
requires signed binaries and currently refuses physical machines. Actual protected-LSA
loading, Winlogon acceptance, MSA/DPAPI continuity and crash recovery still need VM proof.

Native-preview trust is frozen in machine-DPAPI enrollment with SYSTEM/Administrators
ACLs and ownership checks. Null/broad ACLs and reparse files/directories fail closed.
A nonprivileged process cannot replace enrollment or open the service endpoint; a
local administrator or injected SYSTEM process is outside this boundary. The client
uses identification-only SQOS so a fake pipe cannot acquire an impersonation token.
The pipe's first instance stays open between clients, preventing a name takeover.
No HTTP or camera code runs in the provider DLL.

The preview reuses `desktop-approval` messages and the paired user's CNG key. It is
not a Windows authentication authority, attestation verifier, production revocation
system or cold-boot sign-in solution. Remove the staged VM enrollment and stop the
preview service before unpairing/replacing the desktop identity. A compromised relay
can hide revocation; production revocation must be enforced locally at the eventual
authentication boundary. Approval status must never be treated as an LSA credential.

For the unlock build, local removal/replacement of protected `trust.json` revokes
pending approvals even if the relay is offline or conceals its pairing state. Stop
the broker before unpairing; remove both native trust and DPAPI enrollment, then pair
and stage again explicitly. The relay has no authority to update native trust. Android
hardware checks remain client-enforced; independent attestation/application validation
is not implemented. Do not describe this prototype as resistant to an already trusted,
dishonest enrolled phone. First login after reboot and domain/Entra/network logons are
outside the implemented path. There is no LAN fallback yet; use Windows PIN when the
relay is unavailable. Every Windows failure must produce no credential and leave other
providers available. Absolute recovery from arbitrary OS/firmware failures is not a
promise this project can make.

Production requires independent key-attestation chain/revocation/application-identity
verification; trusted roots must account for Android root rotation. A compromised
trusted endpoint, administrator/kernel or dishonest enrolled application is not
defeated by this desktop prototype. Audit files are diagnostic, not tamper-proof.
