# Phone-controlled password vault protocol, 0.5

This optional mode supersedes the original no-stored-password rule **only** with the
user's explicit consent to local encrypted password storage. It uses built-in Windows
password authentication. The preview/legacy LSA protocols remain separate purposes.
All JWS rules from authentication-spec.md apply: strict JSON, canonical base64url,
ES256/SHA-256/P-256, exact fields, pinned endpoint trust and compact-JWS byte digests.
All messages below have `v:1,purpose:password-unlock,type:<specified>`. No Windows
password or its ciphertext is sent to the relay/phone.

## Delegation and enrollment

The paired user CNG signing key signs `vault-delegation` with fields:
`vaultId,windowsDeviceId,androidDeviceId,pairingId,accountBindingId,windowsAccountSid,
loginName,machineJwk`. The machine key is a separate nonexportable CNG P-256 key with
a SYSTEM/Administrators DACL. This permits pre-logon operation without a loaded user
profile. Android verifies the root against the already paired Windows public key.

Windows signs `vault-enroll` with its paired root key:
`requestId,nonce,issuedAt,expiresAt,delegationJws`. Nonce is 32 random bytes; expiry is
at most 300 seconds. Android explicitly reviews the account, generates/reuses a
vault-specific **RSA-2048 OAEP/SHA-256 key (MGF1 SHA-256, empty label)** in Keystore,
requires hardware security level TEE/StrongBox and per-operation authentication,
and invokes BiometricPrompt with the existing pairing approval signing key.

Approved `vault-enrolled` responses contain exactly
`requestId,challengeHash,decision:approve,phoneJwk`, signed by that biometric approval
key. A denied response contains only `requestId,challengeHash,decision:deny`, signed
by the identity key. Android persists the exact signed delegation and key alias
before delivery, preserving the same key on retries. At most four enrollments are
kept; removal deletes private vault keys from Keystore.

Windows generates 32 random bytes as an AES-256 key, encrypts the UTF-16LE account
password with AES-GCM (12-byte random nonce, 16-byte tag), and uses the lowercase
SHA-256 hex digest of `delegationJws` as UTF-8 AAD. The AES key is RSA-wrapped to the
phone public key. Windows stores only ciphertext, wrapped key, public trust anchors,
delegation and transport settings under machine DPAPI **and** strict file ACLs.
Neither side persists the plaintext AES vault key. Setup checks the password/SID
through Windows, wipes plaintext buffers, and commits protected state atomically.

## Each login

Only the real local-console `LogonUI.exe` running as SYSTEM can access V4 IPC.
The service accepts the enrolled SID and CPUS_LOGON/CPUS_UNLOCK_WORKSTATION context.
An existing user session must be locked and match the enrolled SID. First sign-in
requires an empty active console with no user token and logon scenario.

Each request generates fresh ephemeral **RSA-2048** key material in volatile CNG
memory. `vault-unlock`, signed by the delegated machine P-256 key, contains exactly:
`requestId,nonce,issuedAt,expiresAt,delegationJws,sessionId,usageScenario,ephemeralJwk,
wrappedKey`. Expiry is at most 60 seconds, alongside a Windows steady-clock deadline.
The phone verifies the root-signed delegation, machine request, pairing/account
bindings, strict RSA public keys, expiry, and **exact previously enrolled delegation**.
The relay cannot replace the ephemeral key or invent machine requests.

On Approve, BiometricPrompt receives a Keystore-backed RSA decrypt `CryptoObject`.
Only after successful system authentication does it unwrap the 32-byte AES key.
It immediately RSA-wraps that key to the signed fresh laptop public key and wipes
the plaintext AES byte buffer in `finally`. **The AES key briefly exists in phone
application memory; the private RSA key never leaves Keystore.** The encrypted
release is returned as `vault-response` with
`requestId,challengeHash,decision:approve,wrappedKey`, signed by the phone identity
key. This signature authenticates transport; the actual approval gate is the
biometric-authorized Keystore decryption. Denial is the six-field signed response.

Windows independently verifies the pinned phone identity signature, exact request
digest, identifier, terminal state, wall-clock and monotonic deadlines, caller/session,
and RSA cipher size. Its volatile private RSA key unwraps the release. AES-GCM must
authenticate the local password envelope before Windows credentials can be packed.
A forged release, wrong AES key or relay `approved` state fails closed.

The service uses OS credential protection and serialization:
Microsoft accounts use `CredPackAuthenticationBufferW` with protected identity-provider
credentials; local accounts use protected `KERB_INTERACTIVE_UNLOCK_LOGON`, correct
logon/unlock message type and package-relative pointers. LogonUI submits to built-in
Negotiate. Windows controls account policy and whether the password is accepted.

V4 uses a 412-byte request and 8760-byte response, plus a four-byte receipt
acknowledgement after a valid response. Each read/write has a bounded 250 ms wait;
pipe-busy connection retry is bounded to 100 ms. The server keeps its first pipe
instance alive and waits for the receipt before disconnecting, preventing unread
responses from being discarded without an unbounded flush. V3 and V4 pipe names
are separate; both DLL and service must be updated together.

Describe advertises the one-bit automatic-request policy only for the enrolled ready
account. The optional DPAPI config boolean `automaticRequestsEnabled` defaults false
and can be changed only by the enrolled elevated administrator. With it enabled,
SCM lock notifications/startup queue a challenge for the enrolled active console,
after independently verifying its locked/empty context and SYSTEM System32 LogonUI
PID. A provider Begin can adopt that pending operation only for the same trusted
LogonUI PID, session, SID and scenario, before its existing expiry. Adoption changes
only the local correlation GUID, never the signed backend challenge or deadline.
Only cryptographically verified approval permits a one-time provider default/autologon
callback. No permanent default-provider registry setting or filter is installed.

IPC Poll exposes status only. **Claim** hands packed credentials to the initiating
SYSTEM LogonUI caller once and immediately clears the service buffer. Switching
away from a manually pending request, explicit cancellation, session changes, expiry,
caller death and service restart revoke pending work. An automatic request continues
without selecting the tile. Field UnAdvise/Advise, unchanged user arrays and selection
transitions during re-enumeration preserve an already approved handoff rather than
discarding it. A watchdog clears unclaimed credentials independently of UI polling.
The DLL wipes IPC response buffers. Windows owns the final submitted buffer.

After a one-time Claim, Result can audit Windows' status callback once for that same
operation/caller. Non-Result requests must have zero status fields. The UI can display
the NTSTATUS/substatus locally; server telemetry contains only allowlisted
`windows_signin_failed` or `windows_result_success` codes, never packed credentials,
account names, arbitrary exceptions or the password. Callback success is not
independent proof of a completed user session. A missing Result is not a success.

## Relay and logs

Endpoints: POST `/v1/vault-requests`; GET `/v1/vault-requests/pending` (Android);
GET `/v1/vault-requests/:id` (Windows); POST `/:id/responses` (Android);
POST `/:id/cancel` (Windows). Cancellation is root/machine-signed `vault-cancel` with
`requestId,challengeHash`. Tokens are scoped transport capabilities, never signatures.
PostgreSQL row locking serializes pending creation/terminal transitions; nonces are
unique. Active pairing is rechecked on response and result delivery. The relay stores
public keys, signed requests/responses, encrypted wrapped keys and metadata; **not the
Windows password vault ciphertext**, plaintext password, AES key or any private key.

`POST /v1/vault-diagnostics` accepts the root delegation and a delegated machine-signed
`diagnostic-batch`: `batchId,windowsDeviceId,issuedAt,expiresAt,entries`. Entries use
the existing exact allowlisted schema and seven-day retention. No free-text secrets.
Server authentication-event results describe request creation/phone decisions, not
actual Windows logon success. HTTPS/FCM with bounded polling is the initial transport;
there is no direct-LAN/offline vault approval yet. Windows PIN remains independent.
