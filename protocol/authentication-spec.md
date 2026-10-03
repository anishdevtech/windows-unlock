# WINDOWS-UNLOCK protocol v1

All authentication messages are compact JWS, alg=ES256, typ=phoneunlock+jws. Public keys
are P-256 JWK (kty, crv, x, y); no private d parameter. JWS signatures use 64-byte R||S
(RFC7518). Android's DER Signature output is converted with Nimbus's standard ECDSA
transcoder. Windows signs SHA256(JWS signing input) with NCrypt, verifies with BCrypt.
Reject other algorithms, key URLs, critical header extensions, duplicate JSON keys,
oversized input (64 KiB), invalid encoding and nesting deeper than 16.

Common signed fields: v=1, type, purpose=desktop-approval. IDs are UUIDs. Epoch timestamps
are integer seconds UTC. 30-second skew is allowed, but never extends Windows's local
60-second steady-clock deadline. No canonical JSON requirement: verify exact received
JWS bytes; digest references are lowercase SHA256 hexadecimal over the entire JWS.

## Pairing

Windows signs pair-invitation: sessionId, windowsDeviceId, windowsName, nonce (32 bytes
base64url), issuedAt, expiresAt (300s). HTTPS POST /v1/pairing-sessions supplies invitationJws
and SHA256(pairingToken). Locally export invitation JSON with relayUrl, tlsPin (sha256/
base64 SPKI), caPem, windowsJwk, invitationJws, pairingToken. Transfer it through a trusted
file channel; it contains a short-lived enrollment capability and must be deleted.

Android explicitly accepts, generates an auth-per-use approval key and unauthenticated
identity key, and signs pair-proposal using approval key through BiometricPrompt:
sessionId, windowsDeviceId, androidDeviceId, phoneName, approvalJwk, identityJwk,
invitationHash, tokenHash (phone generates a random 32-byte transport token itself).
POST /v1/pairing-sessions/{id}/proposal uses pairingToken bearer authentication.

Both display first 16 hex digits (uppercase) of SHA256(invitationJws + '.' + proposalJws).
Windows verifies proposal, user compares screens, explicitly confirms, then signs
pair-receipt: sessionId, pairingId, windowsDeviceId, androidDeviceId, proposalHash.
POST /v1/pairing-sessions/{id}/confirmation. Android polls GET session with pairingToken,
verifies pinned Windows signature and proposalHash, then activates its local pairing.
Windows stores confirmed approval/identity JWKs locally. Relay cannot substitute trust.

## Approval

Windows signs auth-request: requestId, windowsDeviceId, androidDeviceId, pairingId,
accountBindingId (opaque local profile UUID), nonce, issuedAt, expiresAt (60s).
POST /v1/authentication-requests sends requestJws. Windows keeps this exact token and
monotonic deadline in process memory. Only one outstanding request per pairing.

Android polls GET /v1/authentication-requests/pending with its scoped bearer token;
verifies the request with its pinned Windows key, pairing and expiry before displaying.
Approve invokes a fresh per-use Signature CryptoObject. auth-response fields:
requestId, pairingId, windowsDeviceId, androidDeviceId, challengeHash, decision=approve
or deny. Approve uses approval key; Deny uses identity key without requiring biometric.
POST /v1/authentication-requests/{id}/responses supplies responseJws. Relay validates
before terminal transition. Windows polls GET request, independently verifies signature,
every binding and its local pending/deadline, then consumes once. Server cannot authorize.

POST /v1/authentication-requests/{id}/cancel uses a signed auth-cancel message. Windows
clears local pending even if relay cancellation fails. Lost response or restarted
Windows process never automatically approves. POST /v1/authentication-events records
a signed auth-event (requestId, pairingId, result, timestamp, snapshotPath=null).
DELETE /v1/device-pairings/{id} uses Windows-scoped token; local revocation happens even
if the relay is unreachable. Pairing/transport tokens are not login proofs.

DB states distinguish pending/response_received/cancelled; client verification outcomes
are recorded separately. Duplicate terminal submissions return 409; expired work 410;
unauthorized callers 401/403. Request bodies/messages <=64 KiB and rate-limited.

Future windows-logon purpose and account/session/usage binding are a separate protocol
revision. Desktop approvals must never be accepted as Windows logon credentials.

## Background notification delivery (v0.2)

Android signs push-registration with its identity key: androidDeviceId, pairingId,
token (FCM installation address), nonce, issuedAt, expiresAt (300s). POST
/v1/android/push-token requires the Android bearer token and active pairing. New
registrations supersede old addresses. FCM sends only kind/requestId/expiresAt as a
high-priority hint with TTL <= remaining challenge lifetime. The app renders a private
heads-up notification then fetches/verifies the Windows-signed request on opening.
Neither the notification nor an action button supplies a signature or approval.

## Phone remote commands (v0.2, distinct signed message types)

Windows signs remote-offer: offerId, windowsDeviceId, androidDeviceId, pairingId,
nonce, issuedAt, expiresAt (60s), actions (local permission allowlist). Android verifies
that pinned signature, bindings and expiry; after explicit confirmation and a fresh
approval-key BiometricPrompt signs remote-command: commandId, offerId, windowsDeviceId,
androidDeviceId, pairingId, offerHash, action, viewerJwk (null except camera-start).
The relay consumes one command per offer transactionally. Windows RemoteLease
independently verifies the signed command, exact message shape and bindings, action
allowlist and its monotonic/wall deadline, then atomically consumes its local offer
before an OS action. After process restart no earlier offer is locally pending.
Backend status alone cannot cause an action. No shell or arbitrary command string is
accepted. A signed remote-result binds commandId, commandHash, result, timestamp;
accepted means the companion accepted the request, not proof the OS completed a
shutdown/sleep/restart. The OS may refuse the requested operation.

## Live camera envelope (v0.2)

camera-start includes a public-only 2048-bit RSA JWK (kty,n,e) from a temporary
Android Keystore key. It is covered by the phone's approval-key signature. Windows
requires explicit local camera permission, visible companion window and unlocked
interactive session. Camera watchdog checks local permission/visibility/lock state
and shuts down the media source independently of relay polling/network stalls.

Windows generates random 32-byte AES key. RSA-OAEP with SHA256 and MGF1-SHA256 wraps
the key. Frames use AES-256-GCM, random 12-byte IV, 16-byte tag appended to ciphertext,
AAD UTF8(commandId + ':' + decimal sequence). Sequence starts at 1, increases and
never exceeds 120 per 60s session. Envelope fields: sequence, iv, ciphertext, wrappedKey;
all binary values canonical base64url. Max JPEG plaintext 45000 bytes, output 320x240.
Android verifies GCM before image parsing and refuses duplicate sequence numbers.
Raw video, AES keys, private keys and unencrypted frames are never relayed. No audio
or video file is recorded. One latest encrypted frame is stored in PostgreSQL until
expiry/pruning; backups have their own retention. Viewer keys are removed on normal
closure and orphaned viewer aliases cleared on activity restart.
