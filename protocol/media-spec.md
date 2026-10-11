# Direct media protocol v1 (client release 0.7)

Existing biometric-signed, one-use remote offers authorize `camera-start`,
`audio-speaker-start`, `audio-microphone-start`, `camera-stop` and `media-stop`.
Media starts require a canonical public RSA-2048 OAEP-SHA256/MGF1-SHA256 viewer key
in `viewerJwk`; other actions require null. A local enabled permission, unlocked
Windows session and visible sharing window are independent prerequisites.

Windows generates a fresh 256-bit master key, RSA-wraps it for this exact viewer,
and publishes `/v1/media/:commandId` using its authenticated relay transport.
`descriptorJws` is ES256-signed by the paired Windows root. Its exact payload is
`v,purpose,type,mediaId,nonce,commandHash,windowsDeviceId,androidDeviceId,pairingId,
action,keyHash,transport,issuedAt,expiresAt`. Type is `media-descriptor`, purpose is
`desktop-approval`; hashes are SHA-256 hex of the exact command JWS and canonical
base64url wrapped key. The nonce is 32 bytes. Camera descriptors expire within
60 seconds, audio within 600, bounded by the command's relay viewer deadline.

Transport fields are exactly `protocol,addresses,port,sampleRate,channels,packetMs,
maxFps`. Protocol is `udp-aesgcm-v1`, addresses are at most eight RFC1918 IPv4
literals, and the port is an OS-assigned ephemeral UDP port. Frame interval is
20 ms for audio; maximum video rate is 15 fps. Speaker input is stereo 48 kHz
signed little-endian PCM16, 3840 bytes/packet. Microphone output is mono 16 kHz
PCM16, 640 bytes/packet. Camera uses JPEG at no more than 640×480.

The relay validates signatures, exact binding, private endpoints, format and
expiry; Android verifies the descriptor independently before unwrapping. The
descriptor is immutable/idempotent and delivered only after Windows records
command completion. Relay authentication alone never authorizes device activation.

Directional keys are SHA-256 of UTF-8 `windows-unlock-media-v1:<direction>:<master>`
where direction is `up` or `down` and master is canonical base64url. Each direction
has an independent positive, increasing 64-bit sequence counter. Packet JSON is
exactly `sequence,iv,ciphertext`; AES-256-GCM uses a fresh random 12-byte IV,
16-byte tag and AAD `<commandId>:<direction>:<sequence>`. Binary fields are base64url.
Plaintext starts with one byte: 0 hello, 1 JPEG, 2 PCM audio, 3 stop, 4 heartbeat/ack.
Key material is not sent in UDP packets and is cleared on session teardown.

UDP header is 16 bytes: ASCII WUM1, 8-byte big-endian sequence, 2-byte big-endian
fragment index, 2-byte big-endian count. Fragments contain at most 1100 bytes and
there are at most 60; reconstructed JSON is at most 65536 bytes. Assemblies expire
after 200 ms; native keeps one and Android at most four. Invalid ciphertext cannot
advance the accepted counter or claim the peer. Windows binds the peer endpoint
only after an authenticated hello; Android accepts only descriptor-listed peers
and an authenticated downlink acknowledgement. Late/replayed packets are discarded.

Android heartbeats every 500 ms. Three seconds without authenticated traffic ends
a connected session. Windows stops audio after 15 seconds without a peer and has
independent monotonic session deadlines and continuously checked local permissions.
An authenticated phone POST to `/v1/media/:id/stop` is idempotent and available
through existing control polling as `mediaStopped`, including relay-only video.

Media bytes bypass the database on LAN. Camera HTTPS fallback preserves signed,
encrypted camera envelopes and the one-latest-frame relay table; 0.7 raises its
maximum sequence to 600 and supports `?after=<lastSequence>` to skip duplicate data.
Neither transport stores audio/video recordings. Captured device access still ends
when Windows locks, a permission is revoked, the indicator is hidden/closed, the
session expires, or the companion exits.
