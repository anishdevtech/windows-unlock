# Incremental implementation and release gates

1. **Phase 1:** architecture/threat/protocol docs; C++ desktop/core; Kotlin Compose app;
   manual bilateral pairing; per-use Keystore signatures; HTTPS/PostgreSQL relay;
   diagnostics, automated adversarial tests, real-device walkthrough. No OS login.
2. **Phase 2:** QR invitation scanning, lifecycle/key rotation/revocation UX. Keep all
   transcript comparison and explicit enrollment checks from manual pairing.
3. **Phase 3:** FCM notification reference, fetch and verify signed request, notifications
   permission, token rotation, TTL bounded by challenge expiry, delayed/missing delivery.
   Firebase credentials belong to the server only. Add WSS reconnect delivery.
4. **Phase 4:** direct paired TLS LAN path, offline operation, discovery that is never
   a trust source, short LAN attempt then relay with the same challenge, one consumption.
5. **Phase 5:** opt-in one-shot disclosed snapshot; session-aware camera access/privacy
   investigation; local AES-GCM with protected key; retention 1/7/30 days or never;
   timestamp/device/result/snapshotPath/requestId records. Camera failure cannot deny
   authentication. Cloud upload separately enabled; no continuous/covert capture.
6. **Phase 6:** restricted service IPC and V2 Credential Provider. Disposable VM-first;
   local console scenarios only. Real Windows authentication disabled until a compatible
   password-free account-specific path is verified under LSA protection and recovery.
7. **Phase 7:** independent Android attestation, signer identities, signed builds,
   transactional WiX setup/uninstall, least privilege, secrets/retention/backup policy,
   fuzzing, dependency review, supported Windows update matrix and recovery drills.

Additional prerequisites: Android phone with secure screen lock and strong biometric
or system credential; API 30+; signed release APK for distribution; relay hostname and
trusted TLS; Firebase project/Google Play support for FCM; PostgreSQL; service deployment
secrets and monitoring. None of these implies storing a Windows password.

Phase 1 may use local relay over Wi-Fi. Internet testing uses the same backend deployed
on a hosted server and a new invitation containing its HTTPS address/trust information.
No cloud infrastructure is created or billed automatically.
