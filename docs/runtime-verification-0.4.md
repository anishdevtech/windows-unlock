# Runtime verification, 0.4

Verified on this checkout on 2026-10-08. These results cover the runtime update;
they do not establish acceptance of the native authentication package by Winlogon.

| Check | Result |
| --- | --- |
| TypeScript build and backend security suite | Passed, 32 tests using the injected test store |
| Full Windows C++ Release build | Passed |
| Windows CTest suite | Passed, 7 tests, including native IPC, provider fallback, LSA authority/package boundaries and core cryptography |
| Android APK build and lint | Passed |
| Android unit suite | Passed, 7 tests, including CNG-to-JCA camera encryption interoperability and signed envelope binding |
| Scoped folder ACL creation and second-run idempotency | Passed on an empty temporary test directory; protected DACL, one current-user rule, owner retained |
| Re-running hosted Windows setup | Passed; existing DPAPI pairing preserved, desktop/startup shortcuts refreshed |
| Public Vercel health | HTTP 200 |
| Public diagnostics without credentials | HTTP 401 |
| Hosted database migration 003 | Applied without resetting paired devices |
| Current FCM notification payload | Accepted by Firebase's dry-run validation using the registered phone token |
| Live approval path | Signed Windows request sent, Firebase acceptance reported, phone signature verified by the running companion; corresponding signed application events arrived in PostgreSQL |
| Live camera transport | A phone-signed camera command had a verified accepted laptop receipt; latest encrypted frame sequence reached 12, with the Windows-signed key envelope stored by the relay |

The native camera sharing indicator was rendered and inspected. No camera image,
credential, transport token, private key or biometric data was exported for this
verification. Operator credentials remained in protected local environment input.
The APK uses hardware-key enforcement (`ALLOW_SOFTWARE_KEYS=false`); install it as
an update using the existing debug signing key to preserve the app's pairing.

App Control initially prevented `core_tests.exe` from running, which also blocked
the first Android interoperability run. Later normal builds/checks passed all seven
core/native and seven Android tests without changing App Control policy. The
separate `http_tests.exe` negative certificate-pin/connection-reuse executable was
still blocked by App Control. That specific test remains unverified on this host;
no rename, relocation, policy exclusion or security downgrade was used to run it.
The running companion did connect to the hosted HTTPS relay successfully.

Pending: confirm background banner display under the actual OPPO notification and
battery settings, and visually confirm the new APK's webcam view on the phone.
Successful FCM acceptance and encrypted-frame upload do not prove those UI results.
Cold-boot phone login is not implemented. The native provider, broker and LSA
package remain uninstalled, with a Microsoft-signed authentication DLL and protected
VM/account-compatibility validation still required. Windows PIN/password remain
the actual sign-in path on this laptop.

Follow [runtime update instructions](runtime-update-0.4.md) and
[native signing/setup](lsa-signing-and-setup.md).
