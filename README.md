# WINDOWS-UNLOCK for Windows 11

The prototype includes a native Windows desktop/tray companion, an Android 11+
application, and a deployable TypeScript/PostgreSQL HTTPS relay. It proves phone-authorized signatures;
**it does not unlock Windows or change any Windows sign-in configuration**.

Start with [setup](docs/setup.md), [protocol](protocol/authentication-spec.md),
[architecture](docs/architecture.md), and [recovery](docs/recovery.md).

Builds and test results, including remaining physical-phone checks, are recorded in
[verification](docs/verification.md). This checkout has a provisioned local development
runtime; run `scripts/Start-Local.ps1` to start the relay/database and desktop app.

Windows Hello PIN and password remain independent recovery methods. No Windows
password, Windows PIN, biometric template, or private Android key is transmitted.
No Credential Provider or LSA package is installed in this phase.

Version 0.2 adds Firebase background popup handling (Firebase setup required),
opt-in signed phone controls for lock/sleep/shutdown/restart, and an encrypted live
webcam preview (Android 15+, 320x240 up to 2 fps, 60-second sessions). Start with
[hosting and remote controls](docs/hosting.md). Vercel and a TLS server/VM recipe are
provided; no cloud account, Firebase project or deployment has been created.
