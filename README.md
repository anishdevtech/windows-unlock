# WINDOWS-UNLOCK for Windows 11

The prototype includes a native Windows desktop/tray companion, an Android 11+
application, and a deployable TypeScript/PostgreSQL HTTPS relay. Version 0.3 also
implements a separate native LSA authentication package, Credential Provider and
LocalSystem service for phone-approved **existing console session unlock**.
**These native components are uninstalled and Windows/Winlogon acceptance is not
yet validated. This laptop still requires normal Windows PIN/password.**

Start with [setup](docs/setup.md), [protocol](protocol/authentication-spec.md),
[architecture](docs/architecture.md), and [recovery](docs/recovery.md).

Version 0.4 adds system-rendered background notifications, clearer native sign-in
status, a visible camera-sharing indicator that works from the tray, signed camera
key envelopes, connection reuse and sanitized server diagnostics. Follow the
[runtime update instructions](docs/runtime-update-0.4.md) to update both clients
and the database without removing your pairing.

Builds and test results, including remaining physical-phone checks, are recorded in
[verification](docs/verification.md). This checkout has a provisioned local development
runtime; run `scripts/Start-Local.ps1` to start the relay/database and desktop app.

Windows Hello PIN and password remain independent recovery methods. No Windows
password, Windows PIN, biometric template, or private Android key is transmitted.
No Credential Provider or LSA package has been installed on this laptop.

The older native preview includes a compiled V2 Credential Provider, LocalSystem
approval-preview service, restricted IPC, protected enrollment staging, and a
disposable-VM-only installer. The DLL always returns **no Windows credential**,
including after valid phone approval. Run `scripts/Build-NativePreview.ps1` to build
without installing anything. See [native development](docs/native-development.md)
and [native verification](docs/native-verification.md) for that preview's tested behavior.

The actual unlock targets are `WindowsUnlockAuth.dll`, `CredentialProvider.dll`,
`PhoneUnlockService.exe` and `PhoneUnlockStage.exe`. Run
`scripts/Build-WindowsUnlock.ps1` to build them without installing. Follow
[LSA signing and setup](docs/lsa-signing-and-setup.md) for the EV certificate,
organization/Partner Center registration, Microsoft submission, signed VM installer
and independent recovery tests. See [implementation and validation](docs/lsa-verification.md).
Signing alone does not establish personal Microsoft-account compatibility.
First sign-in after a reboot remains PIN/password; cold-boot phone login is not implemented.

The desktop companion can optionally send a test approval prompt when the current
Windows session locks, including while it runs in the tray. Enable its explicit
lock-prompt setting after hosted pairing. Phone approval still does not unlock Windows.
See [Windows sign-in status and remaining requirements](docs/windows-sign-in-status.md).

Version 0.2 adds Firebase background popup handling (Firebase setup required),
opt-in signed phone controls for lock/sleep/shutdown/restart, and an encrypted live
webcam preview (Android 15+, 320x240 up to 2 fps, 60-second sessions). Start with
[hosting and remote controls](docs/hosting.md). Vercel and a TLS server/VM recipe are
provided. This development installation has a hosted relay and Firebase configuration;
new installations must supply their own protected server credentials and Android
Firebase client configuration. Follow [one-time hosted Windows setup](docs/windows-one-time-setup.md).
