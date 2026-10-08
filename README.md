# WINDOWS-UNLOCK for Windows 11

Version 0.5 adds **phone-controlled encrypted Windows password sign-in** through
an additional native Credential Provider and LocalSystem service. Windows' built-in
Negotiate package checks the password. This architecture requires no custom LSA
package, Microsoft Hardware Developer Program enrollment, or EV certificate.
The password stays encrypted on the laptop; Android's hardware-backed, per-use
BiometricPrompt key releases its decryption key only to a fresh laptop request.

**The code and setup tools are built and partially tested; this laptop's Application
Control policy previously blocked unsigned native checks; the latest checks pass
after the user-selected setting change. Actual Winlogon sign-in on the personal
Microsoft account remains a physical-device acceptance check. The new provider is
now enrolled and installed on this laptop; its LocalSystem service is running.** Normal Windows PIN and Password remain
available. The user explicitly accepted local encrypted password storage for this
alternative; earlier password-free LSA instructions describe a separate legacy mode.

Use [one-time phone sign-in setup](docs/password-unlock-setup.md),
[vault protocol](protocol/password-vault-spec.md), and
[security/acceptance notes](docs/password-vault-security.md).

Build with `scripts/Build-PasswordUnlock.ps1`. Package the development APK and
allowlisted native files with `scripts/Package-PasswordUnlock.ps1 -UnsignedPrototype`.
Packaging does not install anything or override Windows policy.

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
password is sent to the phone/server; no PIN, biometric template, or private Android
key is transmitted. Password credentials are returned locally to Windows only after
phone-controlled decryption and are wiped from application buffers.
The additional 0.5 password Credential Provider is installed on this laptop.
No custom LSA authentication package was installed.

The older native preview includes a compiled V2 Credential Provider, LocalSystem
approval-preview service, restricted IPC, protected enrollment staging, and a
disposable-VM-only installer. The DLL always returns **no Windows credential**,
including after valid phone approval. Run `scripts/Build-NativePreview.ps1` to build
without installing anything. See [native development](docs/native-development.md)
and [native verification](docs/native-verification.md) for that preview's tested behavior.

The **legacy password-free experimental** targets are `WindowsUnlockAuth.dll`, `CredentialProvider.dll`,
`PhoneUnlockService.exe` and `PhoneUnlockStage.exe`. Run
`scripts/Build-WindowsUnlock.ps1` to build them without installing. Follow
[LSA signing and setup](docs/lsa-signing-and-setup.md) for the EV certificate,
organization/Partner Center registration, Microsoft submission, signed VM installer
and independent recovery tests. See [implementation and validation](docs/lsa-verification.md).
Signing alone does not establish personal Microsoft-account compatibility.
That legacy mode does not implement cold-boot phone login. The 0.5 password service
runs before first sign-in; its cold-boot code path requires real-device acceptance.

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
