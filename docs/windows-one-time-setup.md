# One-time hosted Windows setup

The server must first return `status: ok` at https://windows-unlock.vercel.app/health.
The hosted database migrations are already applied for this development installation.
This procedure configures the desktop companion; it does not install a Credential
Provider or turn phone approval into actual Windows lock-screen sign-in. Normal
Windows PIN/password remain available.

On this development laptop, Application Control rejected an interim unsigned build;
the final build subsequently launched normally without policy changes. Use a trusted
publisher signature for distributed releases, rather than relying on unsigned-build
reputation. See [current Windows sign-in and signing status](windows-sign-in-status.md).
The existing hosted pairing was preserved; do not reset it to address a launch block.

On the development laptop, with the Windows build and private operator `backend/.env`
already present, open PowerShell in the project folder and run:

```powershell
.\scripts\Setup-HostedWindows.ps1 -AutoStart -Launch
```

The script creates a separate hosted identity, registers its public key on the hosted
database, imports the scoped transport token into Windows DPAPI and removes its
temporary plaintext transfer file. It uses normal system TLS certificate validation.
The protected state is under `%LOCALAPPDATA%\WINDOWS-UNLOCK\hosted`; the existing
project `.runtime` pairing is preserved. Re-running a completed setup reuses the
hosted identity and refreshes shortcuts rather than registering another device.
The public relay URL, private operator DB credentials and Android app must belong to
the same intended installation. This script is an operator setup tool for this laptop,
not a public installer to distribute with server credentials.

`-AutoStart` adds a shortcut to the current user's Startup folder, so the companion
starts after Windows sign-in. Omit that flag for manual startup. A **WINDOWS-UNLOCK
Hosted** desktop shortcut is always created. Keep the project folder in place because
the shortcut points to its built executable. Neither shortcut starts a backend server
or loads the operator `.env` credentials. There is no administrator requirement or
change to Windows authentication registry settings.

Complete pairing once:

1. In the hosted Windows companion, click **Pair phone**. It creates
   `%LOCALAPPDATA%\WINDOWS-UNLOCK\hosted\phone-invitation.json`, valid for five minutes.
2. Install the rebuilt Android APK. If it has the previous local-relay pairing, use
   **Reset local pairing** before importing this new hosted invitation. Transfer the invitation
   privately to your own phone (for example via USB), then select **Import pairing invitation**.
3. Authenticate when Android requests it. Compare the confirmation code on both
   devices and confirm only if they match. After successful pairing, delete any copied
   invitation from the phone/transfer location. The Windows original is removed by the app.
4. On Android, select **Enable popup approvals** and allow notifications. The Firebase
   client config is included in the rebuilt APK. Do not force-stop the app.
5. On Windows, click **Unlock with Phone (test)**. Check the phone notification and
   approve with the system biometric/device-credential prompt. This proves approval;
   it does not sign into Windows. Repeat with the phone on mobile data.

Power controls and live camera are separate opt-ins on Windows. Leave them off until
you want to test them. Live camera requires a visible companion window and unlocked
Windows, and expires after 60 seconds. Do not enable camera just to complete pairing.

For a background phone prompt when you lock Windows, enable **Send a phone approval
prompt when Windows locks (test only)** in the rebuilt companion. Keep the companion
running in the tray and Android popup approvals enabled. This sends one time-limited
test per lock, with a 60-second cooldown. It does not unlock Windows; continue using
the built-in PIN. It does not run at the first sign-in after a restart. See
[Windows sign-in status](windows-sign-in-status.md) for the exact boundary and the
remaining Credential Provider/authentication requirements.

After setup, use the desktop shortcut or let the Startup shortcut launch the companion.
Do not run local backend scripts for hosted use. Exit from the tray to stop the
companion. To stop automatic startup, remove only the **WINDOWS-UNLOCK Hosted** shortcut
from your Startup folder (`shell:startup`); this does not change PIN/password access.
Use the app's **Unpair** action to revoke the phone before uninstalling it. Keep the
protected state until revocation completes, and do not reset/delete it as a way to fix
a network error.
