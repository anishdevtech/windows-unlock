# LSA signing and Windows setup

The v0.3 code now includes an actual authentication package and credential
serialization, not just the earlier approval preview. It is **not installed or
validated in Windows' real authentication path**. This checkout's physical laptop
still uses its normal PIN/password. Read [verification](lsa-verification.md) before
making a submission or installing anything.

The implementation targets unlocking an **already signed-in, locked local console
session**. After a restart, first sign-in uses Windows PIN/password. It resolves the
existing user SID through the local SAM-backed account and refuses unsupported
accounts. Your personal Microsoft-account session may have such a backing account,
but Microsoft-account/Winlogon/profile/DPAPI behavior has not been demonstrated.
Obtaining a signature does not resolve that compatibility question.

## What you need to obtain

These are developer signing prerequisites, not Firebase or server environment variables:

1. A verified organization account in Microsoft's **Windows Hardware Developer
   Program / Partner Center**, with a legal contact authorized to accept agreements.
2. An organization's Microsoft Entra work account with the global administrator
   role for enrollment. An ordinary Outlook account alone is not this account.
3. An **EV code-signing certificate** issued for the organization. Ask an issuer
   about eligibility and hardware-token/cloud-signing support before purchasing.
   Its private key stays with that secure signing provider; do not put it in chat,
   Git, Vercel, Firebase or Android.
4. Partner Center's **Microsoft-signed LSA DLL returned from a file-signing submission**.
   This is the artifact the installer needs; a certificate thumbprint by itself does
   not make a DLL eligible to run under protected LSA.

Register through [Microsoft's Hardware Developer Program instructions](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/hardware-program-register):
use the organization's work account, supply accurate company/legal-contact details,
complete account verification, upload the EV certificate through Manage certificates,
and respond to Microsoft's requested information. The legal agreements and certificate
purchase must be completed by the authorized account owner. These scripts do not create
an organization or accept agreements for you.

Protected LSA requires the appropriate Microsoft signature. Keep LSA protection,
Secure Boot and Application Control enabled. See [Microsoft's protected-LSA guidance](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection).

## Build, freeze and submit

Install Visual Studio Desktop Development with C++, CMake and Windows SDK signing
tools. From the repository root, use 64-bit PowerShell:

```powershell
.\scripts\Build-WindowsUnlock.ps1 -RunTests
```

On this laptop Application Control blocked `core_tests.exe`; other tests ran. If a
required executable is blocked, sign it through your trusted publisher workflow and
run the checks in the authorized test environment. Do not rename binaries, add roots,
exclude folders or lower policy to evade the block. No install happens during a build.
`Sign-UnlockComponents.ps1 -CertificateThumbprint '<public thumbprint>' -IncludeTestHarnesses`
can publisher-sign the test executables and preview DLL before you rerun CTest. The
package boundary test loads the actual auth DLL, so use the Microsoft-returned DLL
in a matched test build if protected policy requires its signature. Keep the frozen
unsigned submission copy separate. OS policy still makes the final load decision.

When your EV signing certificate/provider is available in `Cert:\CurrentUser\My`,
obtain its **public thumbprint** from Windows' certificate UI. Confirm with the issuer
that it is the EV certificate registered for your organization, then run:

```powershell
.\scripts\Prepare-LsaSubmission.ps1 `
  -EvCertificateThumbprint '<40-character public EV certificate thumbprint>' `
  -EvCertificateConfirmed
```

The script freezes `WindowsUnlockAuth.dll` in a unique `build\lsa-submission-*`
directory, produces a flat cabinet containing only that DLL, signs/timestamps the
CAB through your certificate provider and writes a separate submission hash record.
It checks certificate purpose, RSA support, validity and chain/revocation. EV eligibility
is confirmed by your issuer and Partner Center, not inferred from a local flag.
If your cloud provider uses its own signing tool instead of Windows SignTool, follow
its supported process to sign this exact CAB with the registered EV certificate.

Open [Partner Center's LSA file-signing workflow](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/file-signing-manage):
**Hardware dashboard → File Signing Services → Submit New LSA**. Upload the signed
CAB, review any legal agreement, submit and retain its submission ID. Download and
extract the Microsoft-signed result when processed. Microsoft's [submission requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/file-signing-reqs)
require a single signed CAB without folders and with only binaries being signed.

Keep the downloaded `WindowsUnlockAuth.dll` separate from `build\windows\Release`.
Record its SHA-256 alongside the submission ID. Keep the frozen source/build record.
Review that it is the result for this submission. **Do not modify, rebuild over, or
publisher re-sign the returned DLL.** Every change to its code requires a new submission.

Publisher-sign the matching provider/service/stage binaries separately:

```powershell
.\scripts\Sign-UnlockComponents.ps1 `
  -CertificateThumbprint '<40-character public publisher certificate thumbprint>'
```

This excludes the authentication DLL and leaves its Microsoft signature intact.
The signing scripts export no private key. They have been parsed, but actual signing
and Microsoft submission have not been exercised without your certificate/account.

The desktop companion used for VM pairing is a separate executable. Build it from
the same source checkout and publisher-sign it with `scripts/Sign-WindowsRelease.ps1`
before distribution. Exit a running companion before rebuilding/signing its file;
this implementation task kept your currently running companion intact. Do all builds
before freezing the submission, and keep the matching source revision for the result.

## One-time setup in a disposable VM

The installer deliberately refuses physical machines in this release. Use a
disposable Windows 11 VM with protected LSA enabled and a pre-install checkpoint.
Test both normal PIN and password sign-in before proceeding. Keep a verified recovery
account/password and checkpoint access. PIN is not generally available in Safe Mode.
Do not copy your physical laptop's DPAPI file/key into the VM; **pair the VM itself**
with the phone using the desktop setup and Android v0.3. Keep the paired VM user's
identity and CNG key. Use the same user when elevating the stage tool.

Copy the repository, matching publisher-signed native components and Microsoft-returned
DLL to the VM. In elevated 64-bit PowerShell inside that VM:

```powershell
.\windows\installer\Install-UnlockInVm.ps1 -Phase Register `
  -MicrosoftSignedLsaPath 'C:\SigningResult\WindowsUnlockAuth.dll' `
  -DisposableVm -RecoveryVerified
```

Register copies verified binaries to protected paths and appends only
`WindowsUnlockAuth` to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`
(REG_MULTI_SZ). It preserves the existing list. It does not change Authentication
Packages, provider filters, default provider, exclusions, PIN or LSA protection.
It does not start a service, expose a tile or restart Windows at this stage.
This uses [Microsoft's SSP/AP registration model](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls).

Manually restart **the VM**, sign in with PIN/password, and check Windows Code Integrity
and LSA startup events. Verify that protected LSASS remains enabled and the correct
package loads. Authenticode validation alone cannot prove protected-LSA eligibility.

Stage the **VM's** confirmed desktop pairing using the signed installed tool:

```powershell
& "$env:ProgramFiles\WINDOWS-UNLOCK-SignIn\PhoneUnlockStage.exe" `
  --stage-unlock-from-desktop `
  "$env:LOCALAPPDATA\WINDOWS-UNLOCK\hosted\windows-config.dpapi"

.\windows\installer\Install-UnlockInVm.ps1 -Phase Activate `
  -DisposableVm -RecoveryVerified
```

Staging creates `%ProgramData%\WINDOWS-UNLOCK-SignIn\enrollment.dpapi` with machine
DPAPI and a separate public-only `trust.json`. Both require SYSTEM/Administrators-only
ownership/ACLs. There is no Windows password/PIN in them. Staging is create-only;
partial or old staging is refused. If staging fails after creating one file, remove
only the two known files from that protected directory, review the cause, and retry
under the correct paired account. Do not replace native trust from backend data.

Activate checks the installed hashes/signatures, enrollment files and a read-only
package lookup before registering the project's additional provider and LocalSystem
service. The package lookup confirms presence, not complete unlock compatibility.
The provider is never made the system default. Select **Unlock with Phone** on the
VM's lock screen to initiate the request. Android's private notification opens the
request screen; **Approve** invokes the system biometric/device-credential prompt.
Only a verified response can be serialized to LSA. Windows PIN/password stay available.

## Acceptance before any physical deployment

Record the exact signed DLL hashes, OS build/account type and each observed result:

- First sign in normally, lock the existing session, select the phone tile, authenticate
  on Android and prove Windows actually unlocks the **same SID/session**. A phone
  success screen, Firebase acceptance or broker proof is insufficient.
- Repeat with your personal Microsoft-account backing SID. Verify profile identity,
  existing applications, user DPAPI secrets, Windows Hello PIN and subsequent normal
  password sign-in. Do not advertise MSA support unless these succeed.
- Deny, expired/duplicate/malformed/cross-purpose proofs, tile switch, session replacement,
  enrollment revocation and rapid unlock/relock must all reject old approvals.
- Verify provider teardown after serialization, CredentialsChanged/autologon lifecycle
  and the actual Winlogon logon type. This path has not yet been tested in LogonUI.
- Stop/crash the broker, use a broken config, unavailable relay and unavailable phone.
  Each must leave normal Windows sign-in options usable. No LAN fallback exists yet.
- Cold boot must still accept PIN/password. Do not rely on phone approval for first
  login, domain/Entra accounts, RDP, UAC/CredUI, network or service logons.
- Exercise update, uninstall, failed-install rollback, loaded-DLL cleanup and VM
  checkpoint recovery without disabling security controls. Audit LSA memory/lifetime
  handling and API reentrancy under real protected LSASS.

This is a validation checklist, not a record of completed VM tests. There is no
physical-machine installer switch until the above path is proven and reviewed.

## Revocation and removal

Native enrollment is independent of the desktop profile. Stop the native broker and
remove its local trust before unpairing/replacing the desktop identity. Changing a
backend row alone cannot silently alter or revoke the LSA trust file. Native trust
removal/replacement invalidates pending proofs at consumption.

```powershell
.\windows\installer\Uninstall-Unlock.ps1 -RemoveEnrollment
```

The uninstaller removes only this provider GUID, service and LSA list entry, then the
fixed owned files. It preserves other list entries and unexpected directory content.
LSASS/LogonUI may keep DLLs loaded until restart: the ownership marker remains, you
restart manually, sign in normally and rerun cleanup. There is no recursive deletion
or forced reboot. If experimental LSA code prevents the VM booting, restore its
pre-install checkpoint. See [recovery](recovery.md).
