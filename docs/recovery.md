# Recovery

> Current 0.5 phone sign-in uses a locally encrypted password vault and built-in Windows authentication. See [one-time setup](password-unlock-setup.md) and [vault protocol](../protocol/password-vault-spec.md). Earlier no-password LSA/preview descriptions below refer to those separate modes.


Phase 1 is an ordinary desktop app. Close it, stop the relay, or remove project data;
Windows sign-in still works normally. There is no custom PIN database, authentication
registry modification, provider filter, keyboard simulation, or password storage.

In v0.2, a paired companion closes to the system tray. Right-click its tray icon and
choose Exit to stop remote commands. Disable the local power/camera checkboxes to
revoke those capabilities, or Unpair to remove phone trust. Hiding/minimizing the
window stops camera sharing; tray power controls remain available while opted in.
Phone power actions require explicit confirmation and fresh system authentication.
Automated development checks never execute shutdown/sleep/restart/lock on your laptop.

If phone authentication is unavailable, choose Windows Sign-in options -> PIN.
Maintain the normal account password as well: Safe Mode and some recovery scenarios
may not offer Windows Hello PIN. Never promise PIN availability outside supported
Windows conditions or immunity from unrelated OS/hardware failures.

Later deployment must preserve existing providers, test PIN/password before enabling,
register only project GUIDs, roll back installation failure, and support unregistering
only project components. Test on disposable Windows VMs first. Require recovery drills
for DLL/service failure, offline state, phone loss, reboot, update rollback and uninstall.
Never change LSA protection, Credential Guard, provider exclusions or default providers
to make experimental authentication work. Do not automatically lock/reboot the laptop.

The native development build performs no installation. Its installer explicitly refuses
physical machines. In a disposable VM, the preview tile can request phone approval but
cannot sign in. Use normal Windows sign-in options. See [native development](native-development.md)
for VM-only uninstall and recovery of the project's own registration. Retain a known
Windows password and a VM checkpoint; PIN is not guaranteed in Safe Mode/recovery.

The separate v0.3 actual-unlock installer also refuses physical machines and requires
a Microsoft-signed authentication DLL plus publisher-signed components. Its Register
phase adds only `WindowsUnlockAuth` to LSA's current Security Packages multi-string;
the existing list is preserved. Its Activate phase runs only after reboot/package
lookup and adds only the project's provider/LocalSystem service. No exclusions,
default-provider replacement, password/PIN storage or automatic reboot is used.

For the owned native installation, run elevated `windows/installer/Uninstall-Unlock.ps1`
with `-RemoveEnrollment` to revoke native trust and remove the project's tile, service
and LSA list entry. Only fixed owned files are deleted. Loaded files remain with an
ownership marker; manually reboot, sign in with Windows PIN/password and rerun cleanup.
Do not force-delete LSASS/LogonUI or change protected-LSA policy. A VM unable to boot
must be restored from its pre-install checkpoint. [Signing and setup](lsa-signing-and-setup.md)
contains the required recovery/acceptance checklist before physical deployment.
