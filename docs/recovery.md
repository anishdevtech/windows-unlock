# Recovery

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
