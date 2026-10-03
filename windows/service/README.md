# Native approval-preview service

`PhoneUnlockPreviewService.exe` runs through SCM as LocalSystem in a disposable VM.
It authorizes the real LogonUI process/session on a restricted local pipe and binds
operations to caller PID, enrolled SID, console session, scenario and GUID. The worker
signs challenges with the paired user's NCrypt key under scoped impersonation, then
performs HTTPS and independent CNG phone verification with one-time consumption.
It returns only preview status, never Windows credentials.

The separate elevated `PhoneUnlockPreviewStage.exe` stages an existing pairing into
strict, machine-DPAPI, SYSTEM/Administrators-only enrollment. It refuses existing
enrollment and tampered ownership/ACL/reparse configuration. No setup command is
exposed to LogonUI IPC. Event Log records contain timestamp/device/result/request ID
and null snapshot path. The service captures no camera images.

Not installed on the development laptop. SCM/user-key/profile behavior needs VM
validation; no Windows authentication authority is implemented. See
[native development](../../docs/native-development.md).
