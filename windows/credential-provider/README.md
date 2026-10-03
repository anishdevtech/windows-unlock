# Deferred Phase 6 Credential Provider

V2 native COM provider, local console CPUS_LOGON/CPUS_UNLOCK_WORKSTATION only.
No networking or camera in DLL; asynchronous bounded IPC and visible PIN fallback.
No provider filter, wrapping, default selection changes or password/PIN automation.

Do not register this component until a password-free Windows authentication path
compatible with the account type and protected LSA is proven in disposable VMs.
Successful desktop signature verification alone does not supply a Windows credential.
