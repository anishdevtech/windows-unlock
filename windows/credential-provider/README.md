# V2 Credential Provider approval preview

`CredentialProviderPreview.dll` implements native COM `ICredentialProvider`,
`ICredentialProviderSetUserArray`, and SID-bound `ICredentialProviderCredential2`.
It exposes **Unlock with Phone**, starts asynchronous approval when selected, shows
waiting/approval/denial/expiry/unavailable status, and displays **Sign-in options → PIN**.
Only local console logon/unlock scenarios are enumerated. Networking, pairing,
cryptography and cameras stay outside the DLL.

**GetSerialization always returns CPGSR_NO_CREDENTIAL_NOT_FINISHED and an empty
credential.** Valid desktop phone signatures cannot sign in to Windows. No default
override, provider filter, automatic sign-in, stored password or PIN simulation exists.
IPC is bounded; UI events return to the subscription thread.

The COM harness loads the DLL as an ordinary process without registration. Builds
do not install it; there is no self-registration export. See
[native development](../../docs/native-development.md) for VM-only testing and the
separate Windows authentication release gate.
