# Disposable-VM preview installer sources

`Install-PreviewInVm.ps1` refuses physical machines, requires explicit disposable-VM
and tested-recovery flags plus elevation, and requires trusted payload signatures by
default. Unsigned development payloads are an explicit VM-only option; OS security
policy is never lowered. It owns only its provider GUID/COM CLSID, service and fixed
files. It preserves Microsoft providers/defaults and attempts rollback of its own
changes on failure. No LSA package or real Windows credential is installed.

`Uninstall-Preview.ps1` verifies the owned manifest/paths, unregisters only the preview,
and removes fixed files without recursive deletion. Loaded DLLs retain the ownership
marker for retry after normal sign-in. `-RemoveEnrollment` also requests deletion of
the fixed preview enrollment. No installer/uninstaller has been executed on this laptop;
only parsing and physical-machine refusal were tested.

See [native development](../../docs/native-development.md). Production transactional
setup, signing and full VM recovery acceptance remain release gates.
