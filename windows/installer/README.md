# Deferred Phase 7 installer

WiX installer must own only its COM CLSID/provider GUID/service/files, preserve
Microsoft providers and defaults, verify recovery methods, reject incompatible
authentication configuration, and support transactional rollback/safe uninstall.
Never disable LSA protection or change provider exclusion policies. Phase 1 uses
ordinary build/setup scripts and registers no authentication components.
