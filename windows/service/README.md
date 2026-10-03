# Deferred Phase 6 service

Reuse `windows/core`. Expose separate restricted setup and LogonUI IPC contracts.
Authorize callers using OS identity, reject remote pipe clients and pipe spoofing,
bind requests to SID/session/tile/scenario, and fail closed without blocking other
providers. Run no privileged service during Phase 1. Investigate session-aware webcam
broker in Phase 5; Session 0 capture is not assumed to work on secure desktop.
