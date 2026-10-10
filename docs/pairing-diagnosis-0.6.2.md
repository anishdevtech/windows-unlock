# Pairing diagnosis and repair, October 11, 2026

## Observed cause

The current hosted companion reported no local pairing and a pending revocation,
while an authenticated relay check reported an active pairing and a registered
phone push token. A native diagnostic using the production HTTP client
reproduced HTTP 409 while retrying that exact pending revocation. TLS and device
authentication succeeded; the earlier empty-JSON request fix was already present.

Read-only PostgreSQL inspection found one legacy Android row with
`tokenHash: "revoked"` and the unique `android_token_lookup` index. Revoking the
next phone assigned that same value, violated the index, and rolled back the whole
transaction. Local trust had already been removed, leaving the two states split
and preventing the next invitation from being displayed.

The previous header was also constructed only when the window opened. A successful
pairing updated the config and remote controls, but left the header saying
"No paired phone". Old remote-action text could survive unpairing. These separate
UI defects explain the contradictory screenshot.

## Repair

Revocation now removes the phone's token hash. A missing hash cannot match any
authenticated bearer token and permits multiple revoked phones under the existing
PostgreSQL unique index. No schema migration or index removal is needed. Retry
still requires the owning laptop and returns the already-revoked result safely.

The Windows companion visibly identifies itself as 0.6.2, refreshes its identity
and phone name after operations, shows pending server revocation explicitly, clears
remote-control status when unpaired, and discards queued updates from old remote
agents. Pairing is labelled **Pair phone / QR**. Failed operations include their
stage and safe HTTP status; raw server bodies, tokens and key material are omitted.
Connection checks compare local and authenticated relay state. CLI diagnostics now
include authenticated relay pairing, local pending revocation, and version. State
comparison checks the pairing ID and phone ID, rather than only two paired flags.

## Password sign-in is a separate binding

Hosted records show the latest approved password-vault enrollment belongs to an
older pairing than the newly confirmed phone. Unpairing intentionally invalidates
that enrollment's authority. A running service or an approved desktop connection
test cannot establish that the current phone can release the password key.

The ordinary readiness probe passed and the installed service is running. The
non-elevated vault-status tool could not access/validate the administrator-protected
vault; that result alone does not mean the stored vault is missing. No password,
PIN, encrypted vault, machine signing key or Windows security policy was changed
while diagnosing this issue.

After pairing again, run the local masked enrollment under the same Windows account
and approve **Enable phone sign-in** on the phone. The existing setup script stops
and restarts the owned service around enrollment. Never paste a password into chat.
Follow [password sign-in setup](password-unlock-setup.md). Existing devices that
have not been unpaired do not need to enroll simply because of this update.

## Verification

The PostgreSQL regression was run before the fix and failed with **409 instead of
200** on revocation after a legacy revoked row. With the fix, all 26 security/vault
tests passed with PostgreSQL enabled for the security-suite fixtures, including successive revocations,
retry, old-token rejection and unrelated legacy-row preservation.

The complete relay suite passes 41 tests. Windows companion Release and HTTP-test
builds pass. Ten of eleven existing CTest checks pass; `password_ipc_security`
cannot bind the production pipe while the installed password service owns it.
The service was left running. No IPC implementation was changed in this repair.

Live QR display and authenticated local/server reconciliation are checked after
deployment. Actual phone scanning, matching-code confirmation, password enrollment
and LogonUI sign-in still require interaction on the user's devices; build/test
success does not claim those acceptance steps succeeded.
