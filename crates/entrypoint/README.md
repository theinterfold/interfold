# Node operations and entrypoints

This crate turns CLI configuration into node startup and manages local multi-process nodes. Protocol
decisions remain in their domain crates; the ciphernode builder owns composition/startup
dependencies.

## Process and state ownership

Start acquires the process fence and opens/decrypts the intended identity before constructing the
node. Bootstrap and full roles cannot reuse one populated directory: their reader sets share chain
cursors. [Persistence](../../docs/architecture/persistence-and-replay.md) owns role/schema
admission, and
[upgrades](../../docs/architecture/upgrades.md#controlled-state-reset-never-directory-deletion) owns
identity-preserving reset and the limits of purge/store discovery.

`node validate` is read-only by default. Repair is limited to verified uncommitted tails and derived
membership/history mismatches, not indexed corruption, unknown schemas, or recovery of lost secrets.

Managed children receive SIGTERM first and may use the node shutdown deadline plus five seconds
(currently 65 seconds), then SIGKILL. Output forwarding drains for up to five more seconds before
abort. Child handles use kill-on-drop; partial-start failure cleans children already started, and
cleanup failure yields a nonzero supervisor exit. Exited state is restartable by an operator action,
not reported as Started. There is no persisted desired-state or automatic unexpected-exit restart
policy. Detached daemon launch outlives its CLI launcher; managed-child containment is different.

## Verification

Use `cargo test -p e3-entrypoint`; schema/startup tests may need Foundry/Anvil. The integration
suite owns multi-process restart/shutdown scenarios. Supervisor cleanup tests do not prove all
detached application tasks have drained. CLI persistence-health monitoring is owned by `e3-cli`, not
implied by an Actix actor panic.
