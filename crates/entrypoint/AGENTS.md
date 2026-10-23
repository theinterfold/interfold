# e3-entrypoint

This crate owns executable node operations and their safety checks; builder owns composition and
capability crates own protocol decisions.

- Acquire and retain the process fence before opening state. Lock-file contents are diagnostics, not
  proof of ownership; dropping the guard releases the actual advisory lock.
- Offline validation inspects schema before decoding/repairing state and remains read-only unless
  repair is explicit. Never turn unsupported schema or indexed corruption into automatic reset.
- Purge separates discovered facts, pure planning, and effects. Preserve locks across checking and
  deletion, custom store/key paths, symlink handling, and keyshare/unsubmitted-slash guards. Do not
  replace checked store preflight with ordinary “missing means empty” reads.
- Keep full/bootstrap startup and fatal persistence shutdown routed through their existing owners.
  Test-only proof-skip propagation must not become a production artifact fallback.
- Install the actor panic watch on the Actix thread before actors start. Preserve its thread filter
  and CLI shutdown/error path; other-thread panics stay with their own worker or server.

Use the [README tests/prerequisites](README.md#tests). Use temporary node directories for
fence/validate/purge regressions; never use an operator's populated state as a fixture. See
[persistence](../../docs/architecture/persistence-and-replay.md) for cross-layer recovery limits.
