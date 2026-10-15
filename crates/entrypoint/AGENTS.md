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

Run `cargo test --locked -p e3-entrypoint` with solc/jq and prepared contract fixtures for
transitive dependencies; [zk-prover](../zk-prover/AGENTS.md) documents build-time Noir side effects.
Use temporary node directories for fence/validate/purge regressions. See
[persistence](../../docs/architecture/persistence-and-replay.md) for cross-layer recovery limits.
