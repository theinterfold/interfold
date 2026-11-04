# Ciphernode composition and services

Ciphernode composition, process-fenced operations, compute dispatch, and local command transport
share this family because they assemble and operate a ciphernode. Each remains an independently
importable package in the root Cargo workspace; this directory is not a package or nested workspace.

- [builder](builder/README.md) composes full/bootstrap nodes and recovery.
- [config](config/README.md) resolves node profiles, paths, and network/release identity.
- [daemon-server](daemon-server/README.md) provides loopback CLI control transport.
- [entrypoint](entrypoint/README.md) owns startup, process management, and durable-state safety
  checks.
- [multithread](multithread/README.md) coordinates node compute admission and replay/retry policy.

The [CLI](../cli/README.md) and CLI-owned [initializer](../init/README.md) remain standalone roots:
they serve application projects as well as ciphernode operators. Generic
[task-pool](../task-pool/README.md), [console](../console/README.md), and
[filesystem](../fs/README.md) capabilities remain separate roots rather than becoming node-specific
utilities.

Checkout-relative paths for this family's members start with `crates/ciphernode/`. Use the
[workspace setup](../README.md#setup-and-checks) and each member's checks. Startup ordering and
dispatch recovery remain governed by
[persistence and replay](../../docs/architecture/persistence-and-replay.md);
[upgrades](../../docs/architecture/upgrades.md) owns compatibility and rollback decisions.
