# Ciphernode composition and services

Ciphernode composition, compute dispatch, and local command transport share this family because they
assemble and operate a ciphernode. Each remains an independently importable package in the root
Cargo workspace; this directory is not a package or nested workspace.

- [builder](builder/README.md) composes full/bootstrap nodes and recovery.
- [daemon-server](daemon-server/README.md) provides loopback CLI control transport.
- [multithread](multithread/README.md) coordinates node compute admission and replay/retry policy.

The [configuration](../config/README.md), [CLI](../cli/README.md), CLI-owned
[initializer](../init/README.md), and process-fenced [entrypoint](../entrypoint/README.md) currently
remain at their flat locations. Generic [task-pool](../task-pool/README.md),
[console](../console/README.md), and [filesystem](../fs/README.md) capabilities remain separate
roots rather than becoming node-specific utilities.

Checkout-relative paths for this family's members now start with `crates/ciphernode/`; Cargo package
selection and downstream Git dependency names are unchanged. Use the
[workspace setup](../README.md#setup-and-checks) and each member's checks. Startup ordering and
dispatch recovery remain governed by
[persistence and replay](../../docs/architecture/persistence-and-replay.md);
[upgrades](../../docs/architecture/upgrades.md) owns compatibility and rollback decisions.
