# Persistence

The node's durable state shares this family. Each member remains an independently importable package
in the root Cargo workspace; this directory is not a package or nested workspace.

- [journal](journal/) (package `e3-journal`) keeps the node's inputs, the machine's snapshots, and
  the outbox of effects in one redb file, so one transaction covers each machine step.
- [blobs](blobs/) (package `e3-blobs`) stores large payloads once per E3, named by their Keccak-256
  hash; the machine and its snapshots hold only references.

Checkout-relative paths for this family's members start with `crates/state/`. Use the
[workspace setup](../README.md#setup-and-checks) and each member's checks. Replay and the journal's
layout are recorded in the [decision log](../../docs/architecture/node-v2-decisions.md);
[upgrades](../../docs/architecture/upgrades.md) owns compatibility and rollback decisions.
