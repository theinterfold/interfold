# Persistence and event-runtime state

Durable storage, event-runtime assembly, startup recovery, and per-E3 request routing share this
family so persistence and the paths that restore and replay it are discoverable together. Each
member remains an independently importable package in the root Cargo workspace; this directory is
not a package or nested workspace. The grouping does not claim that repositories, runtime assembly,
recovery, or routing are I/O-free.

- [storage](storage/README.md) (package `e3-data`) provides scoped key/value access, typed
  repositories, snapshot-backed state, event logs, sequence indexes, and oversized event blobs.
- [event-system](event-system/README.md) assembles the event bus, per-aggregate event stores,
  sequencer, and snapshot buffer over storage.
- [sync](sync/README.md) runs startup schema/role preflight, historical reconciliation, and replay,
  including request-router checkpoint projection.
- [request](request/README.md) routes events to per-E3 contexts, restores them from checkpoints, and
  projects E3 lifecycle state.

[Events](../events/README.md) remains a flat root: it owns event identity, payloads, and pipeline
behavior used well beyond this family. [HAMT](../hamt/README.md) remains a focused root behind
storage's in-memory snapshots.

Checkout-relative paths for this family's members start with `crates/state/`. Use the
[workspace setup](../README.md#setup-and-checks) and each member's checks. Durable formats,
snapshot/hydration, and replay ordering are governed by
[persistence and replay](../../docs/architecture/persistence-and-replay.md);
[upgrades](../../docs/architecture/upgrades.md) owns compatibility and rollback decisions.
