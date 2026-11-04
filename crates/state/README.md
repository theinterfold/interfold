# Persistence and event-runtime state

Durable storage and event-runtime assembly share this family so persistence and the runtime that
wires it into recovery are discoverable together. Each member remains an independently importable
package in the root Cargo workspace; this directory is not a package or nested workspace. The
grouping does not claim that repositories or runtime assembly are I/O-free.

- [storage](storage/README.md) (package `e3-data`) provides scoped key/value access, typed
  repositories, snapshot-backed state, event logs, sequence indexes, and oversized event blobs.
- [event-system](event-system/README.md) assembles the event bus, per-aggregate event stores,
  sequencer, and snapshot buffer over storage.

[Events](../events/README.md) remains a flat root: it owns event identity, payloads, and pipeline
behavior used well beyond this family. [HAMT](../hamt/README.md) remains a focused root behind
storage's in-memory snapshots. Historical [sync/replay](../sync/README.md) and per-E3
[request routing](../request/README.md) currently remain separate roots.

Checkout-relative paths for this family's members start with `crates/state/`. Use the
[workspace setup](../README.md#setup-and-checks) and each member's checks. Durable formats,
snapshot/hydration, and replay ordering are governed by
[persistence and replay](../../docs/architecture/persistence-and-replay.md);
[upgrades](../../docs/architecture/upgrades.md) owns compatibility and rollback decisions.
