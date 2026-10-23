# e3-event-system

This is runtime composition for buses, aggregate event stores, snapshot buffering, and data stores,
not a protocol decision owner. Keep it usable by lower-level tests without importing the ciphernode
builder or protocol orchestration crates.

- Configure bus/backend/aggregate options before their first getter: lazy cells keep the first
  value. Tests use `with_fresh_bus()` or an explicit bus to avoid sharing the process-wide default.
- Persisted schema admission precedes opening logs/indexes. Seed the bus clock from every store's
  durable maximum before enabling publication, not merely from snapshot time.
- Attach `SubscribePreFanout` before creating BusHandle so dedup cannot hide snapshot admission.
  Connect the same persistence failure signal to stores and the aggregate router, for both backends.
- Aggregate log names and `sequence_index.{index}` are persisted locations, not cosmetic filenames.
  Keep both in-memory and persisted recipients usable; the existing recipient helpers cover both.
- Shared store/reader caches retain their first instance; only production composition opts into
  them.

[Persistence contracts](../../docs/architecture/persistence-and-replay.md) describe fences and
current limits; [upgrades](../../docs/architecture/upgrades.md) governs layout/path changes. Use the
[README tests/prerequisites](README.md#tests). Persistence changes need the disk-backed path;
in-memory composition is not a disk-crash test.
