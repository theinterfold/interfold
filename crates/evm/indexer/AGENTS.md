# e3-indexer

Read [the indexer contract](README.md) before changing catch-up, handler delivery, or cursor writes.
The applied-block cursor is a best-effort raw-handler watermark, not a transaction over all
projections.

- Backfill is opt-in. Do not acquire replay side effects merely by upgrading a consumer that starts
  at head; raw handlers must tolerate duplicates and return failed writes as errors.
- Preserve both pre-subscribe and confirmed-subscription catch-up passes. Only the second qualifies
  live progress; headers alone cannot prove logs below them were applied.
- Capture only required shared fields in block handlers, not Arc<IndexerContext>: the context owns
  its listener and that capture leaks the whole indexer through a reference cycle.
- Consumer coverage must be checked against live deployment/configuration, not trusted forever just
  because a record remains in a store with no delete operation.

`build.rs` invokes `scripts/build_fixtures.sh` even for a check and can rewrite fixture JSON; edit
Solidity rather than generated ABI/bytecode. Use the [README tests/prerequisites](README.md#tests);
listener progress checks live in e3-evm-helpers. Neither the atomic high-water claim nor typed
callback success proves durable all-handler completion. Catch-up changes need an affected
consumer/reconnect scenario, not only a higher stored block number.
