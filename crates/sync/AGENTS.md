# e3-sync

This crate coordinates replay and historical reconciliation; it is not an Actix actor or a protocol
decision owner. Keep planning independent from adapters when changing the existing module boundary.

- Inspect raw schema/role before opening or repairing state. Identity-only fresh-store admission is
  deliberately narrower than “the database has no events.”
- Replay keeps durable sequence within an aggregate and uses HLC only between aggregate heads.
  Respect both count/byte pages and physical head; short/filtered-empty pages need not mean EOF.
- Preserve separately acknowledged EffectsEnabled, SyncEffect, canonical-history, and SyncEnded
  boundaries. A current-boot control signal cannot be supplied by a previous boot's journal.
- Use ReplaySpool load/replay in regressions, not a test-only sort loop. A separate source bus
  avoids accidentally preparing destination clocks/dedup during fixture creation.
- Network recovery has one cumulative startup budget. Failure to obtain required history must not
  become an unannounced partial resync; bootstrap's optional peer-history policy is explicit.

[Persistence](../../docs/architecture/persistence-and-replay.md) and
[network history](../../docs/architecture/network-delivery.md#historical-sync-and-coverage) own the
cross-layer contract. Run `cargo test -p e3-sync`; full replay/hydration equivalence remains
unproven. The dev-dependency graph includes [test helpers](../test-helpers/AGENTS.md); prepare their
Solidity/prover prerequisites rather than assuming the replay-only target has no external tooling.
