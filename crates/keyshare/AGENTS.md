# e3-keyshare

This capability owns DKG collection and the node's secret-share lifecycle. Keep crypto calculations
separate from mailbox/effects without changing authenticated dealer identity or contribution bytes.

- Authenticate complete dealer messages before saving/reserving slots. A rejected signature cannot
  accuse its claimed dealer or consume that dealer's valid replacement.
- Reuse successful randomized contributions exactly after restart. Early replayed responses wait for
  restored prerequisites; local worker failure before success can retry without accusing peers.
- C2/C3 outcomes authorize only their dispatch batch. Late growth, replaced proof plans, and retired
  collectors must not reuse earlier verdicts/correlations.
- Roster choice is not first-arrival immutability: a supported lower-ranked roster may replace one
  before C4, then fixation is required. Preserve the documented stale-write/double-restart gap.
- Canonical key publication supersedes DKG failures; a local PublicKeyAggregated intent does not. C6
  work waits for confirmed key authority and coalesces repeated resume signals.

[DKG](../../docs/architecture/dkg.md) and
[decryption](../../docs/architecture/threshold-decryption.md) own dimensions, timing, signatures,
and recovery requirements. `cargo test -p e3-keyshare` is focused actor coverage; statement changes
still require prepared real-proof tests. The test graph includes EVM/prover adapters; see
[helper prerequisites](../test-helpers/AGENTS.md) for solc/jq, fixtures, and build-time Noir side
effects before invoking Cargo.
