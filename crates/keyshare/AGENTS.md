# e3-keyshare

This capability owns DKG collection and the node's secret-share lifecycle. Keep crypto calculations
separate from mailbox/effects without changing authenticated dealer identity or contribution bytes.

- Authenticate complete dealer messages before saving/reserving slots. A rejected signature cannot
  accuse its claimed dealer or consume that dealer's valid replacement.
- Reuse successful randomized contributions exactly after restart. Early replayed responses wait for
  restored prerequisites; local worker failure before success can retry without accusing peers.
- During replay, record inputs but start no collectors or timers. Actors created from replayed
  selection inherit `E3Context::effects_enabled`; rebuild collectors at `EffectsEnabled`.
- Keyless missing dealers may advance the soft share checkpoint, never the canonical DKG deadline or
  H−1 verification requirement. Rebuilt collectors must receive the same keyless-dealer set.
- C2/C3 outcomes authorize only their dispatch batch. Late growth, replaced proof plans, and retired
  collectors must not reuse earlier verdicts/correlations.
- Roster choice is not first-arrival immutability: a supported lower-ranked roster may replace one
  before C4, then fixation is required. Preserve the documented stale-write/double-restart gap.
- Canonical key publication supersedes DKG failures; a local PublicKeyAggregated intent does not. C6
  work waits for confirmed key authority and coalesces repeated resume signals.

[DKG](../../docs/architecture/dkg.md) and
[decryption](../../docs/architecture/threshold-decryption.md) own dimensions, timing, signatures,
and recovery requirements. Use the [README tests/prerequisites](README.md#tests). Statement changes
still require prepared real proofs; collection/recovery changes need authenticated rejection, roster
replacement, and resumed-history cases, not only the happy path.
