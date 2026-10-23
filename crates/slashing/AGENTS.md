# e3-slashing

This crate owns accusation admission/voting and cross-proof consistency. The zk-prover compatibility
re-export does not own a second implementation. Keep vote/quorum decisions pure and
timer/publication effects explicit.

- Authentication, E3/party attribution, proof type, and signed window checks precede evidence
  caching or vote-window mutation. Unauthenticated labels and local infrastructure failures are not
  evidence.
- Preserve shared Rust/Solidity digest bytes and distinguish quorum on one preimage from unresolved
  equivocation. Legacy threshold_m is not the accusation quorum; use the domain's H contract.
- Restore commitment history/accepted roster before comparisons. Non-prefix roster rows and
  full-committee recipient slots use different indices; absence from an incomplete cache is not
  fault.
- Save and restore pending voted accusations, admitted votes, absolute timeouts, failed-proof
  evidence, and accused-proof identities. Re-arm timers and release deferred local accusations only
  at `EffectsEnabled`, including for actors created during replay.
- Remove voters only on `CommitteeMemberExpelled`, idempotently across raw/enriched copies. A
  `SlashExecuted` without expulsion preserves their rights and fixed finalized slots.
- Buffered votes, window-move limits, and in-flight re-verifications remain volatile. Keep those
  limits and failed-snapshot-write behavior visible rather than claiming complete crash durability.

[Slashing](../../docs/architecture/slashing.md) owns lanes and settlement dependencies;
[DKG](../../docs/architecture/dkg.md) owns commitment links. Use the
[README test map](README.md#tests); proof-to-slash changes require the prepared integration suite,
not only local vote outcomes.
