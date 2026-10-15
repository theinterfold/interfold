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
- Recreating an actor after restart does not reconstruct volatile votes/timers. Keep that limit and
  failed-snapshot-write behavior visible rather than describing the whole capability as durable.

[Slashing](../../docs/architecture/slashing.md) owns lanes and settlement dependencies;
[DKG](../../docs/architecture/dkg.md) owns commitment links. Run `cargo test -p e3-slashing`; use
the prepared `pnpm rust:test:slashing` suite for changed proof-to-slash behavior.
