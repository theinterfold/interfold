# e3-slashing

## Purpose

Ciphernode accusation admission/voting and cross-proof commitment consistency. This capability
authenticates evidence and forms votes; the EVM adapter submits accepted quorum outcomes and
contracts settle them. `e3-zk-prover` retains compatibility re-exports, not another implementation.

## Map

| Location                                                                                                                                           | Responsibility                                                                     |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| [`accusation_voting/`](src/accusation_voting)                                                                                                      | Authenticated vote state, pure admission/transitions, actor delivery, and effects. |
| [`commitment_consistency/`](src/commitment_consistency)                                                                                            | Cross-proof comparisons, roster history, and consistency snapshots.                |
| [`accusation_manager_ext.rs`](src/accusation_manager_ext.rs), [`commitment_consistency_checker_ext.rs`](src/commitment_consistency_checker_ext.rs) | Per-E3 construction/hydration.                                                     |
| [`repo.rs`](src/repo.rs)                                                                                                                           | Accusation-vote/consistency persistence and layout fixtures.                       |

Local proof/commitment observations and received accusations pass authentication/attribution before
voting. The workflow tallies one signed preimage/window and emits outcomes for the EVM writer;
consistency checks supply evidence but do not execute a slash.

## Router extensions

Register these per-E3 capabilities through `E3RouterBuilder::with_recipient`:

- `AccusationManagerExtension::create(bus, signer, slashing_managers_by_chain, vote_validity_secs_by_chain, deadline_skew_secs, persisted_committees, store)`
  creates/hydrates the `accusation_manager` recipient. Manager addresses bind signatures to the
  correct chain's SlashingManager; committees supply canonical party attribution. The shared store
  supplies per-E3 saved votes.
- `CommitmentConsistencyCheckerExtension::create(bus, store, links_factory)` supplies the
  `commitment_consistency_checker` recipient. The factory maps a BFV preset to the expected
  `CommitmentLink` rules; the standard composition uses `e3_zk_prover::default_links`.

The [builder caller](../ciphernode-builder/src/builder/extensions.rs) shows chain-specific
configuration and registration. Exported `AccusationManager` and `CommitmentConsistencyChecker` also
support lower-level harnesses; extensions are the normal runtime entry.

## Evidence boundary

Authentication, request/party attribution, proof type, and signed windows precede evidence/vote
admission. Local process, I/O, and memory failures are not invalid-peer proofs. Quorum agrees on a
specific preimage, not just any collection of accusation labels.

Hydration restores pending accusations with this node's vote, admitted votes, absolute timeouts,
failed-proof evidence, and accused-proof identities. Vote timers resume at `EffectsEnabled`. Local
failures during replay wait for effects, including in actors that replay creates. Buffered votes and
in-flight re-verifications remain volatile; snapshot enqueue is not a flush acknowledgment.

`CommitteeMemberExpelled`, not `SlashExecuted`, removes voters and their votes. A slash without
expulsion leaves voting and accusation rights intact; finalized party IDs do not change.

The [slashing domain](../../docs/architecture/slashing.md) documents accusation lanes, quorum, and
settlement dependencies; [DKG](../../docs/architecture/dkg.md) owns commitment links.

## Tests

Run `cargo test --locked -p e3-slashing`. Voting workflow tests cover admission, tally,
equivocation, and timeouts; actor/extension tests cover signature digests/windows, saved vote
recovery, replay deferral, and expulsion. Consistency tests cover link/roster indices, snapshot
versions, and hydration. `pnpm rust:test:slashing` is the separate proof-to-contract suite with
[prover prerequisites](../zk/prover/README.md). See [AGENTS.md](AGENTS.md) for evidence/quorum
change constraints.
