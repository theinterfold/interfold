# l-BFV PR Design

## Summary

This PR adds an l-BFV proof path beside the existing DKG circuits for `secure-16384/minimum`.

The new circuits prove five public-key and relinearization-key rows. They link those rows to the
same parties and secret-key shares that legacy DKG uses. The final circuit produces one Honk proof
with 63 public inputs for EVM verification.

```text
Per party:
  legacy C0-C4 -> legacy NodeFold -----------\
  C1 + five l-BFV PK/RLK row proofs -> fold -> NodeFoldV2
                                                   |
  H NodeFoldV2 proofs -> NodesFoldV2 --------------+
                                                    |
Aggregator:                                         v
  five PK/RLK aggregation proofs -> aggregation fold
                                                    |
  NodesFoldV2 + legacy C5 + aggregation fold
                      -> DkgAggregatorV2
                      -> BfvPkVerifierV2
                      -> publishCommittee()
```

## Circuit Design

- `lbfv_pk_generation` proves one public-key contribution row against the compile-time CRS. It
  returns commitments to the party's secret key and public-key contribution.
- `rlk_generation_limb` proves one CRT limb of one relinearization-key row. It enforces bounds and
  uses the fixed CRS, URS, and gadget constants.
- `rlk_generation` recursively verifies every CRT-limb proof for one row. It returns row-level `d0`
  and `d2` commitments.
- `lbfv_generation_fold` folds the five ordered PK and RLK row pairs. It enforces one session,
  party, secret key, RLK randomness value, and row order.
- `NodeFoldV2` verifies an existing legacy `NodeFold`, the applicable C1 proof, and the completed
  generation fold. The C1 check links the l-BFV secret-key commitment to the legacy DKG secret
  share.
- `NodesFoldV2` folds exactly `H` party proofs. It requires ascending and distinct party IDs.
- `lbfv_pk_aggregation` proves that one aggregate PK row is the sum of the selected `H`
  contributions.
- `rlk_aggregation` proves the same relation for one aggregate RLK `d0/d2` row.
- `lbfv_aggregation_fold` folds all five aggregation rows. It binds them to one session, aggregator,
  and accepted-party-set hash.
- `DkgAggregatorV2` verifies `NodesFoldV2`, legacy C5, and the l-BFV aggregation fold. It matches
  each aggregation input commitment to the applicable generation commitment.

The final circuit also preserves the existing legacy checks:

- C2 and C4 share consistency.
- C0 and C3 recipient-key consistency.
- C1 and C5 public-key consistency.
- Committee membership and ordered accepted parties.
- Legacy chunk hashes.

The legacy and V2 proof families have separate verification-key manifests. The legacy manifest has
16 hashes, and the V2 manifest has 12 hashes. This separation prevents substitution between legacy
and V2 circuits that have similar statement layouts.

## Contract Wiring

- `BfvPkVerifierV2.sol` verifies the generated `DkgAggregatorV2Verifier` proof.
- Its constructor pins the generated verifier, registry, recursive proof roots, legacy manifest, and
  V2 manifest.
- The verifier requires exactly 63 public inputs.
- The verifier recalculates the EVM domain binding from the chain ID, verifier address, `e3Id`,
  committee root, selected nodes, committee hash, session, accepted parties, and PK commitment.
- The verifier checks that the accepted party IDs identify members of the finalized on-chain
  committee.
- `BfvPkVerifierRouter.sol` selects a verifier from the statement length and the first two recursive
  verification-key anchors.
- Deployment selects `pkVerifierV2` when a V2 verifier exists. Thus, `secure-16384/minimum` has one
  permitted public-key proof path and no legacy bypass.
- `CiphernodeRegistryOwnable.publishCommittee()` supplies the finalized on-chain committee and root
  to the selected verifier. Publication also requires the existing fold-attestation bundle.

## Scope Boundaries

- The contract-facing `pkCommitment` is still the legacy C5 aggregate-key commitment.
- The circuits prove all five l-BFV public-key rows, but the contracts do not publish the complete
  encryption key. Issue #1739 tracks this work.
- The circuits prove the aggregate relinearization key, but the contracts do not store its
  commitment or bind it to computation verification. Issue #1740 tracks this work.
- This PR establishes the proof structure and the EVM verification path. It does not complete
  external public-key or relinearization-key publication.
- The implementation is specific to five rows and `secure-16384/minimum`, with `N=3`, `H=2`, and
  `T=1`.

## Artifact Status

The circuit source changes are complete. Fresh `secure-16384/minimum` artifact generation and
benchmarking remain necessary to confirm the current verifier, verification keys, and checksums.
These results are the remaining closure evidence for issue #1741.

## Follow-Up Work

- Public-key chunk recovery currently stores incomplete chunk bodies in the
  `DataAvailabilityRecoveryState` schema-2 snapshot. Each candidate is limited to 6 MiB, but active
  candidates have no global memory or snapshot-size bound. Move chunk bodies to content-addressed
  disk records, retain bounded metadata in memory, and migrate existing schema-2 snapshots. An
  eviction-only change is unsafe because it can remove the only recoverable candidate.
- Terminal cleanup removes encrypted l-BFV generation material from snapshots, but append-only
  historical protocol-event records can retain encrypted material. Selective deletion is not
  compatible with current replay semantics. A follow-up must add replay-safe event indirection or
  cryptographic key retirement. This limitation does not expose plaintext and does not make the
  large documents available through generic gossip.
- Lane A replay protection intentionally permits one penalty for each `(E3, operator, proofType)`.
  The signed `proofInstance` identifies a row but does not create another economic penalty.
- The V2 `aggregatorId` binds the aggregation statement to an in-range committee party. It does not
  authorize the transaction sender because committee publication is permissionless.
