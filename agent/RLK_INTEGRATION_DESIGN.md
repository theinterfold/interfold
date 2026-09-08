# Threshold l-BFV RLK Integration Design

Status: pure adapters and the l-BFV public-key, RLK generation, and RLK aggregation helper/prover
boundaries are implemented. Runtime collection, aggregation, storage, and publication remain
pending. This document records verified interfaces, the integration boundary, and decisions that
require protocol approval. It does not define a wire schema or on-chain ABI.

## Scope

The target is a threshold l-BFV relinearization-key (RLK) extension for one E3:

1. Generate one l-BFV public-key contribution and one RLK contribution per accepted party.
2. Produce public-key and RLK proofs for each gadget row.
3. Verify and aggregate the accepted contributions.
4. Persist enough data to recover the operational RLK after restart.
5. Use the recovered RLK for ciphertext multiplication and relinearization.

The existing TrBFV key-generation, decryption, and C0-C7 paths remain in place. The `secure-8192`
preset keeps the existing circuit set. The `secure-16384` preset adds dedicated l-BFV row circuits
and the matching runtime path. The path must remain compatible with the existing committee, proof,
event, and recovery rules.

## Verified Boundary

The locked `fhe::trlbfv` API provides additive l-BFV contributions. It does not provide threshold
decryption, transport authentication, ZK proofs, or witness serialization.

### l-BFV library

- `PublicKeyShare` represents one additive public-key contribution.
- `RelinKeyShare` represents one additive RLK contribution.
- `RelinKeyShare::contribution_with_crp_extended` returns the RLK share and an `RlkWitness`.
- `RlkWitness` contains the auto-zeroized ephemeral key `r`, `errors_d0`, and `errors_d2`.
- `aggregate_relinearization_key` requires the selected shares and an `LBFVPublicKey`.
- RLK aggregation sums the secret-dependent `c0` components and carries the shared `c1` components.
- An operational `LBFVRelinearizationKey` does not retain participant metadata.
- The library validates arithmetic structure, shared URS and CRS values, and public-key consistency.
- Interfold must authenticate contributions, select the canonical participant set, and reject
  duplicate inclusion before library aggregation.
- The locked `fhe.rs` revision exposes validated, read-only `d0` and `d2` row components and level
  metadata. Interfold computes the circuit-specific quotient polynomials.

### Paper-to-library parameter mapping

The paper defines `a` and `d1` as vectors of `l` ring elements. In the pinned implementation, `l` is
the number of RNS key-switching slots, which is the number of moduli at the relevant level under the
HPS optimization. Each slot is a polynomial represented over all RNS limbs. Therefore, the circuit
representation is a matrix with shape `[gadget_slot][rns_limb]`:

- the outer index selects one `d1` or `a` key-switching slot;
- the inner index selects one CRT limb of that polynomial;
- `G_GADGET_ROWS[slot]` is the corresponding `RnsContext::get_garner(slot)` value, reduced to the
  circuit field. In the pinned implementation, this is `q_star[slot] * q_tilde[slot]`, where
  `q_tilde[slot]` is the inverse of `Q / q_slot` modulo `q_slot`;
- `LBFV_URS_GADGET_ROWS[slot]` contains the concrete `d1` polynomial for that slot;
- `LBFV_CRS_GADGET_ROWS[slot]` contains the concrete `a` polynomial for that slot.

The paper's equations and the pinned implementation agree:

```text
d0_j = -sk*d1_j + e0_j + r*g_j
d2_j = r*a_j + e2_j + sk*g_j
```

The existing repository CRP helper returns one deterministic `CommonRandomPoly` and the existing C1
path proves one public-key polynomial in CRT form. It is not an l-BFV `CommonRandomPolyVec` and
cannot populate all RLK rows by repetition. The RLK-enabled public-key path must provide `L`
independent `a_j` polynomials, and the RLK path must provide `L` independent `d1_j` polynomials. The
C1 row extension must therefore define how those l-BFV public-key rows are generated and bound;
reusing the existing single `CRP` literal is not a valid production design.

The key-switching context also fixes the Garner values and row count. These values cannot be chosen
independently of `ciphertext_level`, `key_level`, and the parameter moduli. The current public
library wrappers support the level-0 path, so the first implementation should reject other levels
until the circuit constants and adapters support them.

The current Noir entry point selects `LBFV_URS_GADGET_ROWS` and `LBFV_CRS_GADGET_ROWS` as
compile-time constants. The initial design therefore uses release/config-scoped l-BFV public
randomness. The `secure-16384` seeds are defined in `crates/fhe-params/src/lbfv.rs`, and the
generated `secure_16384/lbfv/{crs,urs}.nr` modules contain the expanded row values. An E3-varying
URS remains a future protocol change because it would require new circuit and recursive public
inputs.

The fixed seeds use SHA-256 domain-separated labels:

```text
SHA-256("interfold/lbfv/secure-16384/v1/crs")
SHA-256("interfold/lbfv/secure-16384/v1/urs")
```

These hashes are public domain-separation values, not secret material. They ensure that CRS and URS
use different deterministic streams, while the preset and version labels prevent accidental reuse
across parameter sets or circuit revisions. The resulting 32-byte values are passed to
`CommonRandomPolyVec::from_seed` by both the runtime integration and the config generator. A change
to either label, seed, parameter set, CRT representation, or row serialization requires regenerated
circuit constants and a new compatible circuit artifact set.

References:

- `https://github.com/gnosisguild/fhe.rs/blob/96981eebe18a63117fb65569b8bf5c2362c29f9a/crates/fhe/src/trlbfv/public_key_share.rs`
- `https://github.com/gnosisguild/fhe.rs/blob/96981eebe18a63117fb65569b8bf5c2362c29f9a/crates/fhe/src/trlbfv/relin_key_share.rs`
- `https://github.com/gnosisguild/fhe.rs/blob/96981eebe18a63117fb65569b8bf5c2362c29f9a/crates/fhe/src/trlbfv/aggregate.rs`

### Noir circuits

The repository contains row-level circuits:

- `circuits/bin/threshold/lbfv_pk_generation/src/main.nr` proves `(commit(sk), commit(pk_row))` for
  one `row_index`.
- `circuits/bin/threshold/rlk_generation/src/main.nr` proves
  `(commit(sk), commit(r), commit(d0), commit(d2))` for one `row_index`.
- `circuits/bin/threshold/rlk_aggregation/src/main.nr` proves the sum of `H` parties' `d0` and `d2`
  rows for one `row_index`.
- The circuits use compile-time row constants. The RLK generation circuit requires each `a` row to
  equal the corresponding l-BFV public-key CRS row.
- The `secure-16384` preset now contains generated fixed CRS, URS, and Garner rows. Unsupported
  presets retain placeholders because their RLK path is disabled.

The production C1 circuit and proof flow still use one summation-only proof per party. A separate
`lbfv_pk_generation` circuit now proves each fixed l-BFV public-key row. It reuses the C1 relation
with zero smudging noise and returns only the secret-key and row commitments. This design preserves
the C1 ABI and C1-to-C5 public-key commitment. The runtime request, response, recursive circuit, and
proof collection path remain deferred.

The three l-BFV Rust paths provide circuit computation, `Prover.toml` generation, row-selectable CLI
sample generation, and `Provable` implementations. Aggregation requires exactly the canonical `H`
shares and computes centered sums for each CRT limb. `CircuitName::RlkGeneration`,
`CircuitName::RlkAggregation`, and `CircuitName::LbfvPkGeneration` use durable discriminants 27, 28,
and 29. No l-BFV `ProofType`, request, response, or runtime event is defined yet.

## Proposed Protocol Shape

### 1. Establish one l-BFV key-generation session

The E3 workflow must create one RLK session context containing:

- `chain_id`, `interfold`, and the complete `e3_id`;
- the request-time crypto configuration ID and preset;
- the canonical committee order;
- the accepted party set used for l-BFV public-key and RLK aggregation;
- the l-BFV CRS rows for `a` and the selected URS rows for `d1`;
- the RLK ciphertext and key levels;
- a versioned domain identifier for proof signatures and durable records.

The session context must derive the accepted participant set from canonical protocol data. It must
not accept participant metadata supplied by a peer. The RLK session belongs to one E3 and must never
be reused by another E3.

### 2. Generate contributions locally

Each party must use the same secret-key contribution that the existing key path binds to its RLK
contribution. The effect runner must:

1. Build the `PublicKeyShare` with the fixed `a` CRS.
2. Build the `RelinKeyShare` with the same `a` CRS and the shared `d1` URS.
3. Retain the `RlkWitness` only in encrypted local pending-proof state.
4. Serialize the public contribution for the authenticated protocol event.
5. Create one l-BFV public-key proof request and one RLK generation proof request for every gadget
   row.

The public-key request for row `j` must carry `row_index = j`, the secret key, the row's public-key
share and error, and the quotient polynomials. The RLK request must carry the row's `d0` and `d2`
values, errors, and quotient polynomials. Both requests must carry the session's preset and
committee scope. Sensitive values must use the existing encrypted-at-rest wrapper.

### 3. Complete the l-BFV public-key row path

The runtime must add the separate proof family without changing the existing C1 proof:

- generate and collect `GADGET_DIM` `LbfvPkGeneration` proofs per party;
- key pending proofs by `(party_id, row_index)`;
- require all l-BFV public-key rows for one party to expose the same `sk_commitment`;
- require that commitment to equal the party's legacy C1 `sk_commitment`;
- preserve the existing C1-to-C2 and C1-to-C5 links;
- extend `NodeFold` and public-input validation with the l-BFV row proofs;
- add compatibility fixtures when the durable request types change.

The l-BFV public-key constructor and witness conversion must use the same concrete `a_j` vector as
the RLK circuit. The existing single-CRP BFV path must remain unchanged. The C1 enum discriminant
must not change. New proof types must be appended to durable enums.

### 4. Generate and verify RLK row proofs

The proof pipeline should treat RLK generation as a separate proof family. A generated row proof
must bind all of these values:

- the complete E3 domain;
- the party slot;
- the RLK session version;
- `row_index`;
- the l-BFV public-key and legacy C1 `sk_commitment` for the same party;
- the `r_commitment`, which must be equal in all rows from one party;
- the RLK `d0` and `d2` commitments;
- the CRS and URS version or digest.

The existing signed-proof envelope binds only `e3_id`, proof type, proof bytes, and public signals.
The new row metadata must therefore be public circuit input, part of the signed payload, or both.
The implementation must not rely on an unsigned event field for row identity.

Receiving nodes must validate the sender, committee slot, session, row, proof type, signature, and
public-input shape before they dispatch heavy ZK verification.

### 5. Aggregate the accepted contributions

RLK aggregation must use the same canonical honest set that supplies the aggregate public key. This
keeps the RLK bound to the public key accepted for the E3 and avoids an RLK based on a different
secret-key sum.

Legacy C5 cannot prove l-BFV row aggregation because its binary pins the single TrBFV `CRP`. The
l-BFV path therefore needs a separate row-indexed public-key aggregation circuit. That circuit must
reuse the C5 aggregation relation, select `LBFV_CRS_GADGET_ROWS[row_index]`, and expose the
aggregate row commitment. It must not change the C5 ABI.

For each row, the aggregator must:

1. Select exactly `H` canonical accepted party IDs.
2. Verify one l-BFV public-key proof and one RLK generation proof for each selected party.
3. Verify each proof's secret-key commitment and row identity.
4. Aggregate the selected public-key rows and run the l-BFV public-key aggregation circuit.
5. Deserialize the selected `RelinKeyShare` values.
6. Run `aggregate_relinearization_key` against the aggregate `LBFVPublicKey`.
7. Run the RLK aggregation circuit with the same `H` party order.
8. Store the operational RLK with separate session and participant metadata.

The operational RLK is derivable from the durable selected shares, aggregate public key, and proof
results. The workflow must still persist the accepted inputs and pending effects before dispatch,
because a local cache is not a recovery source.

### 6. Verify and publish the RLK result

RLK generation and aggregation proofs must be verified on chain. The implementation must add an
explicit verifier boundary that binds the proofs to the E3, crypto configuration, participant set,
row set, and aggregate RLK commitment. A generated Honk verifier alone is not sufficient because it
only verifies proof bytes and public inputs.

The recursive path must mirror the existing DKG path. Existing recursive circuits must be extended
to verify and bind the new l-BFV circuit outputs:

- `NodeFold` must verify the selected party's public-key and RLK generation proofs for every gadget
  row and expose the row commitments.
- `NodesFold` must carry those row commitments while it folds the canonical `H` party rows.
- `DkgAggregator` must verify one public-key aggregation proof and one RLK aggregation proof per
  gadget row. It must bind their expected party commitments to the folded `NodeFold` outputs.
- `DkgAggregator` must expose the aggregate l-BFV public-key and RLK commitment vectors together
  with the existing C5 commitment and DKG proof outputs.

The first publication design is to extend the existing `publishCommittee` call with the aggregate
RLK commitment and the extended `DkgAggregator` proof. This preserves the current C5 publication
boundary and keeps the RLK proof bound to the same committee and E3.

The implementation must measure proof bytes, public-input bytes, calldata size, gas, and contract
runtime before it commits to this shape. If any supported chain cannot accept the combined call, use
a separate versioned E3-scoped RLK publication method. Do not add a separate method only to avoid
the required measurement.

The selected shape must define the on-chain lifecycle stage, replay guard, verifier routing, stored
commitments, row-count bound, and failure behavior. A peer event must not create an EVM transaction
by itself. The EVM writer must accept only a locally produced durable publication intent.

### 7. Use the operational RLK

The computation effect runner must select the RLK by the complete E3 domain and crypto-config ID. It
must reject a ciphertext multiplication request when:

- the RLK is absent;
- the RLK session does not match the aggregate public key session;
- the RLK preset or levels do not match the ciphertext;
- the ciphertext does not have the component count expected before relinearization.

Threshold decryption remains the existing `trbfv` path. `trlbfv` must not be treated as a
replacement for the threshold share and smudging workflow.

## Library Adapter

The locked `fhe.rs` revision `96981eebe18a63117fb65569b8bf5c2362c29f9a` provides the approved
read-only extraction API. It returns validated `d0` and `d2` components and exposes
`ciphertext_level` and `key_level`. `RlkWitness` provides `r`, `errors_d0`, and `errors_d2`.
Interfold converts these values to CRT form and computes the exact modulus-switching and
cyclotomic-reduction quotients. The adapter rejects nonzero levels and CRS mismatches. Interfold
must validate participant identity, canonical selection, and duplicate inclusion before it calls the
aggregation API.

## Durable State

The RLK capability needs versioned durable records for:

- the session context and accepted participant set;
- each party's serialized RLK share and generation-proof bundle;
- per-row proof status and commitment results;
- the selected honest set and aggregation operation;
- the serialized operational RLK or a replayable derivation record;
- pending proof, publication, and aggregation effects;
- terminal failure and deadline state.

Private `RlkWitness` values must not enter gossip, peer history, or durable event payloads. Local
pending-proof storage must encrypt them and must delete them after proof completion or terminal
failure according to the existing secret-retention policy.

Every new durable record requires an explicit schema version and a checked-in compatibility fixture.
Stable operation IDs must include the E3 domain, session version, party slot, proof family, and row.

## Recursive Integration

The recursive proof chain will carry the RLK data as follows:

1. One party produces one public-key proof and one RLK generation proof for each `row_index`.
2. The party's `NodeFold` input contains both ordered proof sets.
3. `NodeFold` verifies each proof pair and returns the row's public-key, `d0`, and `d2` commitments.
4. `NodesFold` preserves the row commitment columns for exactly the canonical `H` party slots.
5. The aggregator produces one public-key aggregation proof and one RLK aggregation proof per row.
6. `DkgAggregator` verifies both aggregation proofs and checks their expected commitment arrays
   against the corresponding `NodesFold` rows.
7. `DkgAggregator` returns aggregate public-key and RLK commitments for the publication wrapper.

The existing C5 commitment remains part of the same DKG publication proof. The on-chain wrapper must
check the new RLK commitment vector against the E3-scoped publication input and the selected
`secure-16384` configuration. The proof must not allow a caller to omit RLK rows or reorder them.

The recursive public-input lengths, VK manifest, generated verifier anchors, and Solidity wrapper
indices must be updated as one compatibility unit. Existing DKG proofs and enum values remain
decodable, but the extended proof requires a new protocol release and artifact set.

## Preset Matrix

The initial supported matrix is:

| Preset         | Existing C0-C7 path | l-BFV PK rows | RLK generation | RLK aggregation |
| -------------- | ------------------- | ------------- | -------------- | --------------- |
| `secure-8192`  | supported           | not enabled   | not enabled    | not enabled     |
| `secure-16384` | supported           | enabled       | enabled        | enabled         |

The `insecure` preset does not support the l-BFV row path in the initial implementation. The build,
artifact, verifier, and runtime gates must fail closed when an l-BFV request targets `insecure` or
`secure-8192`.

The `secure-16384` circuits must use the same concrete l-BFV public-key CRS row data. They must not
introduce a second source of l-BFV cryptographic constants.

## Circuit and Prover Work

The pure circuit slice now includes:

- `crates/zk-helpers/src/circuits/threshold/rlk_generation.rs`;
- RLK generation circuit registration and a `Provable` implementation in `crates/zk-prover`;
- the l-BFV public-key row adapter, circuit computation, codegen, and `Provable` implementation;
- the separate `lbfv_pk_generation` Noir circuit, which preserves the legacy C1 ABI;
- derived RLK quotient bounds that include the Garner term;
- `d0` and `d2` coefficient range checks and a shared-`r` commitment;
- witness conversion tests for `SecretKey`, RNS polynomials, errors, and quotient values;
- `crates/zk-helpers/src/circuits/threshold/rlk_aggregation.rs` and its prover registration;
- exact-`H` aggregation, centered CRT sums, generation commitments, and aggregate commitments;
- recursive synchronization and drift checks for generated l-BFV CRS and URS modules;
- secure-16384 build selection and complete l-BFV row artifact cache gates;
- artifact source hashes that include shared Noir relation and commitment sources;

The remaining capability additions are:

- a row-indexed l-BFV public-key aggregation circuit that preserves the legacy C5 ABI;
- l-BFV public-key proof requests and runtime collection changes;
- generated RLK verifier artifacts for the `secure-16384` preset;
- recursive `NodeFold`, `NodesFold`, and `DkgAggregator` changes so RLK proofs reach the existing
  EVM-facing DKG verifier;
- Solidity verifier wrapper and publication route for the recursive proof;

Generated circuit configuration, parity data, verification keys, and verifier contracts must be
regenerated by the existing build tools. No generated artifact must be edited by hand.

## Testing Plan

The implementation must add tests at these levels:

- pure conversion tests for every supported preset and every RLK row;
- proof-output tests for `commit(sk)`, `commit(d0)`, and `commit(d2)`;
- C1-to-l-BFV and l-BFV-to-RLK commitment-link tests;
- duplicate, missing, reordered, wrong-row, wrong-party, and wrong-session rejection tests;
- exact-`H` aggregation tests and `H < N` tests;
- `RelinKeyShare` and `LBFVPublicKey` serialization round trips;
- depth-one multiplication and threshold decryption using the existing `trbfv` path;
- restart tests at each durable effect boundary;
- an integration scenario that encrypts, multiplies, relinearizes, and threshold-decrypts.

## Decisions Required

The following decisions are resolved:

- RLK is enabled only for `secure-16384` in the initial release.
- RLK aggregation uses the canonical honest `H` set used by public-key aggregation.
- RLK generation runs once per E3. Secret material and operational RLK artifacts are discarded after
  E3 cleanup. Durable proof and commitment history remains domain-bound and is never reused by
  another E3.
- RLK generation and aggregation proofs are verified on chain.
- The proof path extends `NodeFold`, `NodesFold`, and `DkgAggregator` instead of adding a separate
  RLK recursive circuit.
- CRS and URS values use one defined source for the l-BFV row vectors and the C1/RLK circuits.
- l-BFV public randomness uses fixed, domain-separated `secure-16384` seeds. `a_j` and `d1_j` are
  generated with `CommonRandomPolyVec::from_seed`; Garner scalars come from the level-0
  `RnsContext`.
- The implementation attempts to include RLK commitments in the existing `publishCommittee` call. A
  separate E3-scoped publication method is the fallback when measured gas or transaction size is too
  large.

The following decisions remain open. They affect later protocol layers and do not block the pure
adapter, circuit, or prover work in steps 1 through 4 of the implementation order:

1. **Combined publication limits:** Does the extended `publishCommittee` call fit every supported
   chain's gas and transaction-size limits? Measure this in step 9. Use the combined call when it
   fits. Use the versioned fallback method only when measurement shows that it does not.
2. **Wire and storage names:** Step 5 must define stable names and schema versions for the RLK
   session, accepted-party records, proof bundles, aggregation effects, and publication intents.

Do not add contract calls or publication behavior before the step 9 measurements. Do not add durable
records or wire events without the step 5 schema names and versions. Continue the implementation
order through the pure, circuit, prover, and local aggregation layers.
