# Circuits

This directory holds the **Noir** implementation of Interfold’s zero-knowledge circuits: distributed
key generation and encrypted share handling (**BFV**), threshold key generation, user encryption,
and threshold decryption (**TrBFV**), together with recursive proof aggregation.

The Noir sources and tests in this tree are authoritative for constraints and public inputs.
Everything else—docs, diagrams, comments—is there to help you navigate; when in doubt, trust the
code.

```text
circuits/
├── lib/
│   └── src/
│       ├── configs/           # BFV / CRT parameter presets
│       ├── core/dkg/          # Shared logic: C0, C2–C4
│       ├── core/threshold/    # Shared logic: C1, C5, P3, C6, C7
│       └── math/              # Polynomials, SAFE, commitments, modular arithmetic
├── bin/
│   ├── chonk/                 # trBFV C3 and C6 Chonk stacks (app and kernel circuits)
│   ├── config/                # Deployment-time consistency checks on presets
│   ├── dkg/                   # DKG packages and C2 proof pipeline
│   ├── lbfv/                  # l-BFV packages: dkg/, threshold/, recursive_aggregation/
│   ├── threshold/             # TrBFV, user encryption, threshold decryption
│   └── recursive_aggregation/ # Folds and the two on-chain aggregators
└── benchmarks/
```

The shared library is the Nargo package **`lib`** (`lib/Nargo.toml`). All packages under `bin/`
depend on it; module structure is documented in [`lib/src/README.md`](lib/src/README.md).

Packages under `bin/` with a `Nargo.toml` are build targets. Directory names align with the
**`CircuitName`** enum in `crates/zk/config` via `CircuitName::source_path(profile)`. SS retains
`group()`/`dir_path()`; isolated sync DKG packages live under `bin/synchronized/` and never fall
back to SS descendants. Workspace manifests exist at each protocol's `dkg/` and `threshold/`. The
sync definition is not enabled by the live builder policy. Its
[draft proof contracts](../docs/architecture/proof-statements.md#isolated-synchronized-dkg-leaves-draft-not-admitted)
describe the missing provenance joins and deployment limits.

## Circuit package index

The tables below map **`circuits/bin/` paths** to **circuit labels** (C0–C7) and **`CircuitName`**
values used in Rust. Phases **P1–P4** are a product-level grouping of the same protocol steps; for
how phases, commitments, and circuit IDs line up end to end, read
[Cryptography](https://docs.theinterfold.com/learn/cryptography) (source:
[`docs/pages/learn/cryptography.mdx`](../docs/pages/learn/cryptography.mdx)).

**C2** is proven as a **chunk chain**: each of `sk_share_computation` (**C2a**) and
`e_sm_share_computation` (**C2b**) is the final circuit over `*_share_computation_chain` chunks and
one `*_share_computation_chain_last` chunk, which run the Shamir-share checks on consecutive
coefficient ranges and carry the commitment sponges between them. The final circuit verifies the
chunks, so its proof is the one peers and `c2ab_fold` consume, and its share commitments equal the
unchunked C2's. Gossip and threshold signing use that final proof. `c2ab_fold` verifies the final
C2a and C2b proofs and hashes each one's chunk key tree into its key hash.

**C4** is proven the same way, one CRT limb per proof: `share_decryption` (**C4a**, **C4b**) is the
final circuit over `share_decryption_limb_0`, `_1` and `_2`, which each run C4's statement for one
limb and carry the aggregate commitment sponge between them. Its commitments equal the unchunked
C4's, so C6 is unchanged. `c4ab_fold` verifies the final C4a and C4b proofs and hashes each one's
limb key tree into its key hash.

On the l-BFV path (`bin/lbfv/`), C2a and C2b are proven one chunk at a time by
`sk_share_computation_chunk` and `esm_share_computation_chunk`. `c2_chunk_batch` groups chunk
proofs, and the type-bound finalizers `sk_c2_chunk_finalize` and `esm_c2_chunk_finalize` reconstruct
the root commitments the remaining fold pipeline consumes. Gossip and threshold signing use one
terminal C2 proof per type.

### DKG (`bin/dkg/`)

| Path                                | ID        | `CircuitName`                  | Role                                                               |
| ----------------------------------- | --------- | ------------------------------ | ------------------------------------------------------------------ |
| `pk`                                | C0        | `PkBfv`                        | Commit to individual BFV public key                                |
| `sk_share_computation`              | C2a       | `SkShareComputation`           | Secret-key track Shamir shares (`y`); verifies the chunk chain     |
| `sk_share_computation_chain`        | C2a chunk | `SkShareComputationChain`      | A chunk of C2a other than the last; non-ZK                         |
| `sk_share_computation_chain_last`   | C2a chunk | `SkShareComputationChainLast`  | The last chunk of C2a                                              |
| `e_sm_share_computation`            | C2b       | `ESmShareComputation`          | Smudging-noise track Shamir shares (`y`); verifies the chunk chain |
| `e_sm_share_computation_chain`      | C2b chunk | `ESmShareComputationChain`     | A chunk of C2b other than the last; non-ZK                         |
| `e_sm_share_computation_chain_last` | C2b chunk | `ESmShareComputationChainLast` | The last chunk of C2b                                              |
| `share_encryption`                  | C3        | `ShareEncryption`              | BFV encryption of shares under recipient keys                      |
| `share_decryption`                  | C4        | `DkgShareDecryption`           | Decrypt shares; aggregate; commitments for P4; verifies the limbs  |
| `share_decryption_limb_0`           | C4 limb   | `DkgShareDecryptionLimb0`      | CRT limb 0 of C4; non-ZK                                           |
| `share_decryption_limb_1`           | C4 limb   | `DkgShareDecryptionLimb1`      | CRT limb 1 of C4; non-ZK                                           |
| `share_decryption_limb_2`           | C4 limb   | `DkgShareDecryptionLimb2`      | CRT limb 2 of C4; non-ZK                                           |

### Threshold (`bin/threshold/`)

| Path                           | ID  | `CircuitName`                | Role                                                         |
| ------------------------------ | --- | ---------------------------- | ------------------------------------------------------------ |
| `pk_generation`                | C1  | `PkGeneration`               | Threshold public-key contribution                            |
| `pk_aggregation`               | C5  | `PkAggregation`              | Aggregate contributions into threshold public key            |
| `user_data_encryption`         | P3  | —                            | trBFV user ciphertext: both legs over one `u` in one circuit |
| `share_decryption`             | C6  | `ThresholdShareDecryption`   | Partial decryption share                                     |
| `decrypted_shares_aggregation` | C7  | `DecryptedSharesAggregation` | Combine shares; CRT; decode                                  |

### Recursive aggregation (`bin/recursive_aggregation/`)

| Path                                   | `CircuitName`                      | Role                                                                              |
| -------------------------------------- | ---------------------------------- | --------------------------------------------------------------------------------- |
| `c2ab_fold`                            | `C2abFold`                         | Folds C2a and C2b and binds each C2's chunk key tree into its key hash.           |
| `c3_chonk_tube`, `c3_chonk_accumulate` | `C3ChonkTube`, `C3ChonkAccumulate` | Close one branch's C3 Chonk stack; its app and kernels are in `bin/chonk/`.       |
| `c3ab_fold`                            | `C3abFold`                         | Combines the secret key and smudging noise C3 Chonk accumulators and closes both. |
| `c4ab_fold`                            | `C4abFold`                         | Folds C4a and C4b and binds each C4's limb key tree into its key hash.            |
| `node_fold`                            | `NodeFold`                         | Folds C0, C1, `c2ab_fold`, `c3ab_fold`, and `c4ab_fold` for one node.             |
| `nodes_fold`, `nodes_fold_kernel`      | `NodesFold`, `NodesFoldKernel`     | Folds the H `node_fold` proofs in sequence, three per step.                       |
| `dkg_aggregator`                       | `DkgAggregator`                    | Verifies `nodes_fold` and C5. Its EVM proof goes to `publishCommittee`.           |
| `c6_chonk_tube`, `c6_chonk_root`       | `C6ChonkTube`, `C6ChonkRoot`       | Close one ciphertext's C6 Chonk stack; its app and kernels are in `bin/chonk/`.   |
| `decryption_aggregator`                | `DecryptionAggregator`             | Verifies `c6_chonk_root` and C7. Its EVM proof goes to `publishPlaintextOutput`.  |

For recursive trust and public-input bindings, see
[proof statements](../docs/architecture/proof-statements.md#recursive-trust-and-exported-values).

### l-BFV (`bin/lbfv/`)

The l-BFV packages mirror the trBFV groups under `bin/lbfv/{dkg,threshold,recursive_aggregation}/`.
They build only for the l-BFV presets (`insecure-lbfv` and `secure-16384`). Their `lib` dependency
is `../../../../lib`.

| Path                                                                                                | ID         | Role                                                                                        |
| --------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------- |
| `dkg/sk_share_computation_chunk`                                                                    | C2a        | Secret-key Shamir-share coefficient chunk (`y`)                                             |
| `dkg/esm_share_computation_chunk`                                                                   | C2b        | Smudging-noise coefficient chunk (`y`), with its own `\|e\| <= B` check                     |
| `dkg/share_encryption_chunked`                                                                      | C3         | `share_encryption` with the share committed as a chunk root keyed by `(party_idx, mod_idx)` |
| `dkg/share_decryption_chunked`                                                                      | C4         | Decrypt shares from the packed carriers; commit the centred aggregate                       |
| `threshold/lbfv_pk_generation`, `threshold/lbfv_pk_aggregation`                                     | C1, C5     | One l-BFV public-key row: generation per node, aggregation of `H` contributions             |
| `threshold/rlk_generation`, `threshold/rlk_aggregation`                                             | —          | One RLK gadget row: generation per node, aggregation of `H` contributions per component     |
| `threshold/user_data_encryption_chunked`                                                            | P3 wrapper | Verifies the chunked ct0 and ct1 legs, shared `u` root                                      |
| `threshold/user_data_encryption_ct0_chunked`, `threshold/user_data_encryption_ct1_chunked`          | P3         | Leg top-level circuits over `ct*_chunk_main`, `ct*_pk_ct_commit`, `ct*_eval_chunk_identity` |
| `threshold/decrypted_shares_aggregation_wide`                                                       | C7         | `decrypted_shares_aggregation` for ciphertext moduli wider than the field (secure-16384)    |
| `recursive_aggregation/c2_chunk_batch`                                                              | C2         | Verifies a fixed batch of C2 chunk proofs                                                   |
| `recursive_aggregation/sk_c2_chunk_finalize`, `recursive_aggregation/esm_c2_chunk_finalize`         | C2a, C2b   | Verify C2 chunk batches and rebuild the SK and ESM C2 public layouts                        |
| `recursive_aggregation/c2ab_chunk_fold`                                                             | C2ab       | Combines the type-bound terminal C2a and C2b proofs                                         |
| `recursive_aggregation/c3ab_fold_chunked`, `recursive_aggregation/c4ab_fold_chunked`                | C3ab, C4ab | l-BFV counterparts of `c3ab_fold` and `c4ab_fold`; `c3ab_fold_chunked` adds the VK manifest |
| `recursive_aggregation/node_fold_chunked`                                                           | —          | Per-node fold: C0, `c2ab_chunk_fold`, `c3ab_fold`, `c4ab_fold`                              |
| `recursive_aggregation/lbfv_generation_fold`, `recursive_aggregation/lbfv_generation_fold_kernel`   | —          | Fold ordered public-key and RLK generation proof pairs                                      |
| `recursive_aggregation/lbfv_aggregation_fold`, `recursive_aggregation/lbfv_aggregation_fold_kernel` | —          | Fold ordered public-key and RLK aggregation proofs                                          |
| `recursive_aggregation/node_fold_v2`                                                                | —          | Binds a `node_fold_chunked` proof to the terminal generation fold                           |
| `recursive_aggregation/nodes_fold_v2`, `recursive_aggregation/nodes_fold_v2_kernel`                 | —          | Fold exactly `H` `node_fold_v2` proofs in ascending party order                             |
| `recursive_aggregation/dkg_aggregator_v2`                                                           | —          | Verifies the V2 node fold and the aggregation fold                                          |

The l-BFV C3 app circuit `c3_chonk_app_chunked` stays in `bin/chonk/`.

### Configuration

| Path     | Role                                                   |
| -------- | ------------------------------------------------------ |
| `config` | Validates secure preset constants (CRT moduli, bounds) |

## Build and test

From the repository root:

```bash
pnpm build:circuits                # compile circuits, verification keys, artifacts
pnpm noir:lint                    # nargo fmt --check; nargo check (skipped if nargo absent)
pnpm noir:test                    # every package with Noir tests, l-BFV presets and committee matrix; nargo execute: config
```

Pin **nargo** and **bb** to the versions in `crates/zk/prover` and `versions.json`. For local work,
**`interfold noir setup`** installs a toolchain that lines up with the prover and the artifacts CI
produces. Install options and CLI flags are on the
[Noir Circuits](https://docs.theinterfold.com/build/noir-circuits) page
([`docs/pages/build/noir-circuits.mdx`](../docs/pages/build/noir-circuits.mdx)).

## Related documentation

| Topic                                                                  | Location                                                                                                                       |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Cryptographic model (PV-TBFV, phases P1–P4, circuit identifiers C0–C7) | [Cryptography](https://docs.theinterfold.com/learn/cryptography) · [source](../docs/pages/learn/cryptography.mdx)              |
| Toolchain, repository layout, `interfold noir`, compilation            | [Noir Circuits](https://docs.theinterfold.com/build/noir-circuits) · [source](../docs/pages/build/noir-circuits.mdx)           |
| Rust types (`ProofType`, `CircuitName`)                                | [`signed_proof.rs`](../crates/events/src/interfold_event/signed_proof.rs) · [`circuit.rs`](../crates/zk/config/src/circuit.rs) |
| Protocol execution (actors, events, proof ordering)                    | [DKG](../docs/architecture/dkg.md) and [threshold decryption](../docs/architecture/threshold-decryption.md)                    |
