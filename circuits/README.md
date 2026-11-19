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
│   ├── config/                # Deployment-time consistency checks on presets
│   ├── dkg/                   # DKG packages and C2 proof pipeline
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

| Path                           | ID  | `CircuitName`                | Role                                              |
| ------------------------------ | --- | ---------------------------- | ------------------------------------------------- |
| `pk_generation`                | C1  | `PkGeneration`               | Threshold public-key contribution                 |
| `pk_aggregation`               | C5  | `PkAggregation`              | Aggregate contributions into threshold public key |
| `user_data_encryption`         | P3  | —                            | User ciphertext: both legs over one `u`           |
| `share_decryption`             | C6  | `ThresholdShareDecryption`   | Partial decryption share                          |
| `decrypted_shares_aggregation` | C7  | `DecryptedSharesAggregation` | Combine shares; CRT; decode                       |

### Recursive aggregation (`bin/recursive_aggregation/`)

| Path                              | `CircuitName`                  | Role                                                                                   |
| --------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------- |
| `c2ab_fold`                       | `C2abFold`                     | Folds C2a and C2b and binds each C2's chunk key tree into its key hash.                |
| `c3_fold`, `c3_fold_kernel`       | `C3Fold`, `C3FoldKernel`       | Folds the C3 proofs of one branch in sequence. The kernel makes the first accumulator. |
| `c3ab_fold`                       | `C3abFold`                     | Folds the final secret key and smudging noise C3 folds.                                |
| `c4ab_fold`                       | `C4abFold`                     | Folds C4a and C4b.                                                                     |
| `node_fold`                       | `NodeFold`                     | Folds C0, C1, `c2ab_fold`, `c3ab_fold`, and `c4ab_fold` for one node.                  |
| `nodes_fold`, `nodes_fold_kernel` | `NodesFold`, `NodesFoldKernel` | Folds the H `node_fold` proofs in sequence.                                            |
| `dkg_aggregator`                  | `DkgAggregator`                | Verifies `nodes_fold` and C5. Its EVM proof goes to `publishCommittee`.                |
| `c6_chonk_*`                      | `C6Chonk*`                     | Verifies the T + 1 C6 proofs of one ciphertext in one Chonk stack and closes it.       |
| `decryption_aggregator`           | `DecryptionAggregator`         | Verifies `c6_chonk_root` and C7. Its EVM proof goes to `publishPlaintextOutput`.       |

For recursive trust and public-input bindings, see
[proof statements](../docs/architecture/proof-statements.md#recursive-trust-and-exported-values).

### Configuration

| Path     | Role                                                   |
| -------- | ------------------------------------------------------ |
| `config` | Validates secure preset constants (CRT moduli, bounds) |

## Build and test

From the repository root:

```bash
pnpm build:circuits                # compile circuits, verification keys, artifacts
pnpm noir:lint                    # nargo fmt --check; nargo check (skipped if nargo absent)
pnpm noir:test                    # nargo test: lib, decryption_aggregator, dkg_aggregator and node_fold (3 preset/committee pairs); nargo execute: config
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
