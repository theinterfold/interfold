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
│   └── recursive_aggregation/
│       ├── fold/
│       └── wrapper/
│           ├── dkg/
│           └── threshold/
└── benchmarks/
```

The shared library is the Nargo package **`lib`** (`lib/Nargo.toml`). All packages under `bin/`
depend on it; module structure is documented in [`lib/src/README.md`](lib/src/README.md).

Packages under `bin/` with a `Nargo.toml` are build targets. Directory names align with the
**`CircuitName`** enum in `crates/events` via `CircuitName::group()` and `CircuitName::dir_path()`.
Workspace manifests also exist at `dkg/` and `threshold/` for grouped builds.

## Circuit package index

The tables below map **`circuits/bin/` paths** to **circuit labels** (C0–C7) and **`CircuitName`**
values used in Rust. Phases **P1–P4** are a product-level grouping of the same protocol steps; for
how phases, commitments, and circuit IDs line up end to end, read
[Cryptography](https://docs.theinterfold.com/cryptography) (source:
[`docs/pages/cryptography.mdx`](../docs/pages/cryptography.mdx)).

**C2** uses **chunked** recursive proofs: the `sk_share_computation_chunk` (**C2a**) and
`esm_share_computation_chunk` (**C2b**) leaves prove one coefficient chunk of the Shamir-share
computation each. Chunk proofs are grouped by `c2_chunk_batch`, verified in the type-bound terminal
`sk_c2_chunk_finalize` / `esm_c2_chunk_finalize`, and the two terminals are folded by
`c2ab_chunk_fold`. Gossip and threshold signing use the terminal recursive proof; folding and
aggregation consume it.

### DKG (`bin/dkg/`)

| Path                          | ID  | `CircuitName`              | Role                                                |
| ----------------------------- | --- | -------------------------- | --------------------------------------------------- |
| `pk`                          | C0  | `PkBfv`                    | Commit to individual BFV public key                 |
| `sk_share_computation_chunk`  | C2a | `SkShareComputationChunk`  | Secret-key track Shamir shares, one chunk (`y`)     |
| `esm_share_computation_chunk` | C2b | `ESmShareComputationChunk` | Smudging-noise track Shamir shares, one chunk (`y`) |
| `share_encryption`            | C3  | `ShareEncryption`          | BFV encryption of shares under recipient keys       |
| `share_decryption`            | C4  | `DkgShareDecryption`       | Decrypt shares; aggregate; commitments for P4       |

### Threshold (`bin/threshold/`)

| Path                           | ID         | `CircuitName`                | Role                                              |
| ------------------------------ | ---------- | ---------------------------- | ------------------------------------------------- |
| `pk_generation`                | C1         | `PkGeneration`               | Threshold public-key contribution                 |
| `pk_aggregation`               | C5         | `PkAggregation`              | Aggregate contributions into threshold public key |
| `user_data_encryption_ct0`     | P3         | —                            | User ciphertext (first leg)                       |
| `user_data_encryption_ct1`     | P3         | —                            | User ciphertext (second leg)                      |
| `user_data_encryption`         | P3 wrapper | —                            | Wrapper: ct0, ct1, shared randomness              |
| `share_decryption`             | C6         | `ThresholdShareDecryption`   | Partial decryption share                          |
| `decrypted_shares_aggregation` | C7         | `DecryptedSharesAggregation` | Combine shares; CRT; decode                       |

### Recursive aggregation (`bin/recursive_aggregation/`)

| Path                                             | `CircuitName`        | Role                                                                              |
| ------------------------------------------------ | -------------------- | --------------------------------------------------------------------------------- |
| `c2_chunk_batch`                                 | `C2ChunkBatch`       | Groups ordered C2 chunk proofs into a fixed-size recursive batch                  |
| `sk_c2_chunk_finalize`                           | `SkC2ChunkFinalize`  | Type-bound terminal: verifies all SK chunk batches, reconstructs root commitments |
| `esm_c2_chunk_finalize`                          | `ESmC2ChunkFinalize` | Type-bound terminal: ESM track equivalent of `sk_c2_chunk_finalize`               |
| `c2ab_chunk_fold`                                | `C2abChunkFold`      | Fold the two C2 terminal proofs (SK + ESM)                                        |
| `c3_fold`, `c3_fold_kernel`                      | —                    | C3 recursive folding / kernel                                                     |
| `c6_fold`, `c6_fold_kernel`                      | —                    | C6 recursive folding / kernel                                                     |
| `c3ab_fold`, `c4ab_fold`                         | —                    | Recursive folds for the C3/C4 and C2-to-C4 chains                                 |
| `node_fold` / `nodes_fold` (`nodes_fold_kernel`) | —                    | Fold a node's `node_fold` chain (`H`-deep) before `dkg_aggregator`                |
| `dkg_aggregator`                                 | —                    | Top-level DKG on-chain Honk verifier                                              |
| `decryption_aggregator`                          | —                    | Top-level decryption on-chain Honk verifier                                       |

For the recursive aggregation flow, see
[`agent/flow-trace/04_DKG_AND_COMPUTATION.md`](../agent/flow-trace/04_DKG_AND_COMPUTATION.md).

### Configuration

| Path     | Role                                                                    |
| -------- | ----------------------------------------------------------------------- |
| `config` | Validates secure preset constants (CRT moduli, bounds, parity matrices) |

## Build and test

From the repository root:

```bash
pnpm tsx scripts/build-circuits.ts   # compile circuits, verification keys, artifacts
./scripts/lint-circuits.sh           # nargo fmt --check; nargo check (skipped if nargo absent)
./scripts/test-circuits.sh           # unit tests in circuits/lib
```

Pin **nargo** and **bb** to the versions in `crates/zk-prover` and `versions.json`. For local work,
**`interfold noir setup`** installs a toolchain that lines up with the prover and the artifacts CI
produces. Install options and CLI flags are on the
[Noir Circuits](https://docs.theinterfold.com/noir-circuits) page
([`docs/pages/noir-circuits.mdx`](../docs/pages/noir-circuits.mdx)).

## Related documentation

| Topic                                                                  | Location                                                                                                                                |
| ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Cryptographic model (PV-TBFV, phases P1–P4, circuit identifiers C0–C7) | [Cryptography](https://docs.theinterfold.com/cryptography) · [source](../docs/pages/cryptography.mdx)                                   |
| Toolchain, repository layout, `interfold noir`, compilation            | [Noir Circuits](https://docs.theinterfold.com/noir-circuits) · [source](../docs/pages/noir-circuits.mdx)                                |
| Rust types (`ProofType`, `CircuitName`)                                | [`signed_proof.rs`](../crates/events/src/interfold_event/signed_proof.rs) · [`proof.rs`](../crates/events/src/interfold_event/proof.rs) |
| Protocol execution (actors, events, proof ordering)                    | [`agent/flow-trace/04_DKG_AND_COMPUTATION.md`](../agent/flow-trace/04_DKG_AND_COMPUTATION.md)                                           |
