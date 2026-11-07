# e3-trbfv

## Purpose

Threshold-BFV calculations and typed request/response payloads for distributed key generation and
threshold decryption. Dealer admission and timing belong to the [protocol machine](../../protocol/);
the node runs these calculations in its [jobs](../../ciphernode/jobs/).

## Map

| Location                                                                                                                                                               | Responsibility                                                    |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| [`gen_pk_share_and_sk_sss.rs`](src/gen_pk_share_and_sk_sss.rs), [`gen_esi_sss.rs`](src/gen_esi_sss.rs)                                                                 | Randomized key/error contributions and encrypted Shamir payloads. |
| [`key assembly`](src/calculate_decryption_key.rs), [`share calculation`](src/calculate_decryption_share.rs), [`reconstruction`](src/calculate_threshold_decryption.rs) | Local decryption key, ciphertext shares, and final plaintext.     |
| [`shares/`](src/shares)                                                                                                                                                | Typed encrypted share containers and BFV transport encoding.      |
| [`trbfv_config.rs`](src/trbfv_config.rs)                                                                                                                               | Parameter and dimension inputs.                                   |
| [`tests/integration.rs`](tests/integration.rs)                                                                                                                         | Isolated threshold calculation flow using generated fixtures.     |

Workers generate contributions from caller RNG/cipher inputs, recipients assemble their local
decryption keys, and the final calculation reconstructs from party-indexed ciphertext shares. These
functions return data/errors; delivery, roster admission, and retries are outside them.

## Calculation surface

Each public module exposes a typed request/response and its calculation function:

| Module/function                  | Role                                                    |
| -------------------------------- | ------------------------------------------------------- |
| `gen_pk_share_and_sk_sss`        | Public-key contribution and secret-key Shamir shares    |
| `gen_esi_sss`                    | Smudging/error-related Shamir material                  |
| `calculate_decryption_key`       | Assemble this node's decryption key from dealer shares  |
| `calculate_decryption_share`     | Produce this node's share for a ciphertext              |
| `calculate_threshold_decryption` | Reconstruct plaintext from sufficient decryption shares |

`TrBFVConfig::new(encoded_params, num_parties, threshold)` receives T, not T+1. Runtime `PartyId` is
zero-based; Shamir reconstruction coordinates are one-based at the mathematical boundary. Share
ordering must retain the corresponding party IDs. Use paired threshold/DKG metadata from
[e3-fhe-params](../params/README.md), not interchangeable parameter sets.

## Secret inputs and outputs

Share payloads in `shares` use local encrypted wrappers. Their opaque serialized bytes do not make
decoded secret material suitable for logging or ordinary snapshots. Randomized operations take
caller RNG/cipher inputs; the node journals each randomized output before it uses it, so a restart
reuses it rather than generating different shares.

## Tests

Run `cargo test --locked -p e3-trbfv`; no EVM/prover fixture setup is required. Inline cases cover
encrypted share serialization and indices; [`tests/integration.rs`](tests/integration.rs) exercises
threshold computation in isolation, using private share fixtures under `tests/common` and shared
[ballots](../../testing/bfv-support/README.md). See [DKG](../../../docs/architecture/dkg.md) and
[threshold decryption](../../../docs/architecture/threshold-decryption.md) for dimensions and
proofs. See [AGENTS.md](AGENTS.md) for mathematical/indexing change rules.
