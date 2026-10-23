# e3-trbfv

## Purpose

Threshold-BFV calculations and typed request/response payloads for distributed key generation and
threshold decryption. Actors, authenticated dealer admission, and timing belong in
[keyshare](../keyshare/README.md) and [aggregation](../aggregator/README.md).

## Map

| Location                                                                                                                                                               | Responsibility                                                                                   |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [`gen_pk_share_and_sk_sss.rs`](src/gen_pk_share_and_sk_sss.rs), [`gen_esi_sss.rs`](src/gen_esi_sss.rs)                                                                 | Randomized key/error contributions and encrypted Shamir payloads.                                |
| [`key assembly`](src/calculate_decryption_key.rs), [`share calculation`](src/calculate_decryption_share.rs), [`reconstruction`](src/calculate_threshold_decryption.rs) | Local decryption key, ciphertext shares, and final plaintext.                                    |
| [`shares/`](src/shares)                                                                                                                                                | Typed encrypted share containers and BFV transport encoding.                                     |
| [`trbfv_config.rs`](src/trbfv_config.rs), [`trbfv_request.rs`](src/trbfv_request.rs)                                                                                   | Parameter/dimension inputs and worker request/result/error envelopes.                            |
| [`request_execution.rs`](src/request_execution.rs)                                                                                                                     | Synchronous typed dispatch, RNG access, operation labels and calculation/worker failure mapping. |
| [`tests/integration.rs`](tests/integration.rs)                                                                                                                         | Isolated threshold calculation flow using generated fixtures.                                    |

Workers generate contributions from caller RNG/cipher inputs, recipients assemble their local
decryption keys, and the final calculation reconstructs from party-indexed ciphertext shares. These
functions return data/errors; actor delivery, roster admission, and retries are outside them.

## Calculation surface

Each public module exposes a typed request/response and its calculation function:

| Module/function                  | Role                                                    |
| -------------------------------- | ------------------------------------------------------- |
| `gen_pk_share_and_sk_sss`        | Public-key contribution and secret-key Shamir shares    |
| `gen_esi_sss`                    | Smudging/error-related Shamir material                  |
| `calculate_decryption_key`       | Assemble this node's decryption key from dealer shares  |
| `calculate_decryption_share`     | Produce this node's share for a ciphertext              |
| `calculate_threshold_decryption` | Reconstruct plaintext from sufficient decryption shares |

`TrBFVRequest`, `TrBFVResponse`, and `TrBFVError` provide the worker dispatch envelope.
`TrBFVFailure` retains structured threshold error/party attribution when available, in addition to a
human-readable message. The [multithread dispatcher](../multithread/src/multithread.rs) is the
production caller showing RNG/cipher/request handling.

`TrBFVRequest::execute(&rng, &cipher)` is the synchronous native execution boundary. It dispatches
to the existing calculations, locks caller-owned randomness only for randomized operations, and
recovers the same RNG state after a poisoned-lock worker panic. It creates no pool, actor, event
envelope, retry loop or persisted state. Call it from a bounded executor and reuse
already-successful randomized outputs during recovery. `operation_name()` owns the stable diagnostic
labels; `failure(payload)` preserves typed operation and structured threshold/party attribution for
both calculation and local worker errors. Event correlation/publication and resource-failure retry
policy stay with the compute runtime.

`TrBFVConfig::new(encoded_params, num_parties, threshold)` receives T, not T+1. Runtime `PartyId` is
zero-based; Shamir reconstruction coordinates are one-based at the mathematical boundary. Share
ordering must retain the corresponding party IDs. Use paired threshold/DKG metadata from
[e3-fhe-params](../fhe-params/README.md), not interchangeable parameter sets.

## Secret inputs and outputs

Share payloads in `shares` use local encrypted wrappers. Their opaque serialized bytes do not make
decoded secret material suitable for logging or ordinary snapshots. Randomized operations take
caller RNG/cipher inputs; runtime recovery reuses successful outputs rather than silently generating
different shares.

## Tests

Run `cargo test --locked -p e3-trbfv` with [test-helper prerequisites](../test-helpers/README.md).
Inline cases cover encrypted share serialization/indices and structured error extraction;
[`tests/integration.rs`](tests/integration.rs) exercises threshold computation in isolation. See
[DKG](../../docs/architecture/dkg.md) and
[threshold decryption](../../docs/architecture/threshold-decryption.md) for dimensions and proofs.
See [AGENTS.md](AGENTS.md) for mathematical/indexing change rules.
