# e3-trbfv

## Purpose

Threshold-BFV calculations and typed request/response payloads for distributed key generation and
threshold decryption. Actors, authenticated dealer admission, and timing belong in
[keyshare](../../orchestration/keyshare/README.md) and
[aggregation](../../orchestration/aggregator/README.md).

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

SS share calculation accepts exactly one ciphertext and one aggregate smudging share. The upstream
noise owner is consumed by that calculation; persisted copies must not mask another ciphertext.
Independent outputs need separately committed/dealt noise and matching proofs. Keep the
vector-shaped payloads for encoding compatibility, not as authorization to reuse noise for a batch.

The `synchronized` module carries directed PRF keys through DKG's encrypted SK-share packing. Its
native partial calculation consumes the designated set and the signed noise coefficients from the
local allocation. Incoming keys are in published H order; the native transport needs full committee
slots. The [keyshare worker](../../orchestration/keyshare/README.md) owns recovery. Synchronized
admission remains disabled.

PRF keys and packed SK shares are secret material. Key objects zeroize on drop and redact Debug, but
copying their bytes or packing them into an existing share does not make the copies safe to log or
store unencrypted. Authenticated DKG and proof provenance remain prerequisites for runtime use.
Successful randomized DKG outputs must be retained and retransmitted, not resampled on restart.

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
human-readable message. The [compute dispatcher](../../ciphernode/multithread/src/multithread.rs) is
the production caller showing RNG/cipher/request handling.

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
[e3-fhe-params](../params/README.md), not interchangeable parameter sets.

## Secret inputs and outputs

Share payloads in `shares` use local encrypted wrappers. Their opaque serialized bytes do not make
decoded secret material suitable for logging or ordinary snapshots. Randomized operations take
caller RNG/cipher inputs; runtime recovery reuses successful outputs rather than silently generating
different shares.

## Tests

Run `cargo test --locked -p e3-trbfv`; no EVM/prover fixture setup is required. Inline cases cover
encrypted share serialization/indices and structured error extraction;
[`tests/integration.rs`](tests/integration.rs) exercises threshold computation in isolation, using
private share fixtures under `tests/common` and shared
[ballots](../../testing/bfv-support/README.md). See [DKG](../../../docs/architecture/dkg.md) and
[threshold decryption](../../../docs/architecture/threshold-decryption.md) for dimensions and
proofs. See [AGENTS.md](AGENTS.md) for mathematical/indexing change rules.

[`tests/synchronized.rs`](tests/synchronized.rs) checks canonical key packing and real encrypted
SK-share transport from non-prefix dealers to every full-committee recipient. These are native DKG
transport tests, not synchronized ciphertext-decryption, C6/C7, or complete proof-chain coverage.

`tests/synchronized_dkg.rs` independently generates native encrypted shares and prepares the actual
sync C0–C4 inputs through `e3-zk-witness`. Its default test needs no proving tools. With pinned
Nargo/BB, `pnpm rust:test:sync-dkg:proofs` additionally proves leaves and draft dealer/recipient
joins and isolated C5/publication through the production prover API, checks native commitment
agreement and rejects malformed witnesses/public substitutions and independently verified but
mismatched children. It includes H `[0,2]`, self and outside-H recipients, nonzero-CRT key
substitution and a uniformly substituted valid descendant VK tree. Its publication scenario also
verifies the final EVM proof through a freshly generated Solidity verifier and the draft
context-bound wrapper, using native expected anchors. It needs pnpm/workspace dependencies and solc
0.8.28 as well as pinned Nargo/BB. `pnpm rust:test:sync-dkg:publication` selects that scenario
alone; it creates only temporary proof and verifier artifacts. Ordinary contract tests skip its
missing fixture rather than substituting mocks. Canonical context/roster authority, registry
publication/attestations and persistent actor restart remain outside this suite; see
[proof contracts](../../../docs/architecture/proof-statements.md#draft-synchronized-provenance-joins-not-admitted).

`pnpm test:sync-decryption:contract` runs that suite for one Hardhat request, then publishes the
real DKG proof with both selected recipients' signatures and checks the real C6/C7 aggregate against
the resulting registry state. It requires the same pinned tools. The test uses generated Honk
verifiers in a temporary directory and a finalized-committee harness; it does not install artifacts
or enable synchronized requests.
