# Rust client integration

Owners: [Rust SDK](../../crates/sdk/), [BFV client](../../crates/bfv-client/),
[indexer](../../crates/indexer/), and [EVM helpers](../../crates/evm-helpers/). The
[TypeScript SDK](../pages/build/sdk.mdx) is a separate client. Neither client replaces the
application contract's input checks or the protocol's output verification.

## Client boundaries

`e3-sdk` re-exports `bfv_client` and `bfv_params` through feature `bfv`, `evm_helpers` through
`evm`, and `indexer` through `indexer`. The default `full` feature enables all three. These are
re-exports, not a second implementation of encryption or chain tracking.

`bfv_encrypt` returns ciphertext bytes. `bfv_verifiable_encrypt` also returns witness JSON; it does
not itself produce or verify a proof. Verifiable encryption accepts supported threshold parameter
tuples. Commitment helpers compute/check key and ciphertext commitments using the matching
parameters. Treat downloaded key bytes as untrusted until they reproduce the proven request-time
commitment; [DKG](dkg.md) owns that transport boundary. [Proof statements](proof-statements.md) owns
the encryption relation and packing constraints.

The [WASM exports](../../crates/wasm/src/) wrap these BFV helpers for browser and Node clients. The
[SDK guide](../pages/build/sdk.mdx) describes browser integration. Building a wrapper or generating
witness JSON is not evidence that the resulting proof was accepted on chain.

## Catch-up and transactions

`InterfoldIndexer` stores E3 projections through a caller-supplied `DataStore`. Historical catch-up
and cursor writes require `configure_backfill`; the default head-only consumer does not acquire
replay side effects. Opted-in raw handlers must tolerate duplicates and return failed writes as
errors. The cursor is a best-effort raw-handler watermark, not an atomic completion ledger for typed
projections, Ethereum finality, or reorg rollback.

The [indexer contract](../../crates/indexer/README.md) owns the two catch-up passes, live-progress
qualification, cursor-write limits, and callback ownership. Application recovery must check its own
projection, not infer it from block height. CRISP's request/key convergence and input selection
belong to [encrypted computation](encrypted-computation.md).

EVM helpers provide bindings, log/block listeners, and transaction submission. Their
`send_with_next_nonce` serializes nonce selection and broadcast for a chain/account within one
process; receipt waiting happens after the lock is released. Another process sharing the key is
visible only through the RPC pending count. This is not a distributed nonce coordinator or durable
transaction outbox. [Persistence](persistence-and-replay.md) describes node writer recovery limits.

## Evidence

Use `cargo test -p e3-bfv-client`, `cargo test -p e3-indexer`, and `cargo test -p e3-evm-helpers`
for changed owner boundaries. A reconnect change also needs an affected consumer scenario. Local
helper tests do not establish all-handler crash consistency, browser/Node build parity, or
acceptance by a deployed application verifier.
