# e3-evm-helpers

## Purpose

Application-facing Ethereum listeners, Interfold contract clients, retry helpers, and local nonce
coordination. The [Rust SDK](../sdk/README.md) re-exports this crate as `evm_helpers`.
Ciphernode-specific ingestion and transaction policy belong in [e3-evm](../evm/README.md).

## Map

| Location                                                                                   | Responsibility                                                   |
| ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| [`contracts.rs`](src/contracts.rs), [`events.rs`](src/events.rs)                           | Typed Interfold client and Solidity event bindings.              |
| [`event_listener.rs`](src/event_listener.rs), [`block_listener.rs`](src/block_listener.rs) | Subscription/catch-up callbacks and log progress versus headers. |
| [`nonce.rs`](src/nonce.rs), [`retry.rs`](src/retry.rs)                                     | Process-local nonce coordination and retry classification.       |
| [`threshold_queue.rs`](src/threshold_queue.rs)                                             | Ordered items released at a confirmation threshold.              |
| [`tests/integration.rs`](tests/integration.rs)                                             | Anvil listener and transaction scenarios.                        |

Listeners deliver observations to application handlers. Indexer consumers combine successful log
progress with headers before writing a watermark. Signing clients and nonce helpers handle outbound
transactions independently of listener delivery.

## Contract clients

`contracts::InterfoldContract::read_only(http_rpc_url, contract_address).await` creates a read
client. `InterfoldContract::new(http_rpc_url, private_key, contract_address).await` creates a
signing client. Import `InterfoldRead` / `InterfoldWrite` for their operations; the factory also
exposes explicitly named `create_read` and `create_write` constructors.

## Listen and catch up

`event_listener::EventListener::new(provider, filter)` accepts an Alloy provider and log filter.
Register fallible raw handlers with `add_raw_handler` or typed Solidity callbacks with
`add_event_handler`, then await `listen()`. `catch_up(from_block, to_block, chunk)` applies
historical logs. `LiveProgress` helps cursor owners coordinate subscription and successfully applied
observations; received block headers alone are not applied-log progress.

`block_listener::BlockListener` provides block callbacks, and `threshold_queue::ThresholdQueue`
supports confirmation-threshold draining. [Indexer](../indexer/README.md) is the higher-level
consumer showing catch-up/live coordination and the limits of its applied-block cursor.

`nonce::send_with_next_nonce` serializes nonce allocation in this process, not across independent
processes. Retry wrappers classify caller-selected error strings; RPC submission success is not a
successful transaction receipt.

## Tests and build prerequisites

Provide bash, solc, jq, and workspace JS dependencies; run root `pnpm fixtures:build`. `build.rs`
runs the fixture script even for a Cargo check and may rewrite JSON artifacts. Run
`cargo test --locked -p e3-evm-helpers` with Anvil available for chain tests.

Inline tests pin subscription readiness/applied ceilings, nonce reservations/expiry, and threshold
ordering. Integration tests exercise local subscriptions and refused sends. See
[AGENTS.md](AGENTS.md) for handler/cursor and fixture-source change constraints.
