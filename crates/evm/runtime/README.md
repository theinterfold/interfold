# e3-evm

## Purpose

What the CLI's chain commands share: providers built from the operator's RPC settings, the status of
an operator and the committees that hold its collateral, and readable contract errors. The node
reads and writes the chain through [e3-chain](../../ciphernode/chain/); application-side listeners
and contract clients live in [e3-evm-client](../client/README.md).

Shared contract signatures, tuple layouts, events and errors belong to
[e3-evm-contracts](../contracts/README.md). Connection and chain-setting types belong to
[e3-evm-config](../config/README.md); resolving them does not contact or authenticate a chain.

## Map

| Location                                                                     | Responsibility                                                       |
| ---------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| [`helpers.rs`](src/helpers.rs)                                               | Read-only and signing providers from a `ProviderConfig`.             |
| [`operator_status.rs`](src/operator_status.rs)                               | `fetch_operator_status` and `fetch_operator_committees`.             |
| [`log_fetcher.rs`](src/log_fetcher.rs), [`log_window.rs`](src/log_window.rs) | The event scan's `eth_getLogs` calls, with an adaptive block window. |
| [`error_decoder.rs`](src/error_decoder.rs)                                   | Contract errors decoded into readable messages.                      |

`fetch_operator_committees` (`ciphernode status`) reads the bonding registry's obligation views at
the confirmed head's hash. When a view read fails, it scans the `CommitteeObligationUpdated` events
and can save the scan for each operator (the CLI uses `committee-scans/` in the node data
directory). A later call resumes a saved scan when the provider returns the saved block hash, and
rescans from the deploy block when it returns another hash. When the provider has no block at that
height, such as a lagging node, the call returns its result and does not save it. See
[registration and bonding](../../../docs/architecture/registration-and-bonding.md) for the views.

## Tests

Run `cargo test --locked -p e3-evm`. [AGENTS.md](AGENTS.md) covers changes to the scan.
