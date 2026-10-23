# e3-sdk

## Purpose

Feature-gated Rust facade for application clients. It re-exports the existing capability crates
rather than wrapping them with another implementation. The JavaScript SDK is a separate
[workspace package](../../packages/interfold-sdk/README.md).

## Map

[`src/lib.rs`](src/lib.rs) is intentionally only a feature-gated export surface.
[`Cargo.toml`](Cargo.toml) maps features to optional owner crates. Calls through an alias go
directly to that owner; there is no SDK actor, configuration loader, or second client
implementation.

## Select capabilities

| Feature          | Public module aliases                                          |
| ---------------- | -------------------------------------------------------------- |
| `bfv`            | `bfv_client` (`e3-bfv-client`), `bfv_params` (`e3-fhe-params`) |
| `evm`            | `evm_helpers` (`e3-evm-helpers`)                               |
| `indexer`        | `indexer` (`e3-indexer`)                                       |
| `full` (default) | All of the above                                               |

For a BFV-only sibling crate in this checkout, select the local package explicitly:

```toml
[dependencies]
e3-sdk = { path = "../sdk", default-features = false, features = ["bfv"] }
```

The root `workspace.dependencies.e3-sdk` currently enables defaults, so an inherited
`workspace = true` dependency does not provide that minimal selection. For external projects use the
dependency source pinned by their generated template instead of assuming these unpublished workspace
packages have a crates.io release.

```rust
use e3_sdk::bfv_client::{decode_bytes_to_vec_u64, encode_vec_u64_to_bytes};

let bytes = encode_vec_u64_to_bytes(&[7_u64]);
assert_eq!(decode_bytes_to_vec_u64(&bytes).unwrap(), vec![7]);
```

See [BFV usage](../bfv-client/README.md), [contract/listener helpers](../evm-helpers/README.md), and
[indexing](../indexer/README.md) for their API contracts and examples.

## Tests and feature checks

Minimal checks: `cargo check --locked -p e3-sdk --no-default-features`, or add `--features bfv`.
Default/EVM/indexer builds require the [Solidity fixture prerequisites](../evm-helpers/README.md)
even for Cargo checks; BFV-only builds avoid those optional adapters.

The facade has no independent behavioral tests. `cargo check --locked -p e3-sdk` checks the default
exports; BFV/listener/indexer behavior is tested in the linked owner crates above. See
[AGENTS.md](AGENTS.md) for feature/default and re-export changes.
