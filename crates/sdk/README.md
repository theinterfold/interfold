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
| `evm`            | `evm` (`e3-evm-client`); deprecated `evm_helpers` alias        |
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

See [BFV usage](../bfv-client/README.md), [contract/listener helpers](../evm/client/README.md), and
[indexing](../evm/indexer/README.md) for their API contracts and examples.

## EVM dev-release migration

The application package is now `e3-evm-client` (`e3_evm_client` in Rust), not `e3-evm-helpers`.
Update direct Cargo dependencies and imports together. There is no legacy helper package; the node
runtime remains the separate `e3-evm` package.

With SDK feature `evm`, prefer:

```rust
use e3_sdk::evm::contracts::{InterfoldContract, InterfoldRead};
```

`e3_sdk::evm_helpers` is a deprecated re-export of exactly the same client, retained through 0.20
and scheduled for removal in 0.21. It is not a second implementation and does not preserve the old
raw enum API; follow the [wire-type migration](../evm/client/README.md#contract-clients).

Pin SDK, indexer, client, and any direct contract-binding Git dependencies to the same new dev tag
or commit. CRISP uses both the SDK alias and the former direct helper package, so updating only its
SDK pin is insufficient: migrate that direct dependency/import and run its application scenarios
before adopting the dev release. No CRISP changes are made in this repository.

The dependency order is bindings → client → indexer → SDK; the node runtime independently consumes
bindings. The current [release workflow](../../RELEASING.md) does not publish Rust workspace crates
to crates.io. This migration does not publish a package or choose a release tag.

## Tests and feature checks

Minimal checks: `cargo check --locked -p e3-sdk --no-default-features`, or add `--features bfv`.
Default/EVM/indexer builds require the [Solidity fixture prerequisites](../evm/client/README.md)
even for Cargo checks; BFV-only builds avoid those optional adapters.

`tests/exports.rs` checks capability exports and the preferred/legacy EVM type identity, not owner
behavior. Run `cargo test --locked -p e3-sdk --test exports` for defaults, or add
`--no-default-features` with no feature / `--features bfv` / `--features evm` / `--features indexer`
to check each selection, as CI does. BFV/listener/indexer behavior is tested in the linked owner
crates above. See [AGENTS.md](AGENTS.md) for feature/default and re-export changes.
