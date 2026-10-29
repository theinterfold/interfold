# e3-sdk

## Purpose

Feature-gated Rust facade for application clients. The JavaScript SDK is a separate
[workspace package](../../packages/interfold-sdk/README.md).

## Select capabilities

| Feature          | Public module aliases                                          |
| ---------------- | -------------------------------------------------------------- |
| `bfv`            | `bfv_client` (`e3-bfv-client`), `bfv_params` (`e3-fhe-params`) |
| `evm`            | `evm` (`e3-evm-client`)                                        |
| `indexer`        | `indexer` (`e3-indexer`)                                       |
| `full` (default) | All of the above                                               |

`evm_helpers` is a deprecated alias of `evm`, scheduled for removal in 0.21.

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

See [BFV usage](../bfv-client/README.md), [EVM clients](../evm/client/README.md), and
[indexing](../evm/indexer/README.md) for their API contracts and examples.

## Tests and feature checks

Run `cargo test --locked -p e3-sdk --test exports` for default exports. Add `--no-default-features`
to check the minimal facade, then `--features bfv`, `--features evm`, or `--features indexer` to
check individual capabilities.

EVM/indexer builds require the [Solidity fixture prerequisites](../evm/client/README.md), even for
Cargo checks; minimal and BFV-only builds do not. Behavior is tested in the owner crates linked
above. See [AGENTS.md](AGENTS.md) for feature and re-export changes.
