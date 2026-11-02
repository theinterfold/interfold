# e3-evm-config

Owns EVM connection and chain settings: RPC URLs/authentication, configured contract endpoints,
data-availability reader selection, and ingestion defaults/validation. The
[CLI loader](../../cli/README.md#configuration-loading) owns file discovery and precedence;
[e3-evm](../runtime/README.md) owns provider connections, chain/release checks, ingestion, and
transaction recovery. ABI bindings remain in [e3-evm-contracts](../contracts/README.md).

Resolving settings does not authenticate a chain or a deployed contract. Loopback RPC URLs may proxy
public chains: they do not disable confirmations or shorten polling intervals. Historical reads
without deployment blocks retain their existing non-local-endpoint rejection.

Import the settings directly from this crate. Node configuration can contain these values without
depending on the EVM runtime. This crate does not load files, resolve node profiles, or connect
providers.

## Tests

Run `cargo test --locked -p e3-evm-config`. Inline tests cover endpoint/locality handling and
production-safe ingestion defaults and overrides. CLI/configuration tests cover shared-file
deserialization; the runtime's local-chain tests cover provider use. None of these establish reorg
rollback or exactly-once transaction delivery.
