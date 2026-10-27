# Rust EVM integration

These crates share contract facts, not delivery policy:

- [contracts](contracts/README.md) owns checked Solidity ABI bindings and wire types.
- [client](client/README.md) owns application contract calls, listeners, retries, and local nonces.
- [runtime](runtime/README.md) owns ciphernode ingestion, writers, and recovery adapters.
- [indexer](indexer/README.md) owns application projections and their catch-up cursor.

They are members of the root Cargo workspace, not a nested workspace. The
[Rust client integration](../../docs/architecture/rust-client-integration.md) domain describes
client/runtime boundaries and recovery limits. Consult each crate's README for build prerequisites
and verification; shared ABI consistency checks do not establish transaction or ingestion behavior.
