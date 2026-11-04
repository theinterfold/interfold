# e3-ciphernode-config

Resolves ciphernode profiles and paths for runtime callers. The
[CLI application loader](../../cli/README.md#configuration-loading) owns file discovery,
YAML/environment/CLI precedence, and program settings. [EVM settings](../../evm/config/README.md)
own chain and endpoint values; [network/release configuration](../../config/README.md) owns network
identity and bootstrap policy. Resolving settings does not authenticate a chain, peer, or prover.

## Resolve a named node

`UnscopedNodeConfig::into_scoped(name)` resolves a selected node using OS directory defaults;
`into_scoped_with_defaults` supports isolated directory roots. The CLI supplies merged settings and
loaded-file metadata before scoping. Its default node name is `_default`.

Use `NodeConfig` accessors rather than joining paths to the process working directory.
`paths_engine::PathsEngine` distinguishes project-local `.interfold` layouts, OS defaults, named
nodes, and overrides. Relative key paths use the configuration directory; database and log paths use
the data directory. A path change can select another identity or durable store.

For operator examples use the
[configuration reference](../../../docs/pages/reference/configuration.mdx) and
[project template](../../../templates/default/README.md).

## Tests

Run `cargo test --locked -p e3-ciphernode-config`. Inline tests cover node scoping/defaults and path
derivation without starting a node or contacting RPCs. The
[CLI executable tests](../../cli/tests/cli_configuration.rs) cover loaded-file paths and daemon
selection; [entrypoint tests](../../entrypoint/README.md#tests) cover startup and durable-state
safety. See [AGENTS.md](AGENTS.md) before changing identity or state locations.
