# e3-ciphernode-config

Resolves ciphernode profiles, paths, network identity, and compiled release identity for runtime
callers. The [CLI application loader](../../cli/README.md#configuration-loading) owns file
discovery, YAML/environment/CLI precedence, and program settings.
[EVM settings](../../evm/config/README.md) own chain and endpoint values. Resolving settings does
not authenticate a chain, peer, or prover; runtime adapters still enforce chain identity, deployed
releases, and peer compatibility.

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

## Network and release boundaries

Network IDs distinguish deployments, not releases. Built-in IDs are fixed; custom networks require
an explicit 32-byte ID. Protocol versions additionally scope P2P admission; node generation does not
create a separate overlay.

[`protocol-release.toml`](protocol-release.toml) is compiled into the node and read by contract
deployment tooling. The release ID uses the exact workspace version, not the package name or path.
Follow [upgrades](../../../docs/architecture/upgrades.md) before changing counters or release
identity.

## Tests

Run `cargo test --locked -p e3-ciphernode-config`. Inline tests cover node scoping/defaults, paths,
network profiles, and release identity without starting a node or contacting RPCs. Admission changes
also need affected [network tests](../../net/README.md#tests). The
[CLI executable tests](../../cli/tests/cli_configuration.rs) cover loaded-file paths and daemon
selection; [entrypoint tests](../../entrypoint/README.md#tests) cover startup and durable-state
safety. See [AGENTS.md](AGENTS.md) before changing identity or state locations.
