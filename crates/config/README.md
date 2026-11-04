# e3-config

## Purpose

Resolves ciphernode profiles, paths, and network identity for runtime callers. Chain settings are
owned by [e3-evm-config](../evm/config/README.md). The
[CLI application loader](../cli/README.md#configuration-loading) owns file discovery,
YAML/environment/CLI precedence, and program settings. Runtime adapters still check chain identity,
deployed releases, and peer compatibility.

## Map

| Location                                                                 | Responsibility                                                          |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| [`app_config.rs`](src/app_config.rs)                                     | Node settings, named-node resolution, defaults, and resolved accessors. |
| [`paths_engine.rs`](src/paths_engine.rs)                                 | Project/OS/named-node locations and path overrides.                     |
| [`network.rs`](src/network.rs), [`node_release.rs`](src/node_release.rs) | Network and release identity.                                           |

Downstream startup consumes a scoped `AppConfig`; resolving settings alone does not contact or
authenticate a chain, peer, or prover.

## Resolve a named node

`UnscopedAppConfig::into_scoped(name)` resolves a selected node using OS directory defaults;
`into_scoped_with_defaults` supports callers that need isolated directory roots. The CLI supplies
merged settings and loaded-file metadata before scoping. Its default node name is `_default`.

Use `AppConfig` accessors such as `key_file()`, `db_file()`, `log_file()`, `chains()`, and
`network()` rather than joining paths to the process working directory. `paths_engine::PathsEngine`
distinguishes project-local `.interfold` layouts, OS defaults, named nodes, and overrides; different
path fields have different bases.

## Related APIs

- [EVM settings](../evm/config/README.md) supply chain, endpoint, authentication, and
  contract-address values used by node profiles.
- `NetworkProfile` resolves public/local network IDs and bootstrap peers.

For operator configuration examples use the [root README](../../README.md) and
[project template](../../templates/default/README.md).

## Tests

Run `cargo test --locked -p e3-config`. Inline module tests cover node scoping/defaults, path
derivation, network profiles, and release identity. They use local fixtures rather than starting a
node or contacting configured RPCs. See [AGENTS.md](AGENTS.md) for changes that relocate identity or
durable state.
