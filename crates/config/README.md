# e3-config

## Purpose

Loads node/project configuration and resolves the paths, network profile, chain connections, and
program backend consumed by the CLI and runtime. This crate interprets configuration; runtime
adapters still check chain identity, deployed releases, and peer compatibility.

## Map

| Location                                                                                                               | Responsibility                                                                |
| ---------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [`app_config.rs`](src/app_config.rs)                                                                                   | Unscoped YAML model, named-node resolution, defaults, and resolved accessors. |
| [`load_config.rs`](src/load_config.rs), [`yaml.rs`](src/yaml.rs)                                                       | File discovery and environment substitution.                                  |
| [`paths_engine.rs`](src/paths_engine.rs)                                                                               | Project/OS/named-node locations and path overrides.                           |
| [`chain_config.rs`](src/chain_config.rs), [`rpc.rs`](src/rpc.rs), [`contract.rs`](src/contract.rs)                     | Chain ingestion settings, endpoints, and contract addresses.                  |
| [`network.rs`](src/network.rs), [`program_config.rs`](src/program_config.rs), [`node_release.rs`](src/node_release.rs) | Network identity, computation backend, and release identity.                  |

Loading proceeds from discovery through YAML/environment expansion to a scoped `AppConfig`.
Downstream startup consumes resolved settings; loading alone does not contact or authenticate a
chain, peer, or prover.

## Load a named node

`e3_config::load_config(name, found_config_file, otel)` returns a resolved `AppConfig`. The optional
strings select an explicit configuration file and telemetry override. The CLI's
[loader](../cli/src/cli.rs) passes its global `--name`, `--config`, and `--otel` arguments here. The
default CLI node name is `_default`.

Configuration path selection is explicit CLI path, then ancestor search for `interfold.config.yaml`,
then the OS default configuration directory. YAML supports environment substitution.
`UnscopedAppConfig::into_scoped` resolves a selected node; the explicit-defaults variant supports
callers that need isolated directory roots.

Use `AppConfig` accessors such as `key_file()`, `db_file()`, `log_file()`, `chains()`, `network()`,
and `program()` rather than joining paths to the process working directory.
`paths_engine::PathsEngine` distinguishes project-local `.interfold` layouts, OS defaults, named
nodes, and overrides; different path fields have different bases.

## Related APIs

- `chain_config::ChainConfig` includes RPC/finality/log-range and DA settings.
- `RPC` validates HTTP(S)/WS(S) endpoints and exposes protocol conversions.
- `NetworkProfile` resolves public/local network IDs and bootstrap peers.
- `ProgramConfig` selects OpenVM or explicit development mode; removed/unknown backend settings are
  errors rather than an implicit fallback.

For operator configuration examples use the [root README](../../README.md) and
[project template](../../templates/default/README.md).

## Tests

Run `cargo test --locked -p e3-config`. Inline module tests cover path discovery/scoping,
environment expansion, endpoint validation, network profiles, and backend rejection. They use local
fixtures rather than starting a node or contacting configured RPCs. See [AGENTS.md](AGENTS.md) for
changes that relocate identity or durable state.
