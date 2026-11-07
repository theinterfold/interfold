# Interfold CLI (e3-cli)

## Purpose

The `interfold` executable manages ciphernode operation and application projects: setup,
configuration/identity, full/bootstrap startup, multi-node processes, offline state checks, Noir
artifacts, binary updates/removal, and program compilation/services. It delegates node lifecycle to
[e3-entrypoint](../ciphernode/entrypoint/README.md) and composition to
[e3-ciphernode-builder](../ciphernode/builder/README.md).

## Map

| Location                                                                                         | Responsibility                                                                           |
| ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| [`main.rs`](src/main.rs), [`cli.rs`](src/cli.rs)                                                 | Process entry, argument parsing, configuration, and dispatch.                            |
| [`app_config.rs`](src/app_config.rs)                                                             | File discovery, YAML/environment/flag precedence, and application settings assembly.     |
| [`ciphernode/`](src/ciphernode)                                                                  | Operator onboarding, bonds/tickets, and on-chain lifecycle commands.                     |
| [`start.rs`](src/start.rs), [`nodes.rs`](src/nodes.rs), [`node.rs`](src/node.rs)                 | Running-node monitoring, managed nodes, and offline maintenance commands.                |
| [`noir.rs`](src/noir.rs), [`program.rs`](src/program.rs), [`init.rs`](src/init.rs)               | Proof artifact and application-project commands.                                         |
| [`program_support.rs`](src/program_support.rs), [`openvm-compile.sh`](scripts/openvm-compile.sh) | Project runner compile/start, worker environment, cache purge, and embedded guest build. |
| [`program_config.rs`](src/program_config.rs)                                                     | Program compile/start settings and backend validation.                                   |
| [`helpers/telemetry.rs`](src/helpers/telemetry.rs), [`manifest.rs`](src/manifest.rs)             | Tracing/redaction and deployed-network comparison.                                       |
| [`update.rs`](src/update.rs)                                                                     | Release selection, atomic installed-binary replacement, and binary-only removal.         |
| [`build.rs`](build.rs)                                                                           | Deployment bindings and embedded build identity.                                         |

The CLI loads a named configuration, establishes output/telemetry, and delegates effects to their
library owners. Allowed read commands can use the local daemon while a node runs. Startup returns a
handle whose health signals the CLI monitors until shutdown.

`start` watches fatal persistence/gateway errors and the first panic on the actor thread. Gateway
errors and actor panics run the shutdown barrier before an unsuccessful exit; persistence failure
flushes diagnostic logs and exits unsuccessfully. Panics on other threads remain with their owners.

## Run from source

Use the pinned [Rust toolchain](../../rust-toolchain.toml), install workspace JS dependencies, and
prepare contract artifacts and fixtures from the repository root:

```sh
pnpm evm:build
pnpm fixtures:build
cargo run --locked -p e3-cli --bin interfold -- --help
```

Builds need bash, solc, and jq; transitive [prover fixture preparation](../zk/prover/README.md) can
run Noir/pnpm commands even for a Cargo check. `build.rs` reads the tracked deployed-contract
manifest and embeds build identity; `GIT_SHA` overrides revision discovery for source builds. For
installation and operator onboarding see the [root README](../../README.md).

## Common entry points

```sh
interfold ciphernode setup
interfold start
interfold start --bootstrap
interfold config get
interfold node --help
interfold nodes --help
interfold update --help
interfold uninstall --help
```

Global `--config <path>` and `--name <node>` select configuration and a named node.
`start --bootstrap` only helps peers find each other: it answers their lookups and takes no part in
their messages, the chain, or proofs. Use `interfold init <path>` outside an existing project, then
the [project runner workflow](../program/runner/README.md) for `compile` and `program start`.

Some read commands route to the local daemon while a node runs; mutating/offline operations are
deliberately restricted. Reset/purge commands can destroy identity and keyshares: read their
`--help` and [entrypoint safety boundary](../ciphernode/entrypoint/README.md) before use.

Verbosity is WARN by default, INFO with `-v`, DEBUG with `-vv`, TRACE with `-vvv`, and ERROR with
`--quiet`. `--otel <grpc-endpoint>` enables tracing export; see
[workspace debugging](../README.md#debugging).

## Configuration loading

The application loader selects an explicit `--config` file, otherwise searches ancestors for
`interfold.config.yaml`, then falls back to the OS configuration directory. It expands YAML
environment references and applies defaults → YAML → `E3_` variables (nested keys use `__`) →
explicit CLI overrides. An absent `--otel` leaves the YAML/environment value intact.

One file supplies separate node and program settings. Only the resolved node settings reach runtime
owners; [node path resolution](../ciphernode/config/README.md) uses the loaded file's location
rather than assuming the working directory. Program compile/start settings stay with CLI tooling;
resolved worker configuration belongs to the [OpenVM host](../openvm-prover/README.md).

Legacy `program.risc0` settings load so node commands sharing the file keep working, but
compile/start refuse them. Unknown backends are rejected, not silently replaced; development mode
requires an explicit flag or setting.

## Update or remove the binary

`interfold update` (alias `upgrade`) installs the latest stable release. Use `--version dev` for the
most recently published release, stable or pre-release, or `--version <TAG>` to pin or downgrade.
These commands run before configuration handling and create no configuration, password, wallet, or
log file.

Update resolves the running binary's symlinks, stages the download beside that file, and replaces it
by rename. A running node keeps its old executable until restart. The running-node warning is best
effort and requires a readable configuration and a responding control port.

`interfold uninstall` removes only the binary. Configuration, keys, and node data stay. Release
0.19.0 and earlier have no `update` command; use the install script with `--version <TAG>` and, for
a nondefault location, `--dir <DIR>`. See the
[install/update reference](../../docs/pages/reference/cli.mdx#install-and-update) for commands and
supported platforms.

## Tests

Run `cargo test --locked -p e3-cli` with the build prerequisites above. Inline tests cover
command/configuration behavior, local update/archive replacement, and telemetry redaction. Library
configuration tests isolate environment/working-directory fixtures from binary command tests.
[`cli_configuration.rs`](tests/cli_configuration.rs) checks executable discovery, node paths,
program settings/backend rejection, and loopback daemon forwarding;
[`cli_secrets.rs`](tests/cli_secrets.rs) exercises the executable's secret/configuration handling.
The [integration harness](../../tests/integration) covers live multi-process operation separately.
See [AGENTS.md](AGENTS.md) for shared bindings and command-safety change guidance.
