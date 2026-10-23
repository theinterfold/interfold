# Interfold CLI (e3-cli)

## Purpose

The `interfold` executable manages ciphernode operation and application projects: setup,
configuration/identity, full/bootstrap startup, multi-node processes, offline state checks, Noir
artifacts, binary updates/removal, and program compilation/services. It delegates node lifecycle to
[e3-entrypoint](../entrypoint/README.md) and composition to
[e3-ciphernode-builder](../ciphernode-builder/README.md).

## Map

| Location                                                                                         | Responsibility                                                                           |
| ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| [`main.rs`](src/main.rs), [`cli.rs`](src/cli.rs)                                                 | Process entry, argument parsing, configuration, and dispatch.                            |
| [`ciphernode/`](src/ciphernode)                                                                  | Operator onboarding, bonds/tickets, and on-chain lifecycle commands.                     |
| [`start.rs`](src/start.rs), [`nodes.rs`](src/nodes.rs), [`node.rs`](src/node.rs)                 | Running-node monitoring, managed nodes, and offline maintenance commands.                |
| [`noir.rs`](src/noir.rs), [`program.rs`](src/program.rs), [`init.rs`](src/init.rs)               | Proof artifact and application-project commands.                                         |
| [`program_support.rs`](src/program_support.rs), [`openvm-compile.sh`](scripts/openvm-compile.sh) | Project runner compile/start, worker environment, cache purge, and embedded guest build. |
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
`start --bootstrap` runs discovery/history without committee/proof/transaction work; persisted
full/bootstrap directories cannot be interchanged. Use `interfold init <path>` outside an existing
project, then the [project runner workflow](../program-runner/README.md) for `compile` and
`program start`.

Some read commands route to the local daemon while a node runs; mutating/offline operations are
deliberately restricted. Reset/purge commands can destroy identity and keyshares: read their
`--help` and [entrypoint safety boundary](../entrypoint/README.md) before use.

Verbosity is WARN by default, INFO with `-v`, DEBUG with `-vv`, TRACE with `-vvv`, and ERROR with
`--quiet`. `--otel <grpc-endpoint>` enables tracing export; see
[workspace debugging](../README.md#debugging).

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
command/configuration behavior, local update/archive replacement, and telemetry redaction;
[`cli_secrets.rs`](tests/cli_secrets.rs) exercises the executable's secret/configuration handling.
The [integration harness](../../tests/integration) covers live multi-process operation separately.
See [AGENTS.md](AGENTS.md) for generated bindings and command-safety change guidance.
