# Rust components

The root [Cargo workspace](../Cargo.toml) contains the ciphernode runtime, application libraries,
and artifact tooling. Component READMEs orient users and agents with purpose, source maps,
runtime/API boundaries, usage, and tests. Their `AGENTS.md` files describe how to change the code:
conventions, invariants, hazards, and change-specific verification. Cross-component protocol rules
live in the [architecture document index](../docs/architecture/AGENTS.md).

## Setup and checks

Use [rust-toolchain.toml](../rust-toolchain.toml) as the authoritative root toolchain/target pin.
The [root README](../README.md) covers installation and operator setup; root
[package scripts](../package.json) own shared build/test preparation.

```sh
pnpm install --frozen-lockfile
pnpm evm:build
pnpm fixtures:build
cargo test --locked -p e3-committee
```

EVM-facing crates require bash, solc, and jq even for checks because their build scripts compile
Solidity fixtures. Chain tests need Foundry's Anvil. Use the repository's
[CI setup](../.github/workflows) for tool installation/pins rather than historic version examples.
[e3-zk-prover](zk/prover/README.md) builds can also invoke pnpm/Noir and rewrite fixtures; its
compile-only flag does not establish proof readiness. Choose the smallest applicable crate target;
root `pnpm rust:test`, `pnpm rust:test:proofs`, and `pnpm rust:test:slashing` cover different
scopes, with additional prerequisites documented by their owners.

The [OpenVM worker](openvm-prover/README.md) is an independent excluded workspace with its own
pinned tools. [e3-program-runner](program-runner/README.md) supplies shared development/OpenVM
modes. Each generated project's separate `runner/` binary links its own program and calls that
library; the CLI owns compile/start orchestration.

CPU admission/cancellation primitives live in [e3-task-pool](task-pool/README.md). The ciphernode
[compute dispatcher](multithread/README.md) owns replay/retry policy and prover-memory sizing rather
than making those policies part of the executor.

## Find a component

| Capability                      | Entry points                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Operator commands and assembly  | [CLI](cli/README.md), [entrypoint](entrypoint/README.md), [ciphernode builder](ciphernode-builder/README.md), [configuration](config/README.md)                                                                                                                                                                                                            |
| Events and state                | [event types/pipeline](events/README.md), [runtime assembly](event-system/README.md), [storage](data/README.md), [sync/replay](sync/README.md), [request routing](request/README.md)                                                                                                                                                                       |
| Participation and key lifecycle | [sortition](sortition/Readme.md), [keyshare](keyshare/README.md), [aggregation](aggregator/README.md), [slashing](slashing/README.md)                                                                                                                                                                                                                      |
| Runtime adapters                | [EVM](evm/README.md), [network](net/README.md), [shared compute workers](multithread/README.md), [task admission](task-pool/README.md), [FHE](fhe/README.md), [local crypto](crypto/README.md)                                                                                                                                                             |
| Application computation         | [Secure Process/provider](compute-provider/Readme.md), [OpenVM host](openvm-host/README.md), [guest/journal types](openvm-types/README.md), [program HTTP server](program-server/README.md), [DA clients](data-availability/README.md)                                                                                                                     |
| Client libraries                | [Rust SDK](sdk/README.md), [BFV client](bfv-client/README.md), [WASM](wasm/README.md), [EVM helpers](evm-helpers/README.md), [indexer](indexer/README.md)                                                                                                                                                                                                  |
| Parameters, math, and proofs    | [committee](committee/README.md), [committee hashes](committee-hash/README.md), [FHE presets](fhe-params/README.md), [TrBFV](trbfv/README.md), [SAFE](safe/README.md), [polynomials](polynomial/README.md), [parity matrices](parity-matrix/README.md), [ZK config](zk/config/README.md), [witnesses](zk/witness/README.md), [prover](zk/prover/README.md) |
| Project tooling and utilities   | [initializer](init/README.md), [program runner](program-runner/README.md), [circuit builder](zk/build/README.md), [benchmarks](zk/benchmarks/README.md), [samples](zk/samples/README.md), [VFS](fs/README.md), [utilities](utils/README.md), [byte derive](utils-derive/README.md), [immutable map](hamt/README.md)                                        |
| Diagnostics and tests           | [logger](logger/README.md), [console](console/README.md), [local daemon](daemon-server/README.md), [dashboard](dashboard/README.md), [test fixtures](test-helpers/README.md), [system tests](tests/README.md), [layout locks](layout-lock/README.md)                                                                                                       |

For current public flows, see [committee selection](../docs/architecture/committee-selection.md),
[DKG](../docs/architecture/dkg.md), and
[threshold decryption](../docs/architecture/threshold-decryption.md). In particular, locally
aggregated output is publication intent; confirmed chain events establish canonical completion.

## Debugging

The CLI's global verbosity options select these levels:

```sh
interfold start          # WARN
interfold start -v       # INFO
interfold start -vv      # DEBUG
interfold start -vvv     # TRACE
interfold start --quiet  # ERROR
```

Add `--otel http://localhost:4317` to export spans to an OTLP/gRPC collector, for example:

```sh
interfold start -v --otel http://localhost:4317
```

A local Jaeger collector can expose its UI on port 16686 and OTLP/gRPC on 4317; configure those
ports using the chosen Jaeger image's instructions. View traces at `http://localhost:16686`. CLI
setup is separate from test harness telemetry: the integration shell harness accepts `OTEL` for
commands it launches, for example `OTEL=http://localhost:4317 pnpm test:integration base`. Arbitrary
`cargo test` invocations do not automatically export spans merely because `OTEL` is set.

Operational log cursors/rotation and privacy limits are documented in [logger](logger/README.md);
the [dashboard](dashboard/README.md) keeps those diagnostics separate from durable event history.
