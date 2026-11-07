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

The EVM client and indexer require bash, solc, and jq even for checks because their build scripts
compile Solidity fixtures. Chain tests need Foundry's Anvil. Use the repository's
[CI setup](../.github/workflows) for tool installation/pins rather than historic version examples.
[e3-zk-prover](zk/prover/README.md) builds can also invoke pnpm/Noir and rewrite fixtures; its
compile-only flag does not establish proof readiness. Choose the smallest applicable crate target;
root `pnpm rust:test` and `pnpm rust:test:proofs` cover different scopes, with additional
prerequisites documented by their owners.

The [OpenVM worker](openvm-prover/README.md) is an independent excluded workspace with its own
pinned tools. [e3-program-runner](program/runner/README.md) supplies shared development/OpenVM
modes. Each generated project's separate `runner/` binary links its own program and calls that
library; the CLI owns compile/start orchestration.

The ciphernode is one deterministic machine, [e3-protocol](protocol/), run by an
[engine](ciphernode/engine/) that journals every input in [e3-journal](state/journal/) and stores
large payloads once in the [blob store](state/blobs/). Adapters for the [chain](ciphernode/chain/),
the [network](ciphernode/p2p/), and [jobs](ciphernode/jobs/) perform its effects, and
[e3-node](ciphernode/node/) wires them together. The
[decision log](../docs/architecture/node-v2-decisions.md) records why.

## Find a component

| Capability                     | Entry points                                                                                                                                                                                                                                                                                                      |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Operator commands and assembly | [CLI](cli/README.md), [entrypoint](ciphernode/entrypoint/README.md), [ciphernode family](ciphernode/README.md), [node assembly](ciphernode/node/)                                                                                                                                                                 |
| Protocol and state             | [protocol machine](protocol/), [engine](ciphernode/engine/), [persistence family](state/README.md), [journal](state/journal/), [blob store](state/blobs/)                                                                                                                                                         |
| BFV encryption                 | [BFV family](bfv/README.md), [BFV presets](bfv/params/README.md), [BFV client](bfv/client/README.md), [TrBFV](bfv/threshold/README.md)                                                                                                                                                                            |
| Diagnostics                    | [observation family](diagnostics/README.md), [logger](diagnostics/logger/README.md)                                                                                                                                                                                                                               |
| Runtime adapters               | [EVM](evm/README.md), [chain](ciphernode/chain/), [network](ciphernode/p2p/), [jobs](ciphernode/jobs/), [local crypto](crypto/README.md)                                                                                                                                                                          |
| Application computation        | [application execution family](program/README.md), [Secure Process/provider](program/compute-provider/Readme.md), [OpenVM host](program/openvm-host/README.md), [guest/journal types](program/openvm-types/README.md), [program HTTP server](program/server/README.md), [DA clients](data-availability/README.md) |
| Client libraries               | [Rust SDK](sdk/README.md), [WASM](wasm/README.md), [EVM client](evm/client/README.md), [indexer](evm/indexer/README.md)                                                                                                                                                                                           |
| Parameters, math, and proofs   | [committee](committee/README.md), [committee hashes](committee/hash/README.md), [SAFE](safe/README.md), [polynomials](polynomial/README.md), [parity matrices](parity-matrix/README.md), [ZK config](zk/config/README.md), [witnesses](zk/witness/README.md), [prover](zk/prover/README.md)                       |
| Project tooling and utilities  | [initializer](init/README.md), [program runner](program/runner/README.md), [circuit builder](zk/build/README.md), [benchmarks](zk/benchmarks/README.md), [samples](zk/samples/README.md), [VFS](fs/README.md), [utilities](utils/README.md), [byte derive](utils-derive/README.md)                                |
| Command output and transport   | [console](console/README.md), [local daemon](ciphernode/daemon-server/README.md)                                                                                                                                                                                                                                  |
| Testing                        | [test infrastructure family](testing/README.md), [mechanical test support](testing/support/README.md), [BFV ballots](testing/bfv-support/README.md), [fixture binaries](testing/system/README.md), [node simulation](testing/sim/)                                                                                |

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
ports using the chosen Jaeger image's instructions. View traces at `http://localhost:16686`.

Operational log cursors/rotation and privacy limits are documented in
[logger](diagnostics/logger/README.md).
