# Repository scripts

## Purpose

Root [package scripts](../package.json) supply supported commands. Implementations and tests live
with the capability they maintain.

## Map

| Owner                                                | Commands and usage                                                                                |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| [checks/](checks/README.md)                          | Repository, committee, address, binding, license, package-manager, and shell checks.              |
| [circuits/](circuits/README.md)                      | Artifact transport, verifier generation, and Noir wrappers.                                       |
| [Rust circuit builder](../crates/zk/build/README.md) | `pnpm build:circuits`, `pnpm test:circuit-build`.                                                 |
| [Rust benchmarks](../crates/zk/benchmarks/README.md) | `pnpm bench:circuits`, `pnpm test:circuit-bench`.                                                 |
| [release/](release/README.md)                        | Version preparation and explicit publication; [RELEASING.md](../RELEASING.md) owns the procedure. |
| [dev/](dev/README.md)                                | `pnpm clean` removes rebuildable output, not operator state or indexed files.                     |
| [openvm/](openvm/README.md)                          | `pnpm openvm <task>`, `pnpm provenance:manifest`.                                                 |
| [hooks/](hooks/README.md)                            | Shared helpers for `.husky/` entry points.                                                        |
| [blueprint/](blueprint/README.md)                    | Architecture navigation, documentation checks, and PR previews.                                   |

Network runner regressions live beside [their owner](../crates/net/tests/run.sh).

## Tests

Use `pnpm test:scripts`, `pnpm test:release`, `pnpm test:circuit-tooling`, and `pnpm test:harnesses`
for script boundaries. Use `pnpm test:circuit-build` and `pnpm test:circuit-bench` for Rust tooling.
These tests do not qualify cryptographic proofs or a release. Contract size checks and sale
rehearsals belong to the [contract package](../packages/interfold-contracts/README.md).

[AGENTS.md](AGENTS.md) describes how to change repository tooling.
