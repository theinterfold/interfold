# ZK components

## Owners

| Crate                              | Responsibility                                                                         |
| ---------------------------------- | -------------------------------------------------------------------------------------- |
| [config](config/README.md)         | Static parameters, bounds, parity, rendering, and public layouts.                      |
| [witness](witness/README.md)       | Production inputs, deterministic preparation, commitments, and Noir JSON.              |
| [prover](prover/README.md)         | Runtime Noir/BB execution, verification, folding, recovery, and artifact installation. |
| [samples](samples/README.md)       | Unpublished artificial cryptographic material for tests/development.                   |
| [build](build/README.md)           | Unpublished build/configuration operations, source identity, staging, and hydration.   |
| [benchmarks](benchmarks/README.md) | Unpublished leaf/protocol/gas orchestration and saved replay/reports.                  |

Normal dependencies point from witness to config and from build to witness/config. Prover consumes
production configurations and witnesses. Samples stay in dev-dependencies except for the unpublished
benchmark runner, whose executable constructs artificial inputs. No package may depend on that
benchmark binary's crate.

Use `pnpm build:circuits` and `pnpm bench:circuits` for tools. Use the owning README's focused Cargo
tests or `pnpm test:circuit-build` / `pnpm test:circuit-bench` for verification. Prepared real-proof
acceptance is a separate boundary. [AGENTS.md](AGENTS.md) describes shared artifact precautions.
