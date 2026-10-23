# Working on repository scripts

Keep executable behavior in the owning script/library; root `package.json` supplies the supported
entry points. [README.md](README.md) documents flags, prerequisites, and operational side effects.

- Release implementation lives in `release/`, behind `bump.ts` and `index.mjs`.
  [RELEASING.md](../RELEASING.md) owns the procedure; do not introduce another release sequence
  here.
- Preserve argument forwarding, exit status, dry-run/check behavior, and cleanup ownership when
  changing wrappers; use script unit tests to check a wrapper change.
- Circuit build, hydration, verifier generation, and source hashing share preset/committee identity.
  The Rust owner is `crates/zk/build`; `circuits/` here owns transport/adapters and the shared pair
  policy. Change the owning helpers rather than bypassing stamps or rewriting generated outputs. See
  [artifact boundaries](../docs/architecture/circuit-artifacts.md).
- `checks/repository.sh` owns static production configuration guards, not runtime assurance. Changes
  to CI/hooks must retain the actual checks, not replace them with instruction-wording checks.

Use `pnpm test:harnesses` for runner changes, `pnpm test:release` for release tooling, and
`pnpm test:circuit-tooling` for artifact/verifier tooling, plus `pnpm test:circuit-build` and
`pnpm test:circuit-bench` for Rust build/benchmark owners. Select the affected target; these tests
do not publish, compile a real proof, or qualify a release. Blueprint maintenance has its own
[local guidance](blueprint/AGENTS.md).
