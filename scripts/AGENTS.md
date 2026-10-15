# Working on repository scripts

Keep executable behavior in the owning script/library; root `package.json` supplies the supported
entry points. [README.md](README.md) documents flags, prerequisites, and operational side effects.

- Release implementation lives in `bump-versions.ts` and `release/`, behind `release.mjs`.
  [RELEASING.md](../RELEASING.md) owns the procedure; do not introduce another release sequence
  here.
- Preserve argument forwarding, exit status, dry-run/check behavior, and cleanup ownership when
  changing wrappers. `run-crisp-test.sh` tests committed HEAD, not this checkout's pending edits;
  use script unit tests to check a wrapper change before invoking that runner.
- Circuit build, hydration, verifier generation, and source hashing share preset/committee identity.
  Change their common helpers rather than bypassing stamp checks or rewriting generated outputs to
  make a test pass. See [artifact boundaries](../docs/architecture/circuit-artifacts.md).
- `check-repository.sh` owns static production configuration guards, not runtime assurance. Changes
  to CI/hooks must retain the actual checks, not replace them with instruction-wording checks.

Use `pnpm test:harnesses` for runner changes, `pnpm test:release` for release tooling, and
`pnpm test:circuit-tooling` for artifact/verifier tooling. Select the affected target; these tests
do not publish, compile a real proof, or qualify a release. Blueprint maintenance has its own
[local guidance](blueprint/AGENTS.md).
