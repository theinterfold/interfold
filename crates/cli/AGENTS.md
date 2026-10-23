# e3-cli

Keep argument parsing, prompts, and operator output here; delegate node lifecycle and protocol work
to their existing owners rather than implementing another startup path.

- Contract calls generate Rust bindings from tracked contract artifact JSON. After contract API
  changes run `pnpm evm:build` and `pnpm check:bindings`; do not patch a generated ABI to hide a
  mismatch. The [binding check](../../scripts/checks/cli-bindings.ts) documents this boundary.
- `build.rs` reads `packages/interfold-contracts/deployed_contracts.json` and generates Rust data in
  `OUT_DIR`. Change deployment records through the contract tooling, not generated Rust. `GIT_SHA`
  overrides build identity; without local Git metadata the build may query the remote.
- Preserve explicit confirmation and stopped-node safety for reset/purge commands. A successful
  prompt is not a replacement for entrypoint's process fence and state checks.
- Update/uninstall change only the installed binary and run before configuration handling. Preserve
  atomic same-directory replacement, symlink resolution, and the running-node warning without
  creating node state or treating that warning as a stopped-node requirement.
- Keep proof-skip arguments behind the dedicated test-only feature; never make missing proof
  artifacts silently choose an unproved production mode.
- Retain the actor-thread panic watch before startup and its bounded shutdown/error path. Do not
  widen it to compute or dashboard worker threads whose failures have separate owners.
- Project compile/start runs the project's `program-runner` from its root and rejects legacy
  `.interfold/support`. Preserve absolute worker/setup paths, environment forwarding, and errors
  that omit child arguments. Cache purge owns only `.interfold/caches`, not sources or node state.

Use the [README tests/build prerequisites](README.md#tests). Command changes need the affected
executable/daemon path, not only parser assertions. Contract API changes also need the binding check
above; generated data is not the source of truth.
