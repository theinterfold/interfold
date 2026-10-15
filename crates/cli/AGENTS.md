# e3-cli

Keep argument parsing, prompts, and operator output here; delegate node lifecycle and protocol work
to their existing owners rather than implementing another startup path.

- Contract calls generate Rust bindings from tracked contract artifact JSON. After contract API
  changes run `pnpm evm:build` and `pnpm check:bindings`; do not patch a generated ABI to hide a
  mismatch. The [binding check](../../scripts/check-cli-bindings.ts) documents this boundary.
- `build.rs` reads `packages/interfold-contracts/deployed_contracts.json` and generates Rust data in
  `OUT_DIR`. Change deployment records through the contract tooling, not generated Rust. `GIT_SHA`
  overrides build identity; without local Git metadata the build may query the remote.
- Preserve explicit confirmation and stopped-node safety for reset/purge/update commands. A
  successful prompt is not a replacement for entrypoint's process fence and state checks.
- Keep proof-skip arguments behind the dedicated test-only feature; never make missing proof
  artifacts silently choose an unproved production mode.

Run `cargo test --locked -p e3-cli` after the root `pnpm evm:build` / `pnpm fixtures:build`
preparation, with solc/jq available. Transitive zk-prover builds may also prepare Noir fixtures; see
[its build warning](../zk-prover/AGENTS.md). Usage belongs in the [root README](../../README.md).
