# Working on CRISP

CRISP is an application with its own Cargo/pnpm workspaces; root `cargo -p` does not select its
server/program packages. [Readme.md](Readme.md) owns setup, profiles, service exposure, and usage.

- Keep application leaf/slot/parent rules aligned across the contract, SDK/witness generator, server
  indexing, and program policy. Link
  [encrypted computation](../../docs/architecture/encrypted-computation.md) for the detailed
  contract rather than duplicating it in component guidance.
- Input/event/durable-record changes cannot silently migrate an in-flight round. Preserve the
  [server's refusal and deployment procedure](server/Readme.md#upgrading-across-an-input-format-change).
- The native service and separate guest both link `program/`; shared runner sources belong in
  `crates/support-scripts`, not copied `.interfold` caches. Follow their
  [project-context guidance](../../crates/support-scripts/AGENTS.md) for changes there.
- The Vercel client installs published packages outside the workspace. After dependency bumps,
  update `client/pnpm-lock.yaml` with `pnpm install --ignore-workspace` in that directory; a local
  workspace build does not verify the published-package deployment.

Use CRISP's focused `pnpm test:contracts`, `pnpm test:sdk`, and `pnpm test:circuits` targets for the
affected layer. Cross-layer changes need the matching E2E/profile flow in
[proof configuration](docs/PROOF_AGGREGATION_AND_ZK.md). Report which proof paths were real, mocked,
or skipped; an unproved development round cannot qualify OpenVM or recursive BFV acceptance.
