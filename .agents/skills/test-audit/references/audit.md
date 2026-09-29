# Audit workflow

This reference holds the audit-mode procedure of the `test-audit` skill. Judge each candidate with
the checklists in [value-bar.md](value-bar.md).

## Discovery

Keep discovery read-only and report evidence before editing. For broad scope, run parallel discovery
lanes when available:

- Rust crates (`crates/`), split by subsystem when the scope is large;
- Solidity contracts and deployment tooling (`packages/interfold-contracts/`);
- TypeScript packages (`packages/interfold-sdk/`, `interfold-react`, `interfold-mcp`,
  `interfold-config`, `interfold-dashboard`);
- Noir circuits (`circuits/`);
- integration suites, scripts, and tooling (`tests/integration/`, `scripts/`, `templates/`,
  `dappnode/`);
- the CRISP example (`examples/CRISP/`), which has a separate release;
- a cross-cutting pattern sweep.

Outside campaign mode, prefer a few high-confidence candidates over a large speculative inventory.
Hunt for the [junk patterns](value-bar.md#junk-patterns).

## Candidate evidence

Record every field below before editing. A missing field means the candidate is not ready for
deletion:

- exact test name and location;
- what failure it can actually detect;
- non-test callers of the covered production or support seam;
- stronger remaining owner-boundary proof, or why no proof is needed;
- relevant history and the reason the test or seam exists;
- production or test-support deletion unlocked;
- risk and the focused validation command.

## Edit shape

Choose one coherent owner-boundary batch. Delete obsolete test-only exports, globals, wrappers, and
dead production paths instead of preserving aliases. Move retained regressions to their canonical
owners. Consolidate repeated package or dependency assertions into one generic contract.

Prefer net-negative production LOC. Do not add replacement tests that restate the same
implementation, and do not convert uncertain candidates into cleanup to increase deletion counts.

## Validation

Do not edit source or tests while a test run is active in the checkout. Follow `agent/RULES.md`
§Verification ladder.

1. Run the smallest owner and sibling tests: `cargo test -p e3-<crate> <filter>`,
   `pnpm evm:test test/<file>.spec.ts`, `pnpm sdk:test <path>`, `pnpm noir:test` for circuits, or
   `pnpm test:harnesses`, `pnpm test:release`, and `pnpm test:circuit-tooling` for `scripts/`.
2. For removed source greps or plan assertions, run the executable script or dry-run that owns the
   real contract.
3. Run targeted formatting (`cargo fmt`, `nargo fmt`, or prettier on the changed files), then
   `git diff --check`.
4. Run the `.husky/pre-push` gates that cover the changed paths, for example `pnpm lint`,
   `pnpm check:docs`, `pnpm check:invariants`, and `pnpm check:license`. Name the CI jobs whose path
   filters cover the change.
5. Inspect `git diff --numstat`; report production/tooling separately from tests and test support.
6. After final audit edits, review the diff in a fresh context (`agent/RULES.md` §Review before you
   report done). For protocol-bearing paths, use `agent/prompts/invariant-reviewer.md`.

## Landing and continuation

Commit, push, open a PR, or land only when authorized. Use a `test/<topic>` branch from current
`origin/main` and a Conventional Commits PR title (`agent/RULES.md` §Change discipline). A test-only
removal under a path that `scripts/check-doc-sync.sh` watches can arm `pnpm check:docs`. When no
documented behavior changes, put `[skip-doc-sync]` in the commit message. Land one coherent PR at a
time; after landing, refresh from current `main` and rerun read-only discovery for the next
high-confidence batch.

## Handoff

Report:

- root cause and removed low-value categories;
- production owner simplifications;
- retained false positives and why they remain valuable;
- focused and full proof actually run;
- production versus test LOC;
- PR and merge state;
- named follow-ups.
