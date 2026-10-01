# Interfold — Agent Rules

These rules apply to every task, with one agent or with several. Tool-specific files point to
`AGENTS.md`, which points here. Do not copy these rules into tool configs.

## Read budget

- Read this file before you start. Look up everything else only when the task needs it. The table in
  `AGENTS.md` §Read budget names the file for each need.
- Search a large doc for the paths, contracts, events, and symbols that you change. Read the
  matching section only.
- Stop reading when you can name the code that owns the behavior, the contract that the change must
  keep, and the check that proves it.

## Working rules

- Run builds, tests, and lint through the root pnpm scripts (`pnpm test`, `pnpm rust:test`,
  `pnpm lint`, ...), not raw nargo or hardhat. `cargo test -p` and `cargo check -p` for one crate
  are the exception. Command table: `agent/CONTEXT.md` §Key commands.
- Commits and PR titles use Conventional Commits, with `!` for a breaking change. The PR title is
  the default squash-commit title. CI checks only the PR title
  (`.github/workflows/validate-commits.yml`): type `feat`, `fix`, `chore`, `refactor`, `docs`, or
  `test`; lower-case scope; whole header of at most 72 characters.
- Do not hand-edit generated files: `circuits/lib/src/configs/committee/active.nr`, parity matrices,
  generated verifier contracts, the generated constants in
  `packages/interfold-contracts/scripts/utils.ts`, `ActiveCryptoConfig.sol`,
  `circuits/bin/.active-preset.json`, and `deployments/manifest.json`. Switch the committee or
  preset only with `pnpm build:circuits` (`agent/prompts/switch-committee.md`). Full list:
  `agent/invariants/04_BUILD_CONFIG.md`.
- Every new `.rs`, `.sol`, and `.ts` file needs the SPDX `LGPL-3.0-only` header.
- Code comments and `agent/` docs state the current behavior and its reason, in short, active
  sentences. Do not narrate history ("now", "previously", "used to") or PR context, and do not add
  audit-round addendum sections. Put history in the commit message. For longer prose (docs pages,
  READMEs, release notes, PR text, user-facing help or error text), load
  `.agents/skills/asd-ste100/SKILL.md`.
- Before you add, change, or remove a test, apply the authoring gate in
  `.agents/skills/test-audit/SKILL.md`.

## Protocol-bearing changes

A change is protocol-bearing when it changes the behavior of:

- contracts, deployment scripts, or tasks in `packages/interfold-contracts/`, and the CRISP
  contracts and Secure Process (`examples/CRISP/packages/crisp-contracts/contracts/`,
  `examples/CRISP/program/`);
- circuits (`circuits/`, `examples/CRISP/circuits/`), verifiers, proof generation or verification,
  or cryptographic parameters;
- durable schemas and wire formats: events, snapshots, gossip, persisted types, `SCHEMA_VERSION`,
  and `crates/config/protocol-release.toml`;
- actor ordering, persistence, replay, or timers in `crates/`;
- build configuration that generates protocol constants: committee, preset, verifiers, and release
  tooling.

Tests, docs, logs, UI, and refactors that keep the behavior are not protocol-bearing.

For a protocol-bearing change:

1. In `agent/invariants/00_INDEX.md`, read the routing rows for your paths, the meta-invariants, and
   the open issues for your area. Then search the routed section for your files and symbols, and
   read the entries that match.
2. If the change touches `SCHEMA_VERSION`, `GOSSIP_WIRE_MAJOR`, `SYNC_WIRE_MAJOR`, a persisted type,
   an `InterfoldEventData` variant, a contract event or ABI, or
   `crates/config/protocol-release.toml`, state the upgrade class in the PR body: rolling,
   drain-and-resync, or governance. Also state whether `protocol_version` or `node_generation` must
   change. Use `!` when operators must reset or resync.
3. Review the diff as §Review describes.

## Change discipline

1. Start from current `origin/main` on a new `<type>/<topic>` branch, unless the user names another
   base. Do not start the branch name with a tool or agent name (`agent/`, `claude/`, `codex/`).
   Give each agent that runs at the same time its own worktree.
2. Change only the requested scope. Report other findings as follow-ups.
3. Before you add a helper, wrapper, guard, flag, fallback, migration, or legacy-format support,
   name the production caller, the deployed data, or the released artifact that needs it.
4. A regression test runs the changed production path and fails when you revert the fix. Do not copy
   production logic into `#[cfg(test)]` or other test-only code.
5. Do not push with `--no-verify` or set `SKIP_DOC_SYNC=1`. If a gate cannot run, report which gate
   and why.
6. Do not commit plans, audit notes, review transcripts, rollout checklists, or other working files,
   unless the task requires that file.
7. Verify each reviewer or review-bot finding against the code before you change anything. If a
   finding is wrong, reply with the evidence and make no change.
8. Do not merge, mark a PR ready for review, or create a tag unless the user asks.
9. Do not wait for CI unless the user asks. Report the local checks that you ran, and name the CI
   jobs whose path filters cover the change. Do not claim that CI passed unless you saw the result.

## One owner, no copies

A **scattered domain** is a protocol capability or business rule whose logic already lives in
several files, whose copies disagree, or whose calculations sit in the wrong layer (handlers, CLI
formatting, templates, view builders).

These rules apply on top of Change discipline. When they conflict with "change only the requested
scope", the first change is the consolidate. The feature is a later change.

### Second use of existing logic

Before you add a second use of a formula, threshold, format string, hash, or schema fact:

1. Search the repository for that expression.
2. List every copy.
3. If copies disagree, stop and report. Do not add another copy.
4. If copies agree, move the logic to the owning module. Switch every caller. Keep each caller's
   exact results, including guards, rounding, and clamps. Tests must stay green.
5. Add the new use in a later change.

A new helper next to old copies is one more duplicate.

### Where a new rule goes

Put a new rule in the module that owns that domain.

- Rust: the capability directory in `ARCHITECTURE.md` §Canonical Module Structure.
- Protocol facts: the invariant section and the cited source.
- Contract formulas: the Solidity library that already owns that calculation.

Do not put a new rule in the first feature that needs it. A function-level import that exists only
to dodge a cycle means the logic is in the wrong module.

### Refactor, then change

When you work in a scattered domain:

1. Write counts: files that hold the logic, copies of each formula, places the copies disagree.
2. Make a behavior-preserving consolidate. One PR. Tests green. No new feature in that diff.
3. Add a check that fails if the copies return, when you can write one (`scripts/check-*.{sh,ts}`).
4. Repeat the same counts on the result.
5. Then implement the feature on the owner module.

Do not mix the consolidate and the feature in one unverifiable diff.

A prompted "never" is not a gate. A rule that matters has a CI check, a hook, or the
invariant-reviewer procedure.

## Verification ladder

Verify each change at the smallest scope that covers it, and name the command that you ran when you
report. Escalate only as needed:

1. **Single crate:** `cargo test -p e3-<crate>`. Type-check fast with `cargo check -p e3-<crate>`.
2. **One layer:** `pnpm rust:test` · `pnpm evm:test` · `pnpm sdk:test` · `pnpm noir:test`.
3. **One integration scenario:** `pnpm test:integration <name>` (for example `net`; add
   `--no-prebuild` to skip the binary rebuild on a re-run).
4. **Everything:** `pnpm test`. CI runs the same suites, so you rarely need it locally.

A cross-layer change (contracts ↔ Rust ↔ circuits) needs at least one integration scenario, not
only unit tests.

Each ZK proof costs minutes. Run a proof suite (`pnpm rust:test:proofs`, `pnpm sdk:test:proofs`, the
CRISP contract and SDK suites) only when the change can affect proof generation or verification.
Select the affected test with the runner filter (`--grep`, `-t`, or a cargo test name).

Pre-push and CI run different checks. CI also runs the full integration suites, the circuit builds,
the zk-prover e2e tests, the contract storage and size gates, and PR-title validation. Only pre-push
runs `check:addresses`, `check:pnpm`, and the root `eslint`. CI path filters skip the jobs whose
paths did not change.

## Review

Scale the review to the risk. Review the diff (`git diff`), not your memory of the change.

- **Protocol-bearing diff:** run one pass of `agent/prompts/invariant-reviewer.md`. Use a fresh,
  read-only context when your tool has one (Claude Code and OpenCode: the `invariant-reviewer`
  agent). If it does not, do the pass yourself as a separate step after the change is complete. One
  pass is enough, also for schema, wire-format, circuit, and ABI changes: the procedure makes the
  reviewer check their compatibility explicitly. Do not spawn a reviewer per invariant or per
  section unless the user asks for that audit.
- **Any other diff:** read your diff once before you report. It needs no invariant review.

Handle each finding with Change discipline rule 7. The review does not replace the gates, and the
gates do not replace the review: most invariants have no mechanical check.

When the change consolidates a scattered domain, report the same counts from the first audit.
Report files, copies, and disagreements. A clean compile is not enough.

## Harness docs

- Update `agent/` in the same change only when the change makes a documented statement false: a
  command, an invariant, a formula, a function signature, an event, an actor route, or CLI behavior.
  Follow `agent/prompts/update-flow-trace.md`, and edit surgically.
- `pnpm check:docs` (pre-push) rejects a branch that changes protocol-bearing code without an
  `agent/` diff. It exempts a watched file when neither its changed lines nor their enclosing
  declarations name an identifier that the docs mention, when the change is only a formatter reflow,
  and when the branch reverts the file. If the gate fails and no documented statement changed, put
  `[skip-doc-sync]` in the commit message. This is the normal result for most bug fixes, refactors,
  and test changes.
- Keep the always-read surface small (`AGENTS.md` §Harness layout).
