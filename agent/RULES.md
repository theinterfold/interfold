# Interfold — Agent Rules

These rules apply to any LLM agent working on this codebase. Tool-specific config files (AGENTS.md,
CLAUDE.md, .cursor/rules/interfold.mdc, .clinerules, .windsurfrules, etc.) should reference this
file rather than duplicating its content.

## Harness map

| File                     | Read when                                                                                                    |
| ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `RULES.md` (this file)   | Always, before any task                                                                                      |
| `CONTEXT.md`             | You need project overview, terminology, monorepo map, commands, or conventions                               |
| `invariants/00_INDEX.md` | Before changing contracts, circuits, actor runtime, or build config — then only the section it routes you to |
| `ARCHITECTURE.md`        | Rust contribution rules (target design, layering, durability, testing)                                       |
| `CRATES_ARCHITECTURE.md` | The implemented Rust runtime, persistence, and protocol topology                                             |
| `flow-trace/00_INDEX.md` | Protocol behavior questions; known bugs & concerns                                                           |
| `prompts/`               | Canonical bodies for reusable agents/commands — tool wrappers in `.claude/`, `.opencode/` point here         |
| `.agents/skills/`        | Portable task skills; load `asd-ste100` before writing or reviewing technical prose                          |

Maintenance rule: these docs are part of the codebase. When a change invalidates a statement in any
of them (a command, an invariant, a crate's role), update the doc **in the same PR** — surgical
edits, same style as flow-trace updates below. Enforced mechanically by `pnpm check:docs`
(pre-push): protocol-bearing code changes without an `agent/` diff are rejected unless a commit
message carries `[skip-doc-sync]`.

## Working rules

- Run builds/tests/lint through the root pnpm scripts (`pnpm test`, `pnpm rust:test`, `pnpm lint`,
  ...) — not raw cargo/nargo/hardhat. Full command table: `CONTEXT.md`.
- Commits: Conventional Commits, types `feat`/`fix`/`chore` only, description ≤ 72 chars, `!` for
  breaking changes.
- Never hand-edit generated files (committee/preset files, parity matrices, verifier contracts,
  `.active-preset.json`, `deployments/manifest.json`) — see `invariants/04_BUILD_CONFIG.md`.
- Every new `.rs`/`.sol`/`.ts` file needs the SPDX `LGPL-3.0-only` header.
- Before writing or reviewing natural-language technical content, load
  `.agents/skills/asd-ste100/SKILL.md`. Apply it to code comments, doc comments, documentation,
  requirements, procedures, help text, error text, release notes, and PR prose. Preserve protected
  code and exact interface literals.
- Before assuming current behavior is correct, check the "Verified Bugs & Protocol Concerns" table
  in `flow-trace/00_INDEX.md` and the open-issues list in `invariants/00_INDEX.md`.
- Invariant review is one sequential pass. Do not spawn a subagent per invariant or per section
  unless the user explicitly asks for a per-invariant or per-section audit. —
  `invariants/00_INDEX.md` §Review budget

## Verification ladder

Verify every change at the smallest scope that covers it, and state which command you ran when
reporting done. Escalate only as needed:

1. **Single crate:** `cargo test -p e3-<crate>` (exception to the pnpm-scripts rule — per-crate
   scoping has no pnpm wrapper). Type-check fast with `cargo check -p e3-<crate>`.
2. **One layer:** `pnpm rust:test` · `pnpm evm:test` · `pnpm sdk:test` · `pnpm noir:test`.
3. **One integration scenario:** `pnpm test:integration <name>` (e.g. `net`; `--no-prebuild` to skip
   the binary rebuild when only re-running).
4. **Everything:** `pnpm test` — rarely needed locally; CI runs it anyway.

Cross-layer changes (contracts ↔ Rust ↔ circuits) need at least one integration scenario, not just
unit tests. CI additionally runs things pre-push does not: full integration suites, circuit builds,
zk-prover e2e, contract storage/size gates, and commit-message validation — a green pre-push is not
a green CI.

## Project Structure

- `crates/` — Rust workspace: CLI, actors, crypto, networking, FHE, EVM integration
- `packages/` — TypeScript: Solidity contracts (`interfold-contracts`), SDK, React, MCP server
- `circuits/` — ZK proof circuits
- `tests/` — Integration tests
- `agent/` — LLM context documentation

For Rust work, read both `agent/ARCHITECTURE.md` (contribution rules) and
`agent/CRATES_ARCHITECTURE.md` (the implemented runtime, persistence, and protocol topology).

## Build configuration: preset and committee

Two orthogonal axes pick what gets compiled into `circuits/bin/`:

- **Preset** (`--preset insecure-512` [default] | `secure-8192`): the BFV parameter set.
- **Committee** (`--committee minimum` [default] | `micro` | `small`): `(N, T, H)` for the
  secret-sharing committee. Mirrors `e3_zk_helpers::CiphernodesCommitteeSize`.

The current selection is the single source of truth at three places that **must** stay in sync:

| File                                                          | Owner                                      |
| ------------------------------------------------------------- | ------------------------------------------ |
| `circuits/lib/src/configs/committee/active.nr`                | regenerated by `scripts/build-circuits.ts` |
| `packages/interfold-contracts/scripts/utils.ts` (`BFV_DKG_H`) | regenerated by `scripts/build-circuits.ts` |
| `circuits/bin/.active-preset.json`                            | written by `scripts/build-circuits.ts`     |

`scripts/check-committee.sh` (pre-push hook: `pnpm check:committee`) enforces consistency. Always
switch with `pnpm build:circuits --committee <name>`; never hand-edit the three files above.
Supported `(preset, committee)` pairs live in `scripts/circuit-constants.ts`. See
`scripts/README.md#circuit-builder` and `circuits/benchmarks/README.md` for the full recipe.

## Contract addresses

`packages/interfold-contracts/deployed_contracts.json` records what the deploy scripts put on each
network. `pnpm gen:manifest` derives `deployments/manifest.json` from it, and that manifest is the
single source of truth for every published address. It is attached to each release, and
`interfold config check` fetches it to tell an operator that a redeploy happened.

After a redeploy, update every consumer in the same PR: the operator docs, the dashboard, the
DAppNode package, and the CRISP example. `pnpm check:addresses` (pre-push) enforces this. It fails
when a consumer keeps an address the manifest no longer publishes, and when a new file quotes a live
address without being classified in `scripts/check-addresses.ts`.

A release must carry the current manifest. A tag cut before a redeploy ships dead addresses to every
node that fetches the asset, and the node then syncs an address that emits no events.

## Flow-Trace Documentation (`agent/flow-trace/`)

The `agent/flow-trace/` directory contains detailed protocol documentation that traces the complete
lifecycle of the Interfold protocol — from node registration through DKG, computation, decryption,
failure handling, and deactivation.

### When to consult

Read the relevant flow-trace file **before** modifying code in any of these areas:

| Area                                                                                 | File to read                        |
| ------------------------------------------------------------------------------------ | ----------------------------------- |
| CLI commands (`setup`, `register`, `activate`, `status`), on-chain registration, IMT | `01_REGISTRATION.md`                |
| FOLD bonding, tFOLD/USDC tickets, activation thresholds, exit queue                  | `02_TOKENS_AND_ACTIVATION.md`       |
| E3 requests, fee payment, committee selection, sortition, ticket submission          | `03_E3_REQUEST_AND_COMMITTEE.md`    |
| DKG, BFV keygen, ZK proofs (C0–C7), Shamir shares, key aggregation, decryption       | `04_DKG_AND_COMPUTATION.md`         |
| Timeouts, `markE3Failed`, refunds, accusations, slashing (Lane A/B)                  | `05_FAILURE_REFUND_SLASHING.md`     |
| Deactivation, deregistration, E3 completion, node shutdown, sync/restart             | `06_DEACTIVATION_AND_COMPLETION.md` |

Always start from `00_INDEX.md` if unsure which file is relevant.

### How to navigate

1. Open `agent/flow-trace/00_INDEX.md` — it has a topic table and end-to-end flow summaries
2. Find the file that covers your area of interest
3. Each file traces the flow call-by-call with file paths, function names, and event names
4. The index also contains a "Verified Bugs & Protocol Concerns" section — check it before assuming
   current behavior is correct

### When to update

Update flow-trace docs **in the same PR** when any of these happen:

- A contract function signature, event, or state variable changes
- An actor's message handling or event routing changes
- A CLI command's behavior or arguments change
- A ZK circuit or proof pipeline step is added, removed, or reordered
- A timeout, threshold, or fee calculation formula changes
- A bug listed in "Verified Bugs & Protocol Concerns" is fixed or a new one is found

### How to update

- Edit the specific file that covers the changed area — keep changes scoped
- If a change spans multiple files, update all affected files
- Update `00_INDEX.md` only when adding/removing/renaming a file, or when the end-to-end flow
  summaries or the contract interaction map change
- Preserve the existing format: step-by-step traces with `File:` references pointing to actual
  source paths
- Keep the "Verified Bugs" table in `00_INDEX.md` current — mark fixed bugs, add new ones
- Do NOT rewrite entire files for small changes — surgical edits only

### Organization rules

- Files are numbered sequentially (`01_`, `02_`, ...) following the protocol lifecycle order
- Each file covers one logical phase of the protocol
- To add a new phase, use the next available number and add it to the index table
- File names use `SCREAMING_SNAKE_CASE` after the number prefix
