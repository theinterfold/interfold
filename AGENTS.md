# Interfold — Agent Entry Point

This file is the tool-neutral entry point for any LLM coding agent (Claude Code, OpenCode, Codex,
Cursor, Cline, Windsurf, ...). Tool-specific config files point here. The content lives in `agent/`
and `.agents/skills/`. Do not copy it into tool configs.

## Read budget

Read `agent/RULES.md` before you start. It is short, and it applies to every task.

Everything else is reference material. Look it up only when the task needs it. Search a large file
for the paths and symbols that you change, and read the matching section. Do not read the harness
docs whole before you start: the flow-trace, the architecture map, and the invariant sections are
too large for that.

| When the task                                                                    | Look up                                                                             |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| needs a command, a term, the monorepo map, or the build configuration            | `agent/CONTEXT.md`                                                                  |
| changes protocol-bearing code (`agent/RULES.md` §Protocol-bearing changes)       | `agent/invariants/00_INDEX.md`: its routing table names the section to search       |
| adds a Rust crate, actor, message, persisted state, or side effect               | `agent/ARCHITECTURE.md` (rules) and `agent/CRATES_ARCHITECTURE.md` (map), by search |
| changes protocol behavior, or current behavior looks wrong                       | `agent/flow-trace/00_INDEX.md` topic table, then search the matching trace file     |
| writes docs, a README, release notes, PR text, or user-facing help or error text | `.agents/skills/asd-ste100/SKILL.md`                                                |
| adds, changes, or removes tests                                                  | `.agents/skills/test-audit/SKILL.md`                                                |
| switches the committee or preset, or reviews or updates `agent/` docs            | `agent/prompts/` (`switch-committee`, `invariant-reviewer`, `update-flow-trace`)    |

## Task loop

1. Change only the requested scope.
2. Verify at the smallest scope that covers the change. — `agent/RULES.md` §Verification ladder
3. Review the diff. A protocol-bearing diff gets one invariant review pass. — `agent/RULES.md`
   §Review
4. If the change makes a statement in `agent/` false, correct it in the same change. —
   `agent/RULES.md` §Harness docs
5. Report the commands that you ran, their results, and the open questions. Do not merge unless the
   user asks.

## Code review rules

- For a protocol-bearing change (`agent/RULES.md` §Protocol-bearing changes), cite the applicable
  `agent/invariants/` entry in each finding. The safe path preserves the invariant or implements an
  explicit, tested migration.
- A protocol-bearing change is not correct only because it compiles. Check compatibility, replay,
  persistence, and cross-layer behavior.
- Leave formatting and other mechanical findings to the automated checks. Report only consequential,
  actionable findings.

## Harness layout

This section is for people who change the harness. A task agent does not need it.

Canonical, tool-neutral content (edit these; they are the single source of truth):

- `agent/*.md`, `agent/invariants/`, `agent/flow-trace/`: rules, context, invariants, architecture,
  and protocol traces.
- `agent/prompts/`: bodies of the reusable agents and commands (`invariant-reviewer`,
  `switch-committee`, `update-flow-trace`).
- `.agents/skills/`: portable skills. Detailed material stays in the `references/` directory of each
  skill.
- `scripts/check-*.{sh,ts}` and `.husky/pre-push`: mechanical gates (committee sync, doc drift,
  contract addresses, invariant ratchets).
- `packages/interfold-mcp/`: the `interfold-docs` MCP server.

Per-tool adapters are thin wrappers. Do not put content in them:

- Claude Code: `CLAUDE.md`, `.claude/settings.json` (permissions and the format hook), `.mcp.json`,
  `.claude/agents/` (`invariant-reviewer`), `.claude/commands/` (`/invariant-review`,
  `/switch-committee`, `/update-flow-trace`), and `.claude/skills/` (the `asd-ste100` pointer).
- Codex: `AGENTS.md`, `.agents/skills/`, and `.codex/config.toml` (MCP).
- OpenCode: `opencode.json` (permissions, MCP, and the `invariant-reviewer` agent). It loads skills
  from `.agents/skills/` and from `.claude/skills/`.
- Cursor, Cline, Windsurf, and Copilot: one-line pointers to this file.

Sync rules:

- `.claude/settings.json` and `opencode.json` must grant and deny the same capabilities, each in its
  native syntax. Change both together.
- Put the body of a new agent or command in `agent/prompts/`. Add one pointer skill in
  `.agents/skills/` for Codex and OpenCode, and a Claude command or agent in `.claude/`.
- Do not add a `.claude/skills/` pointer for a skill in `.agents/skills/`, because OpenCode would
  load both. The `asd-ste100` pointer is the one exception, because Claude Code finds skills only in
  `.claude/skills/`.
- Keep the always-read surface small. Add reference material to the file that owns the topic, and
  add a row to the read-budget table above. Do not add another file that every task must read.
