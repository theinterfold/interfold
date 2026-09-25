# Interfold — Agent Entry Point

This file is the tool-neutral entry point for any LLM coding agent (Claude Code, opencode, Codex,
Cursor, Cline, Windsurf, ...). Tool-specific config files point here or to `agent/RULES.md`; the
content lives in `agent/` — never duplicate it into tool configs.

Read before starting any task, in this order:

1. `agent/RULES.md` — mandatory working rules (always)
2. `agent/CONTEXT.md` — what Interfold is: terminology, monorepo map, commands, conventions
3. `agent/invariants/00_INDEX.md` — protocol, crypto, runtime, and build invariants you must not
   break; its routing table names the scoped section file(s) to read for the paths you touch
4. `.agents/skills/asd-ste100/SKILL.md` — before writing or reviewing comments, docs, error text,
   requirements, PR prose, or other natural-language technical content
5. Area-specific, when relevant:
   - Rust work → `agent/ARCHITECTURE.md` (contribution rules) and `agent/CRATES_ARCHITECTURE.md`
     (implemented runtime/topology)
   - Protocol behavior → `agent/flow-trace/00_INDEX.md` (lifecycle traces, known bugs)

## Task loop

This loop works with one agent or with several. Each step points to the rule that defines it.

1. Branch from current `origin/main`, unless the user names another base. — `agent/RULES.md` §Change
   discipline
2. Read the harness files above that match the paths you will change.
3. Change only the requested scope.
4. Verify at the smallest scope that covers the change. — `agent/RULES.md` §Verification ladder
5. Review the diff in a fresh context. If you work alone, review it as a separate step. —
   `agent/RULES.md` §Review before you report done
6. If documented behavior changed, update `agent/` in the same change. —
   `agent/prompts/update-flow-trace.md`
7. Report the commands, results, HEAD SHA, and open questions. Do not merge unless the user asks.

## Harness layout: canonical vs adapters

Canonical, tool-neutral (edit these; they are the single source of truth):

- `agent/*.md`, `agent/flow-trace/` — rules, context, invariants, architecture
- `agent/prompts/` — bodies for reusable agents/commands (invariant-reviewer, switch-committee,
  update-flow-trace)
- `.agents/skills/` — portable, repository-scoped skills; detailed material stays in each skill's
  `references/` directory
- `scripts/check-*.{sh,ts}` + `.husky/pre-push` — mechanical gates (committee sync, doc drift,
  contract-address consistency, invariant ratchets); tool-independent
- `packages/interfold-mcp/` — implementation of the `interfold-docs` MCP server

Per-tool adapters (thin wrappers; never put content here):

- Claude Code: `CLAUDE.md`, `.claude/settings.json` (permissions + format hook), `.mcp.json`,
  `.claude/agents/` (`invariant-reviewer`), `.claude/commands/` (`/invariant-review`,
  `/switch-committee`, `/update-flow-trace`), `.claude/skills/` (`asd-ste100` pointer)
- Codex: `AGENTS.md`, `.agents/skills/` (`invariant-review`, `switch-committee`,
  `update-flow-trace`, `asd-ste100`), `.codex/config.toml` (MCP)
- OpenCode: `opencode.json` (permissions, MCP, and the `invariant-reviewer` agent). It loads skills
  from `.agents/skills/` and also from `.claude/skills/`.
- Others (Cursor, Cline, Windsurf, Copilot): one-line pointers to `AGENTS.md`

Sync rules: the permission policies in `.claude/settings.json` and `opencode.json` must grant and
deny the same capabilities with each tool's native syntax. Change both together. When adding an
agent or command, put the body in `agent/prompts/`. Add one pointer skill in `.agents/skills/` for
Codex and OpenCode, and a Claude command or agent in `.claude/`. Do not add a `.claude/skills/`
pointer for a skill in `.agents/skills/`, because OpenCode would load both. The `asd-ste100` pointer
is the one exception, because Claude Code finds skills only in `.claude/skills/`. Edit the canonical
body, not the wrappers.

## Code Review Rules

- Treat `agent/invariants/` (`00_INDEX.md` and the section files that it routes to) as required
  review guidance for contracts, circuits, actor runtime, durable schemas, cryptography, and build
  configuration. Cite the applicable invariant in each finding. Safe path: preserve it or implement
  an explicit, tested migration.
- Do not accept a protocol-bearing change only because it compiles. Verify compatibility, replay,
  persistence, cross-layer behavior, and the matching flow-trace update.
- Keep formatting and other mechanical findings in automated checks. Report only consequential,
  actionable review findings.
