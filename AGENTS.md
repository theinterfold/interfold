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
  `.claude/agents/`, `.claude/commands/`, `.claude/skills/`
- Codex: `AGENTS.md`, `.agents/skills/`, `.codex/config.toml`
- OpenCode: `opencode.json` (permissions, MCP, and `invariant-reviewer`) and `.opencode/skills/`;
  portable skills load from `.agents/skills/`
- Others (Cursor, Cline, Windsurf, Copilot): one-line pointers to `AGENTS.md`

Sync rules: the permission policies in `.claude/settings.json` and `opencode.json` must grant and
deny the same capabilities with each tool's native syntax. Change both together. When adding an
agent or command, put the body in `agent/prompts/` and add a wrapper per tool. Edit the canonical
body, not the wrappers.

## Code Review Rules

- Treat `agent/invariants/00_INDEX.md` and its scoped sections as required review guidance for
  contracts, circuits, actor runtime, durable schemas, cryptography, and build configuration.
  Cite the applicable invariant in each
  finding. Safe path: preserve it or implement an explicit, tested migration.
- Do not accept a protocol-bearing change only because it compiles. Verify compatibility, replay,
  persistence, cross-layer behavior, and the matching flow-trace update.
- Keep formatting and other mechanical findings in automated checks. Report only consequential,
  actionable review findings.
