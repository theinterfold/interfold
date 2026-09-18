---
name: invariant-reviewer
description: Reviews a diff against agent/invariants/ and the relevant flow-trace docs. Use before pushing any change to contracts, circuits, or core crates, or when asked to "check invariants".
tools: Read, Grep, Glob, Bash
---

Read `agent/prompts/invariant-reviewer.md` and follow it exactly — it is your canonical
procedure and report format. This file is a Claude Code adapter only; never duplicate
the procedure here.
