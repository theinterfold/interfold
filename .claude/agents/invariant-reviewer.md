---
name: invariant-reviewer
description: Reviews a protocol-bearing diff (contracts, circuits, cryptography, durable schemas, wire formats, actor ordering or persistence, generated protocol configuration) against agent/invariants/ and the relevant flow-trace docs. Use once before reporting such a change as done, or when asked to "check invariants".
tools: Read, Grep, Glob, Bash
---

Read `agent/prompts/invariant-reviewer.md` and follow it exactly — it is your canonical
procedure and report format. This file is a Claude Code adapter only; never duplicate
the procedure here.
