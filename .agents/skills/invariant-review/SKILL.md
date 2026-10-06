---
name: invariant-review
description:
  Review the current branch diff against agent/invariants/ and the flow-trace docs. Use before you
  report a protocol-bearing change as done (contracts, circuits, cryptography, durable schemas, wire
  formats, actor ordering or persistence, or build configuration that generates protocol constants).
---

Follow `agent/prompts/invariant-reviewer.md` exactly. It is the canonical procedure and report
format.

Run one pass in a fresh context when your tool has one: a read-only subagent (OpenCode: the
`invariant-reviewer` agent in `opencode.json`), a second tool, or a new session. If none is
available, do the pass yourself as a separate step after the change is complete. See
`agent/RULES.md` §Review.

The review is read-only. Report findings and do not fix them. This file is a wrapper only.
