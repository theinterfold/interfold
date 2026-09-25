---
name: invariant-review
description:
  Review the current branch diff against agent/invariants/ and the flow-trace docs. Use before you
  report a change to contracts, circuits, runtime crates, durable schemas, or build configuration as
  done.
---

Follow `agent/prompts/invariant-reviewer.md` exactly. It is the canonical procedure and report
format.

Run the review in a fresh context that does not share the writer's conversation: a second tool, a
read-only subagent (OpenCode: the `invariant-reviewer` agent in `opencode.json`), or a new session.
If none is available, do the review yourself as a separate step after the change is complete. See
`agent/RULES.md` §Review before you report done.

The review is read-only. Report findings and do not fix them. This file is a wrapper only.
