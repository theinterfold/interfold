---
name: invariant-review
description:
  Review the current branch diff against agent/invariants/ and flow-trace docs. Use before pushing
  protocol-bearing changes.
---

Launch the `invariant-reviewer` subagent on the current branch (diff vs origin/main plus uncommitted
changes). Relay its findings ordered by severity with `file:line` references. Review-only — do not
fix anything; the user decides what to act on.
