---
description: Review the current branch diff against agent/invariants/ and flow-trace docs
---

Launch the `invariant-reviewer` agent on the current branch (diff vs origin/main plus
uncommitted changes). $ARGUMENTS, if given, narrows the review to specific files or
areas — pass it through to the agent verbatim.

When the agent reports back, relay the findings ordered by severity with `file:line`
references. Do not fix anything — this command is review-only; the user decides what to
act on.
