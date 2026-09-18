# Update Flow-Trace — Canonical Procedure

Tool-neutral body for the update-flow-trace command/skill. Tool adapters point here — edit THIS file
to change the procedure.

Goal: bring the `agent/` harness docs in sync with the current branch's changes. If the invoking
prompt names a specific change or area, scope to that.

1. Collect the diff: `git diff origin/main...HEAD` plus tracked, uncommitted changes from
   `git diff HEAD`. Use `git status --short` to identify untracked files and include only untracked
   files that belong to the requested change.
2. Map changed areas to docs using the table in `agent/RULES.md` §Flow-Trace Documentation and the
   harness map. Typical triggers: contract signature/event/state-variable changes, actor
   message-handling or routing changes, CLI behavior changes, circuit/proof pipeline changes,
   timeout/threshold/fee formula changes.
3. Edit only the affected files, following the rules in `agent/RULES.md` §How to update: surgical
   edits, preserve the step-by-step `File:` trace format, no wholesale rewrites. Update
   `00_INDEX.md` only for file add/remove/rename, end-to-end summary changes, contract-map changes,
   or "Verified Bugs & Protocol Concerns" table updates (mark fixed bugs, add new ones).
4. Also check whether the change invalidates a statement in `agent/invariants/`, `agent/CONTEXT.md`
   (commands, terminology, versions), `agent/ARCHITECTURE.md`, or `agent/CRATES_ARCHITECTURE.md` —
   update those too if so.
5. Finish by running `pnpm check:docs` to confirm the doc-sync gate passes, and summarize which docs
   changed and why in one line each.
