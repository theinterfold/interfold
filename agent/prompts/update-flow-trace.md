# Update Flow-Trace — Canonical Procedure

Tool-neutral body for the update-flow-trace command and skill. Tool adapters point here. Edit THIS
file to change the procedure.

Goal: make the `agent/` harness docs agree with the changes on the current branch. If the invoking
prompt names a specific change or area, limit the work to that scope.

## When an update is necessary

Update `agent/` in the same PR when the change makes a documented statement false. Typical causes:

- A contract function signature, event, or state variable changes.
- An actor's message handling or event routing changes.
- A CLI command's behavior or arguments change.
- A ZK circuit or proof pipeline step is added, removed, or reordered.
- A timeout, threshold, or fee formula changes.
- A bug in the "Verified Bugs & Protocol Concerns" table of `agent/flow-trace/00_INDEX.md` is fixed,
  or a new one is found.

A change that keeps every documented statement true needs no doc update. Put `[skip-doc-sync]` in
the commit message if `pnpm check:docs` fails for it.

## Procedure

1. Collect the diff: `git diff origin/main...HEAD` plus tracked, uncommitted changes from
   `git diff HEAD`. Use `git status --short` to find untracked files, and include only the untracked
   files that belong to the requested change.
2. Find the statements that the diff makes false. Search `agent/` for the changed functions, events,
   contracts, actors, and CLI commands. The topic table at the top of `agent/flow-trace/00_INDEX.md`
   maps each protocol phase to its trace file.
3. Edit only those statements:
   - Make surgical edits. Do not rewrite a file for a small change.
   - Keep the step-by-step trace format, with `File:` references to real source paths.
   - If the change spans several trace files, update each of them.
   - Update `00_INDEX.md` only for a file addition, removal, or rename, a change to an end-to-end
     summary or the contract map, or a change to the "Verified Bugs & Protocol Concerns" table (mark
     fixed bugs, add new ones).
4. Also correct any statement that the change makes false in `agent/invariants/`, `agent/CONTEXT.md`
   (commands, terminology, versions), `agent/ARCHITECTURE.md`, or `agent/CRATES_ARCHITECTURE.md`.
5. Run `pnpm check:docs` to confirm that the doc-sync gate passes. Summarize which docs changed and
   why, in one line each.

## Trace file organization

- Files are numbered in protocol lifecycle order (`01_`, `02_`, ...). Each file covers one logical
  phase of the protocol.
- To add a phase, use the next free number and add a row to the topic table in `00_INDEX.md`.
- File names use `SCREAMING_SNAKE_CASE` after the number prefix.
