<!-- Keep the PR small and focused. Title and commits: Conventional Commits
     (feat|fix|chore, optional scope, "!" for breaking, description ≤ 72 chars). -->

## What

<!-- One or two sentences: what changes and why. Link the issue if there is one. -->

## Checklist

- [ ] **Verified at the smallest covering scope** — name the command(s) run
      (`cargo test -p e3-<crate>` / layer test / `pnpm test:integration <name>`):
- [ ] **Harness docs** — if this changes contracts, circuits, actor routing, CLI behavior, or any
      formula: the matching `agent/` doc (flow-trace, `agent/invariants/`, architecture) is updated
      in this PR, or a commit carries `[skip-doc-sync]` with a reason.
- [ ] **Invariants** — checked the diff against the `agent/invariants/` section for the touched
      area; nothing in the meta-invariant list (committee ordering, thresholds, proof multiplicity,
      hashing, signatures, witness shape, event identity, replay) changes silently.
- [ ] **Known bugs table** — if this fixes or introduces a protocol concern, the "Verified Bugs &
      Protocol Concerns" table in `agent/flow-trace/00_INDEX.md` is updated.
- [ ] **Breaking?** — if yes: `!` in the commit type, and this PR merges only alongside a breaking
      release.
