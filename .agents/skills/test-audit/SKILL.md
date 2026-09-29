---
name: test-audit
description:
  Invoke whenever writing, changing, reviewing, or sweeping tests. Authoring gate for new tests plus
  audit workflow for low-value, implementation-coupled, or duplicative tests and the test-only
  production seams they demand.
---

# Test Audit

Three modes, one value bar. Authoring mode gates every new or changed test at write time. Audit mode
runs focused sweeps of tests that re-assert source, duplicate stronger proof, couple behavior to
implementation, or keep test-only production seams alive. Continue broad audits as separate coherent
follow-up PRs; optimize for confidence, not deletion count. Campaign mode prunes one whole
subsystem's test surface (every test file that one crate, package, or circuit area owns). Run
campaign mode only when the user asks for it, and apply the candidate evidence and edit shape of the
audit workflow to each batch in the campaign.

## Authoring mode

1. Before you add or change a test, answer the four questions of the
   [authoring gate](references/authoring.md#authoring-gate). A missing answer means do not add the
   test yet.
2. Check the test against every [junk pattern](references/value-bar.md#junk-patterns). A match fails
   the gate unless the [retention bar](references/value-bar.md#retention-bar) names the contract
   that the test independently guards.
3. For a bug fix, write one regression test at the owner boundary that fails on the pre-fix code.
   See [bug regressions](references/authoring.md#bug-regressions).

## Audit mode

1. Read the files that the [value bar](references/value-bar.md#value-bar) names before you judge a
   candidate.
2. Run read-only [discovery](references/audit.md#discovery) and hunt for the junk patterns.
3. Record the [candidate evidence](references/audit.md#candidate-evidence) for each candidate, and
   keep the tests that meet the [retention bar](references/value-bar.md#retention-bar).
4. Edit one coherent owner-boundary batch that follows the
   [edit shape](references/audit.md#edit-shape).
5. Complete the [validation](references/audit.md#validation) steps.
6. Follow [landing and continuation](references/audit.md#landing-and-continuation), then report the
   [handoff](references/audit.md#handoff) items.

## References

- [references/authoring.md](references/authoring.md): the authoring gate and the rules for bug
  regression tests.
- [references/value-bar.md](references/value-bar.md): the junk patterns, the value bar, and the
  retention bar that both modes share.
- [references/audit.md](references/audit.md): discovery, candidate evidence, edit shape, validation,
  landing, and handoff.
