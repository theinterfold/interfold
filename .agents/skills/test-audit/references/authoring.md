# Authoring mode

This reference holds the authoring-mode rules of the `test-audit` skill. Apply them to each new or
changed test.

## Authoring gate

Before adding any test, answer four questions; a missing answer means do not add it yet:

1. What observable behavior, invariant, or independent contract does it protect?
2. What credible regression makes it fail?
3. Why does existing coverage not already catch that failure? Each contract has one primary test
   owner at the strongest boundary; another layer needs its own distinct risk, such as a transport
   or lifecycle failure the owner cannot reach. Prefer extending a table-driven case or shared
   fixture over a near-duplicate test; consolidate duplicated setup in the same change.
4. Does it need a production seam (export, flag, wrapper, injection hook) that no production caller
   needs? If yes, move the test to the real boundary instead.

Then check the test against every [junk pattern](value-bar.md#junk-patterns); a match fails the gate
unless the [retention bar](value-bar.md#retention-bar) names the contract it independently guards. A
test that would break under behavior-preserving refactoring is asserting implementation, not
behavior; rewrite it at the owning boundary before landing it.

## Bug regressions

Bug regression tests must fail on the pre-fix code for the intended reason and pass after the
owner-boundary repair. A regression test that never demonstrably failed proves the mock, not the
fix. One regression at the owner boundary covers the bug; do not replay the same scenario at every
layer it crosses.
