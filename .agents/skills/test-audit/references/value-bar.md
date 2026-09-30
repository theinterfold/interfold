# Shared checklists

This reference holds the checklists that both modes of the `test-audit` skill share.

## Junk patterns

The shared checklist for both modes: the authoring gate rejects a new test that matches one, and
audits hunt for existing tests that do.

- assertion-free coverage probes;
- self-comparisons and identity copiers;
- copied fixtures, inventories, manifests, or export lists;
- exact source, import, or string greps;
- private predicate or call-shape tests duplicated at real boundaries;
- duplicate invocations of the same contract;
- provider-local replays of shared helpers;
- tests whose only purpose is preserving test-only exports, globals, or wrappers;
- dead production code whose only callers are tests;
- expected values produced by the helper or renderer under test;
- mocks that implement the asserted behavior, or one identical mock standing in for different APIs;
- fixtures that supply the receipt, admission, or callback ordering the owner should produce, or
  persistence asserted against a store the path never writes;
- capability tests that restate declared flags instead of exercising the delivery or acknowledgement
  the flag promises;
- negative controls that pass for an unrelated reason, such as a denial from a different guard or a
  rejection the production path never reaches;
- names or fixtures that promise more than the input exercises, such as a "retires the window" test
  asserting the window was not cleared.

## Value bar

Tests justify their maintenance cost by protecting behavior, a credible regression, or an
independently meaningful contract. In an audit, an existing test that must change for
behavior-preserving source reorganization is suspect, not automatically deletable; the authoring
gate still rejects new ones.

Before judging a candidate, read the complete test and production owner, its entry point, callers,
callees, sibling implementations, overlapping tests, CI routing, and relevant history. For Rust
tests, search `agent/ARCHITECTURE.md` §Testing Requirements. Search the routed `agent/invariants/`
sections for the audited files and symbols. When the test claims dependency-backed behavior, inspect
the dependency source or types directly.

## Retention bar

Keep a test when it independently enforces a public API, SDK, protocol, config, migration, storage,
security, platform, default, wire-byte, generated cross-language, package, release, or architecture
contract. Also keep:

- call ordering when order is observable behavior;
- regressions with a credible failure mode;
- source inspection when it is the cheapest independent guard: it fails when the contract changes
  (the user-facing key, byte, or path) and survives an identifier-only refactor;
- a retained test that fails on the baseline: treat it as a possible product bug, reproduce it, and
  repair the owner rather than deleting it;
- a test that guards a meta-invariant: committee ordering, threshold meaning, proof multiplicity,
  hashing, signatures, circuit witness shape, event identity, or replay semantics
  (`agent/invariants/00_INDEX.md` §Meta-invariants);
- a test that `agent/invariants/`, `agent/flow-trace/`, or `agent/ARCHITECTURE.md` cites as
  enforcement. To remove one, update the citation in the same change.

Slow alone is not a deletion reason, and a test that resembles implementation may still be the
independent contract: prove otherwise before removing it. Cost does count against duplication. When
a slow test (a ZK proof, a key generation, a chain or network run) repeats a contract that a cheaper
test or a test that already pays that cost guards, remove it or merge its assertions into that test.
When several tests generate the same proof or fixture, generate it once and share it.
