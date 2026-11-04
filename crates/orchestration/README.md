# Protocol orchestration

The workflows that carry an E3 through its committee protocols share this family: committee
formation, the DKG and decryption-share lifecycle, aggregation and publication, and accusations.
Each member remains an independently importable package in the root Cargo workspace; this directory
is not a package or nested workspace, and the grouping does not merge their state machines.

- [sortition](sortition/Readme.md) (package `e3-sortition`) projects request-time eligibility,
  scores ticket submissions, coordinates committee finalization, and derives this node's party and
  aggregator roles.
- [slashing](slashing/README.md) (package `e3-slashing`) admits accusations, forms votes toward
  quorum, and checks commitment consistency across proofs.

Shared committee parameters and ordered membership stay in [committee](../committee/README.md), and
committee/decryption-domain hashes in [committee hashes](../committee-hash/README.md). The
[ciphernode builder](../ciphernode/builder/README.md) dispatches these workflows into a node; the
[ZK prover](../zk/prover/README.md) and other execution backends remain separate owners.

Checkout-relative paths for this family's members start with `crates/orchestration/`. Use the
[workspace setup](../README.md#setup-and-checks) and each member's checks.
[Committee selection](../../docs/architecture/committee-selection.md),
[DKG](../../docs/architecture/dkg.md), and [slashing](../../docs/architecture/slashing.md) govern
the cross-component rules; [upgrades](../../docs/architecture/upgrades.md) owns compatibility and
rollback decisions.
