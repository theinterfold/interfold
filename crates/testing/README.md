# Testing

Shared test infrastructure, the node simulation, and the integration fixture binaries share this
family. Every member is an unpublished package that other crates reach only through
dev-dependencies, or through the system harness's own fixture binaries; none is a production
capability. Each member remains an independently importable package in the root Cargo workspace;
this directory is not a package or nested workspace. Folder names drop the repeated "test", so they
differ from the package names.

- [support](support/README.md) (package `e3-test-support`): seeded RNGs with one mutex per simulated
  node, scoped test tracing, and read-only `bb` discovery. It has no internal-crate dependencies.
- [bfv-support](bfv-support/README.md) (package `e3-bfv-test-support`): artificial BFV ballots and
  their tally, shared by the TrBFV integration suite and the system harness.
- [sim](sim/) (package `e3-sim`): v2 nodes in one process with virtual time, crashes, and network
  delays, each checked against a shadow copy of its machine that never crashes.
- [system](system/README.md) (package `e3-tests`): the `fake_encrypt` fixture binary used by the
  [integration scripts](../../tests/integration), and the ciphernode image's entrypoint test.

## Boundaries

[Fixture ownership](../../docs/architecture/repository-testing.md#fixture-ownership-2325) decides
what is shared here and what stays with its owner. Grouping the directories does not move fixtures:
ZK samples stay in [zk/samples](../zk/samples/README.md), and single-owner fixtures stay private to
their suites (for example `bfv/threshold/tests/common`).

`pnpm check:repository` runs the Cargo containment guard
([`cargo-feature-containment.py`](../../scripts/checks/cargo-feature-containment.py)). It keeps both
support packages unpublished, dev-only, and free of internal dependencies; allows only the system
harness to enable `test-only-skip-proof-aggregation`; rejects production dependencies on `e3-tests`;
and keeps the fixture binaries off the node assembly. A passing test graph does not prove that
containment, because Cargo feature unification can enable test features throughout a workspace test
run.

Simulated networks, deterministic RNGs, and placeholder proofs are not evidence of distributed
behavior or proof validity. The [testing domain](../../docs/architecture/repository-testing.md)
separates native fixture evidence from real-proof and chain runs.

Checkout-relative paths for this family's members start with `crates/testing/`. Use the
[workspace setup](../README.md#setup-and-checks) and each member's checks.
