# e3-test-support

Unpublished mechanical support for independent Rust test suites: seeded ChaCha RNGs, scoped test
tracing and existing `bb` discovery. There are no internal-crate dependencies, fixture bins,
protocol types, event runtimes, or cryptographic samples here. Consumers use dev-dependencies only.

`derive_shared_rng(base_seed, salt)` preserves wrapping seed addition and creates a separate mutex
for every call. Give each simulated node its own RNG; cloning one `Arc` serializes worker execution.
`create_seed_from_u64` returns seed bytes; the caller supplies its domain wrapper. These RNGs are
deterministic test inputs, not production entropy.

`with_tracing` installs a scoped subscriber, not a process-wide default. `find_bb` only discovers
tools: it neither installs them nor validates matching circuit artifacts. Report tool/artifact skips
separately from completed proof tests.

## Tests

```sh
cargo test --locked -p e3-test-support
```

No Solidity, Noir, node builder or prover preparation is required. Other fixtures live at their
[owner boundaries](../../docs/architecture/repository-testing.md#fixture-ownership-2325): isolated
[event runtimes](../event-system/README.md#test-fixtures), artificial
[ballots](../bfv-test-support/README.md), and complete [system scenarios](../tests/README.md).
