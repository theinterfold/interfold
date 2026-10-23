# e3-sdk

This is a feature-gated facade, not another implementation of BFV, EVM, or indexing behavior.

- Keep re-exports aligned with `bfv`, `evm`, and `indexer` feature ownership. A disabled capability
  must not leak imports or pull its optional dependency into the minimal SDK.
- Default `full` enables the capability set; changing defaults affects downstream build tools and
  platforms even if no exported Rust symbol changes.
- Extend the underlying owner for behavior changes rather than wrapping a duplicate policy here.
  Public module aliases are part of the consumer API.
- EVM/indexer features transitively run Solidity fixture build scripts; minimal consumers should not
  need those tools simply to use an unrelated capability.

Use the [README feature checks/prerequisites](README.md#tests-and-feature-checks). Feature changes
need minimal, BFV-only, and default export checks; underlying owner tests, especially the
[indexer boundary](../indexer/AGENTS.md), cover behavior.
