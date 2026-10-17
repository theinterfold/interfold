# ZK Rust crates

These libraries and development tools share circuit artifacts with the runtime and deployed
verifiers. Use the owning crate's README for its API and operations.

## Operational context

- Rust refactors do not automatically require new circuit artifacts. Development can use published
  artifacts from a different source revision.
- Do not restamp published artifacts to make a local source hash agree. A release needs its own
  source-bound validation.
- Preset selection changes shared repository files, not just this directory. Coordinate a switch or
  regeneration with other work.
- Do not launch a full circuit matrix or proof campaign as incidental test preparation. Select the
  smallest check that covers the requested change.
- Preserve saved benchmark runs rather than replacing them with later measurements.

## Changes that need a protocol decision

Witness JSON, commitment openings, public-input layouts, and parameter choices are protocol
interfaces. A cleanup is not permission to change them. Tests establish concrete contracts, but they
cannot approve a deployment migration or a different cryptographic assumption.

Search `agent/invariants/02_CRYPTO_CIRCUITS.md` or `04_BUILD_CONFIG.md` when that compatibility
question matters. Read only the relevant sections. Update an existing statement if it becomes false.
