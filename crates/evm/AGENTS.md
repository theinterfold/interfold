# Working on Rust EVM integration

Keep contract signatures, wire tuples, events, errors, and typed enum views in `contracts`.
Application delivery belongs in `client`/`indexer`; node ingestion and transaction recovery belong
in `runtime`. Sharing ABI facts does not authorize sharing confirmation, nonce, retry, cursor, or
replay policy. Persisted domain/projection types remain with their owners.

Connection and chain-setting types belong to `config`, not the ABI crate or a node configuration
facade. Their consumers still own runtime validation and delivery policy.

Use the nearest crate's `AGENTS.md` and [README](README.md). There is no nested Cargo workspace.
When moving a crate, update root workspace paths, Docker manifest inputs, fixture includes, and
documentation/blueprint references together. A path change in circuit tooling can change source
identity; preserve artifact provenance rather than restamping a cache.
