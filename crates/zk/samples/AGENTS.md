# e3-zk-samples

This unpublished crate constructs artificial cryptographic material, not live application inputs.
[README.md](README.md) owns sample APIs and dealer/recipient conventions.

- Return production input types from `e3-zk-witness`. Keep static bounds/configuration in
  `e3-zk-config` and preparation/encoding in `e3-zk-witness`; do not copy either into fixtures.
- Preserve distinct threshold and DKG parameters, canonical committee dimensions, per-dealer
  randomness, and exact C7 reconstruction counts. A sampled witness is not proof acceptance.
- Production crates use samples only through dev-dependencies. The unpublished benchmark owner is
  the sole normal-dependency exception. Preserve `pnpm check:repository` containment, including
  aliases and target-specific tables.
- Never log or commit generated private keys, witness secrets, or machine-local artifacts.

Run `cargo test --locked -p e3-zk-samples` for sample construction. Changed preparation needs
`cargo test --locked -p e3-zk-witness`; changed statements also require prepared real-proof
coverage.
