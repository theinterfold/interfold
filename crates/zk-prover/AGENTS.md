# e3-zk-prover

This crate executes proof requests, verification, folding, and artifact installation. Runtime
process success, a valid witness, and a verified cryptographic statement are different results.

- Keep missing VK/process/I/O failures distinct from completed invalid verification; only the latter
  can classify a peer proof as invalid. Retain exact inputs for local retry.
- Seed finalized party slots and request preset/committee before replay. C0 recovery scans
  unresolved durable inputs, including snapshot prefixes and filtered pages, then waits for effects.
- Proof-plan replacement invalidates old correlations; complete signed bundles precede publication.
  C3 multiplicity comes from threshold Shamir rows even when encryption uses the paired DKG preset.
- Use pinned witness serialization/tools and complete recursive VK-tree anchors. A final wrapper
  hash does not bind unanchored descendants; a checksum does not establish circuit/source
  compatibility.
- Installation validates required pairs/manifests before replacement and retains recovery evidence
  on failed rollback. Test-only proof-skip support must never become a production fallback.

[Proof statements](../../docs/architecture/proof-statements.md) and
[artifacts](../../docs/architecture/circuit-artifacts.md) own these contracts. `build.rs` invokes
`scripts/build_fixtures.sh`: a Cargo check can run pnpm install, rebuild Noir circuits, and rewrite
checked-in fixture JSON. For compile-only work use
`E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1 cargo check --locked -p e3-zk-prover --tests`; this skips fixture
preparation, not proof tests, and does not establish that matching artifacts exist.
`pnpm rust:test:proofs` needs prepared matching circuits, nargo, and bb; ordinary ignored tests or
compilation are not proof verification. Circuit-size sweeps must restore compiled artifacts, not
just source selectors.
