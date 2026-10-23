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

[Proof statements](../../../docs/architecture/proof-statements.md) and
[artifacts](../../../docs/architecture/circuit-artifacts.md) own these contracts. Read the
[README build warning and compile-only command](README.md#before-running-cargo) before invoking
Cargo: fixture preparation can install dependencies, rebuild circuits, and rewrite tracked JSON. Use
the [README test map](README.md#tests) to distinguish native/fake-process coverage from prepared
real proofs; ordinary ignored tests or compilation are not proof verification. Circuit-size sweeps
must restore compiled artifacts, not just source selectors.
