# e3-fhe-params

Keep BFV presets, parameter builders, and scalar parameter arithmetic here, not in witness callers.
[README.md](README.md) explains parameter search and API usage.

- Threshold and DKG presets are paired but not interchangeable. Preserve serialized preset order,
  canonical names, and explicit unsupported-value errors; test-only insecure sets are not a
  production fallback.
- The degree-128 insecure variants reuse degree-512 discriminants. Preserve the
  [testnet reset boundary](../../docs/architecture/upgrades.md#insecure-testnet-preset-reset);
  matching serialized discriminants do not prove matching parameter meaning.
- Use exact integer arithmetic in search and residue/width derivation. Narrowing plaintext moduli or
  assuming the FHE primitive's restricted modulus range changes supported scalar calculations.
- CRP derivation is deterministic from its prescribed seed and parameter set. Changing either
  changes distributed key material; do not replace it with local random initialization.
- `abi-encoding` is an optional consumer boundary. Parameter encoding/hash changes need coordinated
  contract, circuit, and client review, not just Rust builder updates.

Use the [README tests](README.md#tests). Preset changes also require the canonical
[circuit build flow](../../scripts/circuits/README.md#circuit-builder) and matching proof artifacts;
search output alone is not a deployed security/compatibility decision.
