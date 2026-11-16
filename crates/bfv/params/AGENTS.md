# e3-fhe-params

Keep BFV presets, protocol profiles, parameter builders, and scalar parameter arithmetic here, not
in witness callers. This crate owns each profile's admission gate and its configuration identities.
[README.md](README.md) explains parameter search and API usage.

- Threshold and DKG presets are paired but not interchangeable. Preserve serialized preset order,
  canonical names, and explicit unsupported-value errors; test-only insecure sets are not a
  production fallback.
- The degree-64 insecure variants reuse degree-512 discriminants under schema 8. Preserve the
  [testnet reset boundary](../../../docs/architecture/upgrades.md#insecure-testnet-preset-reset);
  matching serialized discriminants do not prove matching parameter meaning.
- Keep the `BfvProfile` variant order and serde names. Event logs and saved state encode the
  variant, and the [runtime layout lock](../../testing/system/tests/layout_lock.rs) pins both.
- Admission is separate from identity. `crypto_config_id` and `from_crypto_config_id` resolve every
  supported profile, including a disabled one, and callers check `ensure_admission_enabled`
  themselves. Disabling a profile keeps its configuration IDs, which recovery still checks for saved
  E3s. Change `admission_enabled` only in the order of
  [Retiring a BFV profile](../../../docs/architecture/upgrades.md#retiring-a-bfv-profile).
- Use exact integer arithmetic in search and residue/width derivation. Narrowing plaintext moduli or
  assuming the FHE primitive's restricted modulus range changes supported scalar calculations.
- CRP derivation is deterministic from its prescribed seed and parameter set. Changing either
  changes distributed key material; do not replace it with local random initialization.
- `abi-encoding` is an optional consumer boundary. Parameter encoding/hash changes need coordinated
  contract, circuit, and client review, not just Rust builder updates.

Use the [README tests](README.md#tests). Preset changes also require the canonical
[circuit build flow](../../../scripts/circuits/README.md#circuit-builder) and matching proof
artifacts; search output alone is not a deployed security/compatibility decision.
