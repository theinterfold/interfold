# BFV encryption

The current FHE capability is BFV and its threshold variant. Its parameter, client,
threshold-calculation, and runtime-adapter crates share this family, and each keeps its own
boundary. Each member remains an independently importable package in the root Cargo workspace; this
directory is not a package or nested workspace. The family is named for the scheme, not `fhe`, while
BFV is the only one. Folder names drop the scheme prefix; package names are unchanged.

- [params](params/README.md) (package `e3-fhe-params`) owns the BFV presets, parameter builders,
  on-chain parameter encoding, and the preset search.
- [client](client/README.md) (package `e3-bfv-client`) encrypts with BFV, computes the
  circuit-compatible public-key and ciphertext commitments, and converts plaintext bytes; it backs
  the WASM API and the SDK's `bfv` feature.
- [threshold](threshold/README.md) (package `e3-trbfv`) performs the threshold-BFV calculations for
  distributed key generation and threshold decryption, with typed request/response payloads.
- [runtime](runtime/README.md) (package `e3-fhe`) adapts fhe.rs for nodes: keyshare generation,
  ciphertext decryption, public-key and plaintext share aggregation, and the FHE dependency of each
  admitted E3 context.

The `params` and `runtime` sources are circuit source-identity inputs: moving or renaming them
changes `SOURCE_HASH` even when every byte is unchanged. See
[circuit artifacts](../../docs/architecture/circuit-artifacts.md) before relocating them.

Local encryption of saved identities and secret shares stays in [crypto](../crypto/README.md).
[Polynomials](../polynomial/README.md), [SAFE](../safe/README.md),
[parity matrices](../parity-matrix/README.md), the [Rust SDK](../sdk/README.md),
[WASM](../wasm/README.md), and the shared test [BFV ballots](../bfv-test-support/README.md) keep
their own roots. The actors that run these calculations belong to
[keyshare](../orchestration/keyshare/README.md) and
[aggregation](../orchestration/aggregator/README.md).

Checkout-relative paths for this family's members start with `crates/bfv/`. Use the
[workspace setup](../README.md#setup-and-checks) and each member's checks.
[Proof statements](../../docs/architecture/proof-statements.md),
[DKG](../../docs/architecture/dkg.md),
[threshold decryption](../../docs/architecture/threshold-decryption.md), and
[Rust client integration](../../docs/architecture/rust-client-integration.md) govern the
cross-component rules; [upgrades](../../docs/architecture/upgrades.md) owns compatibility and
rollback decisions.
