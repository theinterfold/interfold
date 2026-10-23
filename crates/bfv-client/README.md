# e3-bfv-client

## Purpose

Native client helpers for BFV encryption, circuit-compatible public-key/ciphertext commitments, and
plaintext byte conversion. The same implementation backs the [WASM API](../wasm/README.md) and is
re-exported as `e3_sdk::bfv_client` with the SDK's `bfv` feature.

## Map

| Location                     | Responsibility                                                                 |
| ---------------------------- | ------------------------------------------------------------------------------ |
| [`client.rs`](src/client.rs) | Parameter validation, ordinary/verifiable encryption, and circuit commitments. |
| [`lib.rs`](src/lib.rs)       | Public exports and plaintext/u64/byte conversions.                             |

The client decodes the committee key against the supplied parameters, encodes the plaintext, and
encrypts it. Verifiable encryption uses the circuit computation so the ciphertext and private
witness come from one operation. Commitments are shared with the ZK layer, rather than hashing
whichever key serialization the caller received.

## Encrypting inputs

`client::bfv_encrypt(data, public_key, degree, plaintext_modulus, moduli)` takes serialized
public-key bytes and BFV parameters and returns serialized ciphertext bytes. Parameters must match
the committee key; use [e3-fhe-params](../fhe-params/README.md) rather than copying presets.

For inputs that need an encryption proof, `client::bfv_verifiable_encrypt(...)` returns
`VerifiableEncryptionResult { encrypted_data, circuit_inputs }`. The JSON circuit inputs contain the
encryption witness/randomness for that same ciphertext. This produces witness data, not a proof, and
only supported threshold presets are accepted. Keep that JSON private.

Before trusting a distributed key, call `client::validate_pk_commitment` with its expected on-chain
commitment and parameters. Validation checks the decoded key's circuit commitment, not byte-for-byte
decode/re-encode equality. `compute_pk_commitment`, `compute_ct_commitment`, and
`compute_ct_commitment_with_params` expose the corresponding commitment calculations.
`generate_public_key` is useful for fixtures: it discards the secret key, so it is not a recoverable
client key-generation API or a distributed committee setup.

## Plaintext words

```rust
use e3_bfv_client::{decode_bytes_to_vec_u64, encode_vec_u64_to_bytes};

let words = vec![1_u64, 2, 3];
let bytes = encode_vec_u64_to_bytes(&words);
assert_eq!(decode_bytes_to_vec_u64(&bytes).unwrap(), words);
```

Words are little-endian; decoding rejects a partial eight-byte word.

## Tests

Run `cargo test --locked -p e3-bfv-client` from the root. Inline tests in
[`client.rs`](src/client.rs) cover parameter/key rejection, encryption, and key commitment
admission. The word-conversion snippet above illustrates the separate `lib.rs` helpers; there are no
dedicated inline tests for those helpers today. No node or external prover process is needed.
Real-proof acceptance is described in
[proof statements](../../docs/architecture/proof-statements.md); [AGENTS.md](AGENTS.md) covers
changes to the shared boundary.
