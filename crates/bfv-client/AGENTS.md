# e3-bfv-client

This is the client-side BFV/commitment boundary shared by native callers and WASM.

- Keep commitment calculations delegated to `e3-zk-witness`; a byte hash is not a SAFE circuit
  commitment. Preserve explicit parameter validation before decoding untrusted keys/ciphertexts.
- Public-key admission compares the decoded key's commitment, not decode/re-encode byte equality:
  fhe.rs normalizes an internal flag during threshold-key decoding.
- Verifiable encryption must return the randomness from the same encryption that produced the
  ciphertext. Never log that randomness or expose it through an ordinary encryption response.
- Plaintext byte helpers use little-endian u64 words and reject partial words; changing this also
  changes runtime/application decoding.

Use the [README tests](README.md#tests). For commitment/witness changes, also exercise the
consumer's real-proof flow; Rust round trips alone do not establish circuit agreement. See
[proof statements](../../docs/architecture/proof-statements.md).
