# e3-openvm-types

This crate owns the shared guest stream and public journal format, not backend execution.

- Preserve header fixed-integer bincode options, complete-consumption checks, and bounded item
  framing. A length prefix must be rejected before allocating beyond the guest's per-item limit.
- Journal word order, byte order, and address padding must match Solidity receipt decoding. Do not
  serialize the Rust struct generically as a substitute for its explicit ABI bytes.
- Every computation-domain field is part of receipt identity; removing one weakens replay binding
  even if the ciphertext and input-root hashes remain unchanged.
- Inputs stream as header, all ciphertexts, then selected ciphertexts in the prescribed order.
  Changes require host, worker, guest, and contract review together, not a one-sided decoder fix.

Run `cargo test --locked -p e3-openvm-types`. Format changes additionally need host/guest parity and
contract journal coverage from the [OpenVM workflow](../openvm-prover/README.md). A byte round trip
does not establish proof compatibility; see
[encrypted computation](../../docs/architecture/encrypted-computation.md).
