# e3-zk-witness

This crate owns circuit input data, witness preparation, commitments, and canonical Noir JSON
encoding. Each family's `Inputs::compute` takes its configuration from `e3-zk-config`. It does not
construct a second configuration from a preset.

`WitnessError` covers preparation, conversion, and commitment failures. Commitment packing stays
private inside `commitments.rs`. The private `negacyclic` module owns the circuit-specific fold. It
pads zero products to the circuit's `2N-1` shape. `Polynomial::mul` retains its canonical
single-coefficient zero result. Preparation checks polynomial shapes before indexing or pairing
limbs and returns errors for invalid shapes or inexact quotient division.

`Inputs::to_json` returns canonical Noir JSON directly. It preserves field names, polynomial
containers, and unsigned field-element encoding; it does not perform encryption or file writes.

C7 reads only the native ascending prefix selected by `config.max_msg_non_zero_coeffs`. It checks
exactly `T+1` shares, strictly increasing one-based committee IDs, and level-zero contexts. It pads
short messages and computes commitments over that prefix. Noir performs interpolation and CRT
reconstruction. For Small, C7 requires 10 shares, not the 14 shares required by C5.

User-data encryption separates encryption from preparation. `Inputs::compute` takes the exact typed
ciphertext and its `EncryptionIntermediates`; repeated preparation from the same material is
deterministic. `encrypt_and_prepare` encrypts once and returns `(Ciphertext, Inputs)`. BFV-client
and CRISP serialize that ciphertext only at their output boundaries. The ct0 quotient includes the
lifted `e0` correction; ct1 retains its separate `r_ct1` JSON key.

The normal dependency points from witness to config. Config does not depend on witness or samples.
Noir execution and proving belong to `e3-zk-prover`.

`dkg/<circuit>.rs` and `threshold/<circuit>.rs` keep each circuit's data, preparation, and encoding
together. C0 accepts a `PublicKey` directly instead of a one-field data wrapper.

Artificial sample constructors belong to the unpublished `e3-zk-samples` crate. Tests use it
through a dev dependency. The normal dependency graph of this crate excludes sample support.
Production input types stay here.
