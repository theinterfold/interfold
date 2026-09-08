// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct1_pk_commit` and `ct1_ct_commit` (both hold raw
//! sensitive witness data, so both are ZK-verified) and passes their commitments through.
//! `pk1is`/`ct1is` are never chunked in either approach - their commitment formula is a protocol
//! invariant (see `ct1_pk_commit`).

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};

fn main(
    pk_vk: UltraHonkVerificationKey,
    pk_proof: UltraHonkZKProof,
    pk_public_inputs: [Field; 1],
    pk_key_hash: pub Field,
    ct_vk: UltraHonkVerificationKey,
    ct_proof: UltraHonkZKProof,
    ct_public_inputs: [Field; 1],
    ct_key_hash: pub Field,
) -> pub (Field, Field) {
    verify_honk_proof(pk_vk, pk_proof, pk_public_inputs, pk_key_hash);
    verify_honk_proof(ct_vk, ct_proof, ct_public_inputs, ct_key_hash);

    (pk_public_inputs[0], ct_public_inputs[0])
}
