// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunking-comparison branch: verifies `ct1_eval_pk` and `ct1_eval_ct` (both hold raw sensitive
//! witness data, so both are ZK-verified; reused as-is from the witness-group-split branch, since
//! `pk1is`/`ct1is` are never chunked in either approach) and passes their commitments and
//! evaluations through. Checks both used the same `gamma`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::threshold::L;

global LEAF_LEN: u32 = 2 + L;

fn main(
    pk_vk: UltraHonkVerificationKey,
    pk_proof: UltraHonkZKProof,
    pk_public_inputs: [Field; LEAF_LEN],
    pk_key_hash: pub Field,
    ct_vk: UltraHonkVerificationKey,
    ct_proof: UltraHonkZKProof,
    ct_public_inputs: [Field; LEAF_LEN],
    ct_key_hash: pub Field,
) -> pub (Field, Field, [Field; L], Field, [Field; L]) {
    verify_honk_proof(pk_vk, pk_proof, pk_public_inputs, pk_key_hash);
    verify_honk_proof(ct_vk, ct_proof, ct_public_inputs, ct_key_hash);

    assert(pk_public_inputs[0] == ct_public_inputs[0], "gamma mismatch");
    let gamma = pk_public_inputs[0];

    let pk1_commitment = pk_public_inputs[1];
    let mut pk1is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        pk1is_at_gamma[i] = pk_public_inputs[2 + i];
    }

    let ct1_commitment = ct_public_inputs[1];
    let mut ct1is_at_gamma: [Field; L] = [0; L];
    for i in 0..L {
        ct1is_at_gamma[i] = ct_public_inputs[2 + i];
    }

    (gamma, pk1_commitment, pk1is_at_gamma, ct1_commitment, ct1is_at_gamma)
}
