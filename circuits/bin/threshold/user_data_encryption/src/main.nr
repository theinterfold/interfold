// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Wrapper for one user-data encryption (P3). Verifies the ct0 and ct1 top-level proofs, checks
//! that both legs encrypt under the same randomness `u`, and outputs the aggregate pk and ct
//! commitments.
//!
//! Outputs: `ct0_vk_chain`, `ct1_vk_chain`, `pk_commitment`, `ct_commitment`, `k1_commitment`.
//!
//! Each `*_vk_chain` is `compute_ude_vk_chain(top_level_key_hash, vk_manifest)`, so it binds the
//! verification key of every circuit in that leg. The verifier must compare both values to
//! deployment anchors. A verifier that does not compare them accepts a proof from any circuit
//! with a matching public-input shape at any level of the tree.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::core::threshold::user_data_encryption_chunk::compute_ude_vk_chain;
use lib::math::commitments::{compute_commitment, DS_CIPHERTEXT, DS_PK_AGGREGATION};

fn main(
    // P3: ct0 top-level proof.
    ct0_verification_key: UltraHonkVerificationKey,
    ct0_proof: UltraHonkProof,
    ct0_public_inputs: [Field; 5], // vk_manifest, pk0_commitment, ct0_commitment, k1_root, u_root
    ct0_key_hash: Field,
    // P3: ct1 top-level proof.
    ct1_verification_key: UltraHonkVerificationKey,
    ct1_proof: UltraHonkProof,
    ct1_public_inputs: [Field; 4], // vk_manifest, pk1_commitment, ct1_commitment, u_root
    ct1_key_hash: Field,
) -> pub (Field, Field, Field, Field, Field) {
    verify_honk_proof_non_zk(
        ct0_verification_key,
        ct0_proof,
        ct0_public_inputs,
        ct0_key_hash,
    );
    verify_honk_proof_non_zk(
        ct1_verification_key,
        ct1_proof,
        ct1_public_inputs,
        ct1_key_hash,
    );

    // Both legs must encrypt under the same randomness `u`.
    assert(ct0_public_inputs[4] == ct1_public_inputs[3], "u mismatch between ct0 and ct1");

    let ct_inputs = [ct0_public_inputs[2], ct1_public_inputs[2]].as_vector();
    let ct_commitment = compute_commitment(ct_inputs, DS_CIPHERTEXT);

    // Threshold PK aggregation commitment (pk0 and pk1 limbs).
    let pk_inputs = [ct0_public_inputs[1], ct1_public_inputs[1]].as_vector();
    let pk_commitment = compute_commitment(pk_inputs, DS_PK_AGGREGATION);

    let k1_commitment = ct0_public_inputs[3];

    let ct0_vk_chain = compute_ude_vk_chain(ct0_key_hash, ct0_public_inputs[0]);
    let ct1_vk_chain = compute_ude_vk_chain(ct1_key_hash, ct1_public_inputs[0]);

    (ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment)
}
