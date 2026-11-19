// SPDX-License-Identifier: LGPL-3.0-only

//! Disabled synchronized dealer join: C1, C2 and all non-self C3 rows. No SS smudging lane.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::synchronized::sync_insecure_64::{L_THRESHOLD, N_PARTIES};
use lib::core::synchronized::provenance::join_dealer;
use lib::math::commitments::compute_vk_hash;

global C3_COUNT: u32 = (N_PARTIES - 1) * L_THRESHOLD;
global C2_LEN: u32 = 5 + N_PARTIES * L_THRESHOLD;

fn main(
    c1_vk: UltraHonkVerificationKey,
    c1_proof: UltraHonkZKProof,
    c1_public: [Field; 5],
    c2_vk: UltraHonkVerificationKey,
    c2_proof: UltraHonkZKProof,
    c2_public: [Field; C2_LEN],
    c3_vk: UltraHonkVerificationKey,
    c3_proofs: [UltraHonkZKProof; C3_COUNT],
    c3_public: [[Field; 3]; C3_COUNT],
    c1_key_hash: Field,
    c2_key_hash: Field,
    c3_key_hash: Field,
    setup_binding: pub [Field; 2],
    dealer_id: pub u32,
    ) -> pub (Field, Field, Field, [[Field; L_THRESHOLD]; N_PARTIES], [Field; N_PARTIES], [[Field; L_THRESHOLD]; N_PARTIES]) {
    verify_honk_proof(c1_vk, c1_proof, c1_public, c1_key_hash);
    verify_honk_proof(c2_vk, c2_proof, c2_public, c2_key_hash);
    for slot in 0..C3_COUNT {
        verify_honk_proof(c3_vk, c3_proofs[slot], c3_public[slot], c3_key_hash);
    }
    let (pk, root, messages, keys, ciphertexts) = join_dealer::<N_PARTIES, L_THRESHOLD>(
        setup_binding,
        dealer_id,
        c1_public,
        c2_public,
        c3_public,
    );
    let tree = compute_vk_hash([c1_key_hash, c2_key_hash, c3_key_hash].as_vector());
    (tree, pk, root, messages, keys, ciphertexts)
}
