// SPDX-License-Identifier: LGPL-3.0-only

//! Disabled per-recipient setup join. This is not the C5/publication wrapper.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::synchronized::sync_insecure_64::{H, L_THRESHOLD, N_PARTIES};
use lib::core::synchronized::provenance::join_recipient;
use lib::math::commitments::compute_vk_hash;

global C2_LEN: u32 = 5 + N_PARTIES * L_THRESHOLD;
global C4_LEN: u32 = 6 + H + H * L_THRESHOLD;
global NODE_LEN: u32 = 6 + N_PARTIES + 2 * N_PARTIES * L_THRESHOLD;

fn main(
    c0_vk: UltraHonkVerificationKey,
    c0_proof: UltraHonkZKProof,
    c0_public: [Field; 1],
    c2_vk: UltraHonkVerificationKey,
    c2_proof: UltraHonkZKProof,
    c2_public: [Field; C2_LEN],
    c4_vk: UltraHonkVerificationKey,
    c4_proof: UltraHonkZKProof,
    c4_public: [Field; C4_LEN],
    node_vk: UltraHonkVerificationKey,
    node_proofs: [UltraHonkProof; H],
    node_public: [[Field; NODE_LEN]; H],
    c0_key_hash: Field,
    c2_key_hash: Field,
    c4_key_hash: Field,
    node_key_hash: Field,
    expected_tree_hash: pub Field,
    setup_binding: pub [Field; 2],
    recipient_id: pub u32,
    dealer_ids: pub [u32; H],
) -> pub ([Field; H], Field, Field) {
    verify_honk_proof(c0_vk, c0_proof, c0_public, c0_key_hash);
    verify_honk_proof(c2_vk, c2_proof, c2_public, c2_key_hash);
    verify_honk_proof(c4_vk, c4_proof, c4_public, c4_key_hash);
    for row in 0..H {
        verify_honk_proof_non_zk(node_vk, node_proofs[row], node_public[row], node_key_hash);
    }
    let (threshold_keys, sk, bundle, node_tree) = join_recipient::<N_PARTIES, L_THRESHOLD, H>(
        setup_binding,
        recipient_id,
        dealer_ids,
        c0_public[0],
        c2_public,
        c4_public,
        node_public,
    );
    let tree = compute_vk_hash([node_key_hash, node_tree, c0_key_hash, c2_key_hash, c4_key_hash]
        .as_vector());
    assert(tree == expected_tree_hash, "Unanchored DKG descendant VK");
    (threshold_keys, sk, bundle)
}
