// SPDX-License-Identifier: LGPL-3.0-only

//! Disabled publication wrapper: H selected recipient setup proofs and bounded C5.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::synchronized::sync_insecure_64::{H, N_PARTIES};
use lib::core::synchronized::publication::join_publication;
use lib::math::commitments::compute_vk_hash;

fn main(
    setup_vk: UltraHonkVerificationKey,
    setup_proofs: [UltraHonkProof; H],
    setup_public: [[Field; 7 + 2 * H]; H],
    setup_key_hash: Field,
    c5_vk: UltraHonkVerificationKey,
    c5_proof: UltraHonkProof,
    c5_public: [Field; H + 1],
    expected_tree_hash: pub Field,
    c5_key_hash: pub Field,
    setup_binding: pub [Field; 2],
    dealer_ids: pub [u32; H],
) -> pub (Field, [Field; H], [Field; H], [Field; H], Field) {
    for row in 0..H {
        verify_honk_proof_non_zk(setup_vk, setup_proofs[row], setup_public[row], setup_key_hash);
    }
    verify_honk_proof_non_zk(c5_vk, c5_proof, c5_public, c5_key_hash);
    assert(
        expected_tree_hash == compute_vk_hash([setup_key_hash, setup_public[0][0]].as_vector()),
        "Unanchored publication descendant VK",
    );
    join_publication::<N_PARTIES, H>(
        setup_binding, dealer_ids, setup_public[0][0], setup_public, c5_public,
    )
}
