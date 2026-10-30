// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C4 over its verified limb chain. Verifies the three limb proofs (each with its own key), links
//! them from the fresh aggregate sponge and returns the aggregate commitment the unchunked C4
//! returned. See `lib::core::dkg::share_decryption_chain`.
//!
//! Public: `[expected_commitments[H][L], agg_commitment, key_tree]`, where `key_tree` hashes the
//! three limb keys. The first `H * L + 1` fields are the unchunked C4's public inputs.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::{L_THRESHOLD, N, SHARE_DECRYPTION_BIT_AGG};
use lib::configs::default::H;
use lib::core::dkg::share_decryption_chain::check_limb_chain;
use lib::math::commitments::compute_vk_hash;

fn main(
    expected_commitments: pub [[Field; L_THRESHOLD]; H],
    limb_vks: [UltraHonkVerificationKey; L_THRESHOLD],
    limb_key_hashes: [Field; L_THRESHOLD],
    limb_proofs: [UltraHonkProof; L_THRESHOLD],
    limb_links: [[Field; 2]; L_THRESHOLD],
) -> pub (Field, Field) {
    // One circuit per limb: each limb starts the aggregate sponge at its own position.
    std::static_assert(
        L_THRESHOLD == 3,
        "C4 has one limb circuit for each of three limbs",
    );
    for l in 0..L_THRESHOLD {
        let mut public = [0; H + 2];
        for party_idx in 0..H {
            public[party_idx] = expected_commitments[party_idx][l];
        }
        public[H] = limb_links[l][0];
        public[H + 1] = limb_links[l][1];
        verify_honk_proof_non_zk(limb_vks[l], limb_proofs[l], public, limb_key_hashes[l]);
    }
    let agg_commitment = check_limb_chain::<N, L_THRESHOLD, SHARE_DECRYPTION_BIT_AGG>(limb_links);
    (agg_commitment, compute_vk_hash(limb_key_hashes.as_vector()))
}
