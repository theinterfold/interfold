// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The bid proof for the auction type 4: 2 roles (`ge`, `gt`). It verifies the `auction_bid_pair`
//! proof, and nothing else: a bidder of this type sends no mask. The mask providers send the masks.
//!
//! Public inputs, in order: `ct_commitments` (2), `bidder`, `levels`, then the returned
//! `pk_commitment` and `vk_anchor`. See `auction_bid3` for what they bind.
//!
//! `vk_anchor` is the hash of the wrapper key hash, the two VK chains and the key hash of the pair
//! circuit. The two VK chains are witnesses here: the inner proof commits to them, so they cannot
//! differ from the chains the anchor pins.
use auction_bid::committee_key_commitment;
use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use interfold_lib::configs::insecure_simd::threshold::GADGET_DIM;
use interfold_lib::math::commitments::compute_vk_hash;

fn main(
    user_data_encryption_key_hash: Field,
    ct0_chain: Field,
    ct1_chain: Field,
    pair_verification_key: UltraHonkVerificationKey,
    pair_proof: UltraHonkProof,
    pair_key_hash: Field,
    ct_commitments: pub [Field; 2],
    bidder: pub Field,
    levels: pub Field,
    public_key_row_commitments: [Field; GADGET_DIM],
    relinearization_key_commitment: Field,
) -> pub (Field, Field) {
    assert(bidder != 0);
    // The wrappers' `pk_commitment` is the commitment of row 0, the encryption key.
    let pk_row0 = public_key_row_commitments[0];
    verify_honk_proof_non_zk(
        pair_verification_key,
        pair_proof,
        [
            ct_commitments[0],
            ct_commitments[1],
            levels,
            pk_row0,
            user_data_encryption_key_hash,
            ct0_chain,
            ct1_chain,
        ],
        pair_key_hash,
    );

    let pk_commitment =
        committee_key_commitment(public_key_row_commitments, relinearization_key_commitment);
    let vk_anchor = compute_vk_hash(
        [user_data_encryption_key_hash, ct0_chain, ct1_chain, pair_key_hash].as_vector(),
    );
    (pk_commitment, vk_anchor)
}
