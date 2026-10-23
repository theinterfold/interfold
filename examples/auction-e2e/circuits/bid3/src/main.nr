// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The bid proof for the auction types 0 to 2: 3 roles (`ge`, `gt`, `mask`). It verifies the
//! `auction_bid_pair` proof (roles 0 and 1) and the user-data encryption proof of the mask. The
//! mask has a free `k1`: it is uniform random and the encryption proof range-checks it.
//!
//! Public inputs, in order: `ct_commitments` (3), `bidder`, `levels`, then the returned
//! `pk_commitment` and `vk_anchor`. The program contract supplies the sender as `bidder`, the
//! `levels` of the auction, the committee key commitment of the E3 and the deployment anchor. A
//! proof built for another sender, another key, another number of levels, or with another circuit
//! in any position of the tree, fails verification.
//!
//! A public input is part of the proof transcript, so the proof verifies only for that `bidder`,
//! and a copy of the proof sent from another address fails. The circuit also constrains `bidder`
//! to be non-zero, so no compiler pass can treat it as unused.
//!
//! `vk_anchor` is the hash of the wrapper key hash, the two VK chains and the key hash of the pair
//! circuit.
use auction_bid::{committee_key_commitment, UDE_PUBLIC_LEN, verify_wrapper};
use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use interfold_lib::configs::insecure_simd::threshold::GADGET_DIM;
use interfold_lib::math::commitments::compute_vk_hash;

fn main(
    user_data_encryption_verification_key: UltraHonkVerificationKey,
    mask_proof: UltraHonkProof,
    // ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment
    mask_public_inputs: [Field; UDE_PUBLIC_LEN],
    user_data_encryption_key_hash: Field,
    pair_verification_key: UltraHonkVerificationKey,
    pair_proof: UltraHonkProof,
    pair_key_hash: Field,
    ct_commitments: pub [Field; 3],
    bidder: pub Field,
    levels: pub Field,
    public_key_row_commitments: [Field; GADGET_DIM],
    relinearization_key_commitment: Field,
) -> pub (Field, Field) {
    assert(bidder != 0);
    // The wrapper's `pk_commitment` is the commitment of row 0, the encryption key.
    let pk_row0 = public_key_row_commitments[0];
    let ct0_chain = mask_public_inputs[0];
    let ct1_chain = mask_public_inputs[1];
    let _ = verify_wrapper(
        user_data_encryption_verification_key,
        mask_proof,
        mask_public_inputs,
        user_data_encryption_key_hash,
        ct_commitments[2],
        pk_row0,
        ct0_chain,
        ct1_chain,
    );
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
