// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The offer proof of a negotiation: 3 ciphertexts (`lanes 0..8`, `lanes 8..16`, `mask`). It verifies the
//! `negotiation_offer_lanes` proof (ciphertexts 0 and 1) and the user-data encryption proof of the mask,
//! and proves that the mask has zero sum over the 8 groups of every level.
//!
//! Public inputs, in order: `ct_commitments` (3), `party`, `role`, `levels`, then the returned
//! `pk_commitment` and `vk_anchor`. The program contract supplies the party (the sender or the signer
//! of a relayed offer), its role, the `levels` of the negotiation, the committee key commitment of the
//! E3 and the deployment anchor. A proof built for another party, role, key, number of levels, or with
//! another circuit in any position of the tree, fails verification.
//!
//! A public input is part of the proof transcript, so the proof verifies only for that `party`, and a
//! copy of the proof sent from another address fails. The circuit also constrains `party` to be
//! non-zero, so no compiler pass can treat it as unused. `role` and `levels` are checked in
//! `negotiation_offer_lanes`, whose proof carries them.
//!
//! `vk_anchor` is the hash of the wrapper key hash, the two VK chains and the key hash of the lanes
//! circuit.
use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use interfold_lib::configs::insecure_simd::threshold::{GADGET_DIM, N};
use interfold_lib::math::commitments::compute_vk_hash;
use interfold_lib::math::polynomial::Polynomial;
use negotiation_offer_lib::{
    check_mask, committee_key_commitment, k1_commitment, SLOTS, UDE_PUBLIC_LEN, verify_wrapper,
};

fn main(
    user_data_encryption_verification_key: UltraHonkVerificationKey,
    mask_proof: UltraHonkProof,
    // ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment
    mask_public_inputs: [Field; UDE_PUBLIC_LEN],
    user_data_encryption_key_hash: Field,
    lanes_verification_key: UltraHonkVerificationKey,
    lanes_proof: UltraHonkProof,
    lanes_key_hash: Field,
    ct_commitments: pub [Field; 3],
    party: pub Field,
    role: pub Field,
    levels: pub Field,
    public_key_row_commitments: [Field; GADGET_DIM],
    relinearization_key_commitment: Field,
    mask_k1: Polynomial<N>,
    mask: [Field; SLOTS],
) -> pub (Field, Field) {
    assert(party != 0);
    // The wrapper's `pk_commitment` is the commitment of row 0, the encryption key.
    let pk_row0 = public_key_row_commitments[0];
    let ct0_chain = mask_public_inputs[0];
    let ct1_chain = mask_public_inputs[1];
    let committed = verify_wrapper(
        user_data_encryption_verification_key,
        mask_proof,
        mask_public_inputs,
        user_data_encryption_key_hash,
        ct_commitments[2],
        pk_row0,
        ct0_chain,
        ct1_chain,
    );
    assert(k1_commitment(mask_k1) == committed, "k1 is not the encrypted plaintext");
    check_mask(mask_k1, mask);
    verify_honk_proof_non_zk(
        lanes_verification_key,
        lanes_proof,
        [
            ct_commitments[0],
            ct_commitments[1],
            role,
            levels,
            pk_row0,
            user_data_encryption_key_hash,
            ct0_chain,
            ct1_chain,
        ],
        lanes_key_hash,
    );

    let pk_commitment =
        committee_key_commitment(public_key_row_commitments, relinearization_key_commitment);
    let vk_anchor = compute_vk_hash([
        user_data_encryption_key_hash,
        ct0_chain,
        ct1_chain,
        lanes_key_hash,
    ]
        .as_vector());
    (pk_commitment, vk_anchor)
}
