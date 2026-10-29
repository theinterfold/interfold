// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The proof of a mask of the auction type 1, sent by a mask provider. It verifies one user-data
//! encryption proof, and proves that the plaintext of that ciphertext has 128 SIMD slots that are
//! all nonzero mod `t`.
//!
//! The program multiplies the output of the auction by the masks of all providers. A slot that
//! is zero in one mask would set that slot of the output to 0, and the output would not show the
//! result. This proof rules that out. The slot values themselves stay private.
//!
//! Public inputs, in order: `ct_commitment`, `provider`, then the returned `pk_commitment` and
//! `vk_anchor`. The program contract supplies the sender as `provider`, the committee key
//! commitment of the E3 and the deployment anchor. A proof built for another sender, another key,
//! or with another encryption circuit fails verification, and a copy of a proof sent from another
//! address fails as well. The circuit also constrains `provider` to be non-zero, so no compiler
//! pass can treat it as unused.
//!
//! `vk_anchor` is the hash of the wrapper key hash and the two VK chains.
use auction_bid::{
    committee_key_commitment, k1_commitment, k1_is_nonzero_slots, UDE_PUBLIC_LEN, verify_wrapper,
};
use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey};
use interfold_lib::configs::insecure_simd::threshold::{GADGET_DIM, N};
use interfold_lib::math::commitments::compute_vk_hash;
use interfold_lib::math::polynomial::Polynomial;

fn main(
    user_data_encryption_verification_key: UltraHonkVerificationKey,
    user_data_encryption_proof: UltraHonkProof,
    // ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment
    user_data_encryption_public_inputs: [Field; UDE_PUBLIC_LEN],
    user_data_encryption_key_hash: Field,
    ct_commitment: pub Field,
    provider: pub Field,
    public_key_row_commitments: [Field; GADGET_DIM],
    relinearization_key_commitment: Field,
    k1: Polynomial<N>,
    // The 128 slot values, each in `1..=t - 1`.
    slot_values: [Field; N],
) -> pub (Field, Field) {
    assert(provider != 0);
    // The wrapper's `pk_commitment` is the commitment of row 0, the encryption key.
    let pk_row0 = public_key_row_commitments[0];
    let ct0_chain = user_data_encryption_public_inputs[0];
    let ct1_chain = user_data_encryption_public_inputs[1];
    let committed = verify_wrapper(
        user_data_encryption_verification_key,
        user_data_encryption_proof,
        user_data_encryption_public_inputs,
        user_data_encryption_key_hash,
        ct_commitment,
        pk_row0,
        ct0_chain,
        ct1_chain,
    );
    assert(k1_commitment(k1) == committed, "k1 is not the encrypted plaintext");
    k1_is_nonzero_slots(k1, slot_values);

    let pk_commitment =
        committee_key_commitment(public_key_row_commitments, relinearization_key_commitment);
    let vk_anchor =
        compute_vk_hash([user_data_encryption_key_hash, ct0_chain, ct1_chain].as_vector());
    (pk_commitment, vk_anchor)
}
