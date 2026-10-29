// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The bid proof for the roles 2 and 3 (`share1` and `share2`), the second leaf of the bid tree of
//! the auction type 5.
//!
//! It verifies the user-data encryption proofs of both roles and nothing else. A share is uniform
//! random, and the encryption proof already range-checks its plaintext, so no other constraint
//! applies. The proof is a recursive proof (`noir-recursive-no-zk`): `auction_bid4` verifies it.
//!
//! Public inputs, in order: the two ciphertext commitments, `pk_row0` (the commitment of the
//! encryption key), the key hash of the wrapper circuit, and its two VK chains. They are the public
//! inputs of `auction_bid_masks`.
use auction_bid::{UDE_PUBLIC_LEN, verify_wrapper};
use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey};

fn main(
    user_data_encryption_verification_key: UltraHonkVerificationKey,
    user_data_encryption_proofs: [UltraHonkProof; 2],
    // Per role: ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment
    user_data_encryption_public_inputs: [[Field; UDE_PUBLIC_LEN]; 2],
    ct_commitments: pub [Field; 2],
    pk_row0: pub Field,
    user_data_encryption_key_hash: pub Field,
    ct0_chain: pub Field,
    ct1_chain: pub Field,
) {
    for r in 0..2 {
        // The `k1_commitment` that `verify_wrapper` returns is not needed: a share has no
        // constraint on its plaintext.
        let _ = verify_wrapper(
            user_data_encryption_verification_key,
            user_data_encryption_proofs[r],
            user_data_encryption_public_inputs[r],
            user_data_encryption_key_hash,
            ct_commitments[r],
            pk_row0,
            ct0_chain,
            ct1_chain,
        );
    }
}
