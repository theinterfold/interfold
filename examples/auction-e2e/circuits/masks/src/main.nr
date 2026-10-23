// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The bid proof for the roles 2 and 3 (`mask` and `pair_mask`), the second leaf of the bid tree
//! of the auction type 3.
//!
//! It verifies the user-data encryption proofs of both roles. The `k1` of the mask is free: it is
//! uniform random and the encryption proof already range-checks it. The `k1` of the pair mask must
//! be a pair-equal mask of its private `pair_values`. The proof is a recursive proof
//! (`noir-recursive-no-zk`): `auction_bid4` verifies it.
//!
//! Public inputs, in order: the two ciphertext commitments, `pk_row0` (the commitment of the
//! encryption key), the key hash of the wrapper circuit, and its two VK chains.
use auction_bid::{k1_commitment, k1_is_pair_mask, PAIR_UNITS, UDE_PUBLIC_LEN, verify_wrapper};
use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey};
use interfold_lib::configs::insecure_simd::threshold::N;
use interfold_lib::math::polynomial::Polynomial;

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
    pair_mask_k1: Polynomial<N>,
    // The free values of the pair mask: one for each level of each pair of groups.
    pair_values: [Field; PAIR_UNITS],
) {
    for r in 0..2 {
        let committed = verify_wrapper(
            user_data_encryption_verification_key,
            user_data_encryption_proofs[r],
            user_data_encryption_public_inputs[r],
            user_data_encryption_key_hash,
            ct_commitments[r],
            pk_row0,
            ct0_chain,
            ct1_chain,
        );
        if r == 1 {
            assert(k1_commitment(pair_mask_k1) == committed, "k1 is not the encrypted plaintext");
        }
    }
    k1_is_pair_mask(pair_mask_k1, pair_values);
}
