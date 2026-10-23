// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The bid proof for the roles 0 and 1 (`ge` and `gt`), the first leaf of the bid tree.
//!
//! It verifies the user-data encryption proofs of both roles, and proves that their `k1` are the
//! thermometers of the one private bid `b`, which is below `levels`. Both thermometers use the
//! same `b` in this circuit, so no commitment to `b` is needed. The proof is a recursive proof
//! (`noir-recursive-no-zk`): `auction_bid3` and `auction_bid4` verify it.
//!
//! Public inputs, in order: the two ciphertext commitments, `levels`, `pk_row0` (the commitment
//! of the encryption key), the key hash of the wrapper circuit, and its two VK chains.
use auction_bid::{check_thermometers, k1_commitment, UDE_PUBLIC_LEN, verify_wrapper};
use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey};
use interfold_lib::configs::insecure_simd::threshold::N;
use interfold_lib::math::polynomial::Polynomial;

fn main(
    user_data_encryption_verification_key: UltraHonkVerificationKey,
    user_data_encryption_proofs: [UltraHonkProof; 2],
    // Per role: ct0_vk_chain, ct1_vk_chain, pk_commitment, ct_commitment, k1_commitment
    user_data_encryption_public_inputs: [[Field; UDE_PUBLIC_LEN]; 2],
    ct_commitments: pub [Field; 2],
    levels: pub Field,
    pk_row0: pub Field,
    user_data_encryption_key_hash: pub Field,
    ct0_chain: pub Field,
    ct1_chain: pub Field,
    k1s: [Polynomial<N>; 2],
    b: Field,
) {
    check_thermometers(k1s[0], k1s[1], b, levels);
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
        assert(k1_commitment(k1s[r]) == committed, "k1 is not the encrypted plaintext");
    }
}
