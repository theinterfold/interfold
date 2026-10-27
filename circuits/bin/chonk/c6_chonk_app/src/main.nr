// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chonk app for C6: verifies a decryption's `T + 1` C6 proofs, checks they share one domain and
//! writes their sk, esm, ct and d commitments by slot, then the C6 leaf key hash
//! (`lib::math::chonk`). Every slot is filled: the stack holds the whole chain.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::T;
use lib::math::c6_fold::{assert_c6_domain, C6_PUBLIC_LEN, place_c6_leaves};
use lib::math::chonk::{C3_CHONK_LEAVES, C6_CHONK_DATA_LEN, C6_CHONK_LEAVES};

fn main(
    leaf_vk: UltraHonkVerificationKey,
    leaf_key_hash: Field,
    proofs: [UltraHonkZKProof; C6_CHONK_LEAVES],
    c6_public_inputs: [[Field; C6_PUBLIC_LEN]; C6_CHONK_LEAVES],
    slot_indices: [u32; C6_CHONK_LEAVES],
) -> return_data [Field; C6_CHONK_DATA_LEN + 1] {
    // One stack holds the whole column; bb's ECCVM bound was measured at 24 UltraHonk proofs per
    // stack (`C3_CHONK_LEAVES`), and a larger committee needs a second stack.
    std::static_assert(
        C6_CHONK_LEAVES <= C3_CHONK_LEAVES,
        "T + 1 C6 proofs must fit one Chonk stack",
    );
    for k in 0..C6_CHONK_LEAVES {
        assert(slot_indices[k] < T + 1, "slot index out of range");
        verify_honk_proof(leaf_vk, proofs[k], c6_public_inputs[k], leaf_key_hash);
    }
    let domain_hi = c6_public_inputs[0][3];
    let domain_lo = c6_public_inputs[0][4];
    assert_c6_domain(c6_public_inputs, domain_hi, domain_lo);
    // `T + 1` leaves in distinct slots fill every slot.
    let (sk, esm, ct, d) = place_c6_leaves(
        [0; T + 1],
        [0; T + 1],
        [0; T + 1],
        [0; T + 1],
        c6_public_inputs,
        slot_indices,
    );
    let mut out = [0; C6_CHONK_DATA_LEN + 1];
    out[0] = domain_hi;
    out[1] = domain_lo;
    for i in 0..(T + 1) {
        out[2 + i] = sk[i];
        out[2 + (T + 1) + i] = esm[i];
        out[2 + 2 * (T + 1) + i] = ct[i];
        out[2 + 3 * (T + 1) + i] = d[i];
    }
    out[C6_CHONK_DATA_LEN] = leaf_key_hash;
    out
}
