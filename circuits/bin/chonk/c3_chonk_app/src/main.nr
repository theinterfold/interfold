// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chonk app for C3: verifies `C3_CHONK_LEAVES` C3 proofs and writes their rows, then the C3 leaf
//! key hash. An empty place has the slot index `C3_SLOTS` and writes nothing; its proof position
//! repeats a real leaf. See `lib::math::chonk`.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::c3_fold::place_leaves;
use lib::math::chonk::C3_CHONK_LEAVES;

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

fn main(
    leaf_vk: UltraHonkVerificationKey,
    leaf_key_hash: Field,
    proofs: [UltraHonkZKProof; C3_CHONK_LEAVES],
    c3_public_inputs: [[Field; 3]; C3_CHONK_LEAVES],
    slot_indices: [u32; C3_CHONK_LEAVES],
) -> return_data [Field; 3 * C3_SLOTS + 1] {
    for k in 0..C3_CHONK_LEAVES {
        verify_honk_proof(leaf_vk, proofs[k], c3_public_inputs[k], leaf_key_hash);
    }
    let (pk, msg, ct) = place_leaves(
        [0; C3_SLOTS],
        [0; C3_SLOTS],
        [0; C3_SLOTS],
        c3_public_inputs,
        slot_indices,
    );
    let mut out = [0; 3 * C3_SLOTS + 1];
    for i in 0..C3_SLOTS {
        out[i] = pk[i];
        out[C3_SLOTS + i] = msg[i];
        out[2 * C3_SLOTS + i] = ct[i];
    }
    out[3 * C3_SLOTS] = leaf_key_hash;
    out
}
