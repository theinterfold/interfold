// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Same IO as [`c3_fold`](../c3_fold/src/main.nr) but **only** verifies the inner
//! `ShareEncryption` proofs. It proves the chain's first leaves on their own: its proof carries
//! their rows and is the accumulator the first `c3_fold` step verifies (with `is_first_step`,
//! under this circuit's key).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::c3_fold::{C3_FOLD_LEAVES, place_leaves};

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

pub global C3_FOLD_PREFIX_LEN: u32 = 4 + C3_FOLD_LEAVES;
pub global C3_FOLD_PUBLIC_LEN: u32 = C3_FOLD_PREFIX_LEN + (3 * C3_SLOTS);

fn main(
    inner_vk: UltraHonkVerificationKey,
    inner_proofs: [UltraHonkZKProof; C3_FOLD_LEAVES],
    c3_public_inputs: [[Field; 3]; C3_FOLD_LEAVES],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C3_FOLD_PUBLIC_LEN],
    inner_key_hash: pub Field,
    fold_key_hash: pub Field,
    kernel_key_hash: pub Field,
    is_first_step: pub bool,
    slot_indices: pub [u32; C3_FOLD_LEAVES],
) -> pub ([Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS]) {
    for k in 0..C3_FOLD_LEAVES {
        verify_honk_proof(
            inner_vk,
            inner_proofs[k],
            c3_public_inputs[k],
            inner_key_hash,
        );
    }

    // Signature parity with `c3_fold`: the kernel starts the chain, so acc_* is unused.
    let _ = (acc_vk, acc_proof, fold_key_hash, kernel_key_hash, acc_public_inputs);

    assert(is_first_step);

    place_leaves(
        [0; C3_SLOTS],
        [0; C3_SLOTS],
        [0; C3_SLOTS],
        c3_public_inputs,
        slot_indices,
    )
}
