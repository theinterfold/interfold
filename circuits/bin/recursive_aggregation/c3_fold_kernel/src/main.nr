// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Same IO as [`c3_fold`](../c3_fold/src/main.nr) but **only** verifies the inner `ShareEncryption`
//! proof. Used to mint a fixed genesis `UltraHonkProof` that bootstraps the real `c3_fold` circuit,
//! which always runs `verify_honk_proof_non_zk` on the accumulator (see `c3_fold`).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

pub global C3_FOLD_PUBLIC_LEN: u32 = 6 + (3 * C3_SLOTS);

fn main(
    inner_vk: UltraHonkVerificationKey,
    inner_proof: UltraHonkZKProof,
    c3_public_inputs: [Field; 5],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C3_FOLD_PUBLIC_LEN],
    inner_key_hash: pub Field,
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    slot_index: pub u32,
    expected_kernel_key_hash: pub Field,
    expected_fold_key_hash: pub Field,
) -> pub ([Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS]) {
    assert(slot_index < C3_SLOTS);

    verify_honk_proof(inner_vk, inner_proof, c3_public_inputs, inner_key_hash);
    assert(c3_public_inputs[2] == (slot_index / L_THRESHOLD) as Field);
    assert(c3_public_inputs[3] == (slot_index % L_THRESHOLD) as Field);

    // Signature parity with `c3_fold`: kernel mints the genesis accumulator, so acc_* is unused.
    let _ = (acc_vk, acc_proof, acc_key_hash, acc_public_inputs, expected_fold_key_hash);

    assert(is_first_step);
    assert(acc_key_hash == expected_kernel_key_hash);

    let pk_new = c3_public_inputs[0];
    let msg_new = c3_public_inputs[1];
    let ct_new = c3_public_inputs[4];

    let mut out_pk: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_msg: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_ct: [Field; C3_SLOTS] = [0; C3_SLOTS];

    for i in 0..C3_SLOTS {
        let idx = i as u32;
        if idx == slot_index {
            out_pk[i] = pk_new;
            out_msg[i] = msg_new;
            out_ct[i] = ct_new;
        } else {
            out_pk[i] = 0;
            out_msg[i] = 0;
            out_ct[i] = 0;
        }
    }

    (out_pk, out_msg, out_ct)
}
