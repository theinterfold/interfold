// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C3 fold: one inner ZK `ShareEncryption` proof per step, chained with the previous
//! accumulator (`c3_fold` non-ZK proof, or a fixed genesis proof from `c3_fold_kernel` on the first
//! step; see `crates/zk-prover` and `c3_fold_kernel`).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;

/// Total slots: one per (party, threshold-modulus) pair.
pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

/// Total public fields for a `c3_fold` proof: 6 pub parameters + 3*C3_SLOTS (pk, msg, ct).
pub global C3_FOLD_PUBLIC_LEN: u32 = 6 + (3 * C3_SLOTS);

pub global C3_FOLD_PREFIX_LEN: u32 = C3_FOLD_PUBLIC_LEN - (3 * C3_SLOTS);

/// Named indices into the 6-field accumulator prefix (`c3_fold` and `c3_fold_kernel` share this
/// layout; the 3-field-wide per-slot tail starts at `C3_FOLD_PREFIX_LEN`).
pub global ACC_CHILD_VK_IDX: u32 = 0;
pub global ACC_ACC_VK_IDX: u32 = 1;
pub global ACC_IS_FIRST_STEP_IDX: u32 = 2;
pub global ACC_SLOT_INDEX_IDX: u32 = 3;
pub global ACC_EXPECTED_KERNEL_IDX: u32 = 4;
pub global ACC_EXPECTED_FOLD_IDX: u32 = 5;

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

    // Bind every fold step to one canonical child VK: the previous accumulator's child VK hash
    // (public input 0) must equal this step's inner `ShareEncryption` VK hash. This closes the VK
    // substitution attack where an intermediate step is proven under a noncanonical child VK.
    assert(acc_public_inputs[ACC_CHILD_VK_IDX] == inner_key_hash);

    if is_first_step {
        assert(acc_key_hash == expected_kernel_key_hash);
    } else {
        assert(acc_key_hash == expected_fold_key_hash);
        if acc_public_inputs[ACC_IS_FIRST_STEP_IDX] == 1 {
            assert(acc_public_inputs[ACC_EXPECTED_KERNEL_IDX] == expected_kernel_key_hash);
        } else {
            assert(acc_public_inputs[ACC_EXPECTED_FOLD_IDX] == expected_fold_key_hash);
        }
    }

    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    let pk_new = c3_public_inputs[0];
    let msg_new = c3_public_inputs[1];
    let ct_new = c3_public_inputs[4];

    let mut out_pk: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_msg: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_ct: [Field; C3_SLOTS] = [0; C3_SLOTS];

    for i in 0..C3_SLOTS {
        let idx = i as u32;
        if is_first_step {
            if idx == slot_index {
                out_pk[i] = pk_new;
                out_msg[i] = msg_new;
                out_ct[i] = ct_new;
            } else {
                out_pk[i] = 0;
                out_msg[i] = 0;
                out_ct[i] = 0;
            }
        } else {
            let prior_pk = acc_public_inputs[C3_FOLD_PREFIX_LEN + i];
            let prior_msg = acc_public_inputs[C3_FOLD_PREFIX_LEN + C3_SLOTS + i];
            let prior_ct = acc_public_inputs[C3_FOLD_PREFIX_LEN + C3_SLOTS + C3_SLOTS + i];

            if idx == slot_index {
                assert(prior_pk == 0);
                assert(prior_msg == 0);
                assert(prior_ct == 0);
                out_pk[i] = pk_new;
                out_msg[i] = msg_new;
                out_ct[i] = ct_new;
            } else {
                out_pk[i] = prior_pk;
                out_msg[i] = prior_msg;
                out_ct[i] = prior_ct;
            }
        }
    }

    (out_pk, out_msg, out_ct)
}
