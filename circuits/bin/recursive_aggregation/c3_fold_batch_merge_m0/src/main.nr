// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5a r53 MERGE tier M0 — anchor-only (0 sub-gates).
//!
//! The baseline of the N=19 C3 merge: verify the prior accumulator (non-ZK UltraHonk
//! — the kernel genesis, or a lower merge layer) and re-emit its 3 x C3_SLOTS slot
//! array at c3_fold's EXACT public layout (4-prefix + 3*C3_SLOTS). This is what a
//! zero-sub-gate merge gate costs; M1/M2's delta over M0 isolates the per-sub-gate
//! in-circuit verify increment (the load-bearing number the r19 "6.81M" figure
//! assumes ≈ the 0.766M leaf rate).
//!
//! Soundness: identity map — out = acc slot tail (passthrough). Public prefix
//! (acc_key_hash / is_first_step / slot0 / slot1) is the c3_fold 4-prefix
//! convention (kernel slot + reserved).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk,
};
use lib::configs::default::N_PARTIES;
use lib::configs::default::dkg::L_THRESHOLD;

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;
pub global C3_FOLD_PUBLIC_LEN: u32 = 4 + (3 * C3_SLOTS);
pub global C3_FOLD_PREFIX_LEN: u32 = C3_FOLD_PUBLIC_LEN - (3 * C3_SLOTS);

fn main(
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C3_FOLD_PUBLIC_LEN],
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    slot0: pub u32,
    slot1: pub u32,
) -> pub ([Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS]) {
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    let base = C3_FOLD_PREFIX_LEN;
    let mut out_pk: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_msg: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_ct: [Field; C3_SLOTS] = [0; C3_SLOTS];
    for i in 0..C3_SLOTS {
        let idx = i as u32;
        out_pk[i] = acc_public_inputs[base + idx];
        out_msg[i] = acc_public_inputs[base + C3_SLOTS + idx];
        out_ct[i] = acc_public_inputs[base + 2 * C3_SLOTS + idx];
    }

    (out_pk, out_msg, out_ct)
}