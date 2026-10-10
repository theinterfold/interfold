// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5a r53 MERGE tier M2 — anchor + b6 + b10 sub-gates (16-leaf merged chain).
//!
//! The full-structure merge: ONE anchor verify (kernel genesis / lower merge layer)
//! + TWO in-circuit verifies of real production sub-gates (b6 @ [slot1, slot1+6),
//! b10 @ [slot1+6, slot1+16)) + fold 16 slots into the combined 3 x C3_SLOTS array,
//! anchor values passing through for every untouched slot — EXACTLY the sequential-
//! chain final state (equivalence target).
//!
//! Public prefix (4 fields, same convention as c3_fold/b2/b3/b10):
//!   acc_key_hash, is_first_step, slot0 (kernel slot, = anchor slot), slot1 (b6 start).
//!
//! Soundness (per slot):
//!   out[s] = sub6 tail[s]    for s in b6 range     (asserted anchor-zero there)
//!   out[s] = sub10 tail[s]   for s in b10 range    (asserted anchor-zero there)
//!   out[s] = acc tail[s]     elsewhere
//! plus assert(!in6 | !in10): the two sub-gates' ranges are disjoint (by construction
//! b10 starts at slot1+B6; asserted in-circuit anyway).
//!
//! Noir beta.26: & | ! (no && / ||).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk,
};
use lib::configs::default::N_PARTIES;
use lib::configs::default::dkg::L_THRESHOLD;

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;
pub global C3_FOLD_PUBLIC_LEN: u32 = 4 + (3 * C3_SLOTS);
pub global C3_FOLD_PREFIX_LEN: u32 = C3_FOLD_PUBLIC_LEN - (3 * C3_SLOTS);
pub global B6: u32 = 6;
pub global B10: u32 = 10;

fn main(
    vk6: UltraHonkVerificationKey,
    proof6: UltraHonkProof,
    public6: [Field; C3_FOLD_PUBLIC_LEN],
    kh6: pub Field,
    vk10: UltraHonkVerificationKey,
    proof10: UltraHonkProof,
    public10: [Field; C3_FOLD_PUBLIC_LEN],
    kh10: pub Field,
    slot1: pub u32,
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C3_FOLD_PUBLIC_LEN],
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    slot0: pub u32,
) -> pub ([Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS]) {
    verify_honk_proof_non_zk(vk6, proof6, public6, kh6);
    verify_honk_proof_non_zk(vk10, proof10, public10, kh10);
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    assert(slot1 + B6 + B10 <= C3_SLOTS);
    let start10: u32 = slot1 + B6;

    let base = C3_FOLD_PREFIX_LEN;
    let mut out_pk: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_msg: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_ct: [Field; C3_SLOTS] = [0; C3_SLOTS];
    for i in 0..C3_SLOTS {
        let idx = i as u32;
        let in6: bool = (idx >= slot1) & (idx < start10);
        let in10: bool = (idx >= start10) & (idx < start10 + B10);
        assert(!in6 | !in10);
        assert(!in6 | (acc_public_inputs[base + idx] == 0));
        assert(!in6 | (acc_public_inputs[base + C3_SLOTS + idx] == 0));
        assert(!in6 | (acc_public_inputs[base + 2 * C3_SLOTS + idx] == 0));
        assert(!in10 | (acc_public_inputs[base + idx] == 0));
        assert(!in10 | (acc_public_inputs[base + C3_SLOTS + idx] == 0));
        assert(!in10 | (acc_public_inputs[base + 2 * C3_SLOTS + idx] == 0));
        if in6 {
            out_pk[i] = public6[base + idx];
            out_msg[i] = public6[base + C3_SLOTS + idx];
            out_ct[i] = public6[base + 2 * C3_SLOTS + idx];
        } else if in10 {
            out_pk[i] = public10[base + idx];
            out_msg[i] = public10[base + C3_SLOTS + idx];
            out_ct[i] = public10[base + 2 * C3_SLOTS + idx];
        } else {
            out_pk[i] = acc_public_inputs[base + idx];
            out_msg[i] = acc_public_inputs[base + C3_SLOTS + idx];
            out_ct[i] = acc_public_inputs[base + 2 * C3_SLOTS + idx];
        }
    }

    (out_pk, out_msg, out_ct)
}