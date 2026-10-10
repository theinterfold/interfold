// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5a r53 MERGE tier M1 — anchor + 1 b6 sub-gate (6-leaf batch).
//!
//! Delta over M0 = exactly ONE in-circuit verify of a b6 sub-gate proof
//! (a 5.28M-gate circuit's non-ZK UltraHonk proof) + fold its 6 slots into the
//! combined array. This isolates the per-sub-gate in-circuit verify increment
//! — the load-bearing number the r19 "6.81M / 8-sub merge" figure assumes to be
//! the 0.766M leaf-verify rate (an 8.35M-gate circuit's proof cannot cost a
//! leaf-verify's 0.766M; this tier measures it).
//!
//! Public prefix (4 fields, same convention as c3_fold/b2/b3/b10):
//!   acc_key_hash, is_first_step, slot0 (kernel slot = anchor slot, e.g. 0),
//!   slot1 (sub-gate covered range start).
//!
//! Composition semantics (exact sequential-chain state):
//!   out[s] = sub_public tail[s]   for s in [slot1, slot1+6)   (sub-gate range)
//!   out[s] = acc tail[s]          elsewhere (kernel slot + untouched anchors)
//!   assert: anchor value is zero INSIDE the covered range (the sub-gate must
//!          not overwrite already-filled slots — disjointness).
//!
//! The b6 sub-gate emits c3_fold's public 4+3*C3_SLOTS layout with EXACTLY its
//! covered range non-zero (c3_batch copies its anchor through, anchored at the
//! genesis kernel = zeros there; covered-slot-zero assert at non-first step).
//! So `sub_public tail[s]` is exactly the sequential chain's value at s.
//! Use of & | ! (Noir beta.26 has no && / ||; no short-circuit in circuits).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk,
};
use lib::configs::default::N_PARTIES;
use lib::configs::default::dkg::L_THRESHOLD;

pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;
pub global C3_FOLD_PUBLIC_LEN: u32 = 4 + (3 * C3_SLOTS);
pub global C3_FOLD_PREFIX_LEN: u32 = C3_FOLD_PUBLIC_LEN - (3 * C3_SLOTS);
pub global B6: u32 = 6;

fn main(
    sub_vk: UltraHonkVerificationKey,
    sub_proof: UltraHonkProof,
    sub_public: [Field; C3_FOLD_PUBLIC_LEN],
    sub_key_hash: Field,
    slot1: pub u32,
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C3_FOLD_PUBLIC_LEN],
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    slot0: pub u32,
) -> pub ([Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS]) {
    verify_honk_proof_non_zk(sub_vk, sub_proof, sub_public, sub_key_hash);
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    assert(slot1 + B6 <= C3_SLOTS);

    let base = C3_FOLD_PREFIX_LEN;
    let mut out_pk: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_msg: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_ct: [Field; C3_SLOTS] = [0; C3_SLOTS];
    for i in 0..C3_SLOTS {
        let idx = i as u32;
        let covered: bool = (idx >= slot1) & (idx < slot1 + B6);
        assert(!covered | (acc_public_inputs[base + idx] == 0));
        assert(!covered | (acc_public_inputs[base + C3_SLOTS + idx] == 0));
        assert(!covered | (acc_public_inputs[base + 2 * C3_SLOTS + idx] == 0));
        if covered {
            out_pk[i] = sub_public[base + idx];
            out_msg[i] = sub_public[base + C3_SLOTS + idx];
            out_ct[i] = sub_public[base + 2 * C3_SLOTS + idx];
        } else {
            out_pk[i] = acc_public_inputs[base + idx];
            out_msg[i] = acc_public_inputs[base + C3_SLOTS + idx];
            out_ct[i] = acc_public_inputs[base + 2 * C3_SLOTS + idx];
        }
    }

    (out_pk, out_msg, out_ct)
}