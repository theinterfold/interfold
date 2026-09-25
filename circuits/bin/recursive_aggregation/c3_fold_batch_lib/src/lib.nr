// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5 r9 -- PRODUCTION-FIT batched c3 fold (PoC).
//!
//! Collapses leaf 2..=(1+B) of the recursive c3_fold chain into ONE
//! non-recursive gate. Each recursion gate of `c3_fold` costs = one inner
//! ZK verify (C3 leaf, ~700K) + one full-accumulator NON-ZK verify (~700K),
//! re-paid every step. Batch = B inner ZK verifies over B DISTINCT slots +
//! a ONE-TIME non-ZK verify of the prior anchor accumulator, then the
//! 4 + 3*C3_SLOTS public output of `c3_fold` EXACTLY (same public ABI ->
//! downstream c3ab_fold/node_fold UNCHANGED, VK-rebuild-only deployment).
//!
//! `C3BatchH` = common gate body, parameterized by B (number of inners).
//! B=1: replaces a single c3_fold step (lower-bound figures).
//! B>=2: B-1 leaf verifies per non-ZK accumulator verify, so per covered
//! step the non-ZK ~700K is amortized over B steps: (B-1)/B of that cost
//! removed per step.
//!
//! Emitted public tuple == `c3_fold` return type: ([SLOTS]; [SLOTS]; [SLOTS])
//! with the SAME slot-map fill rule (first step zeroes, later steps copy).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;

/// Same slot count as `c3_fold` (one slot per (party, modulus) pair).
pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

/// Same public length as `c3_fold`: 4 pub params + 3*C3_SLOTS slot array.
pub global C3_FOLD_PUBLIC_LEN: u32 = 4 + (3 * C3_SLOTS);
pub global C3_FOLD_PREFIX_LEN: u32 = C3_FOLD_PUBLIC_LEN - (3 * C3_SLOTS);

/// Inner (C3 leaf) public input length for the ShareEncryption ZK proof.
pub global C3_INNER_PUBLIC_LEN: u32 = 3;

/// One inner proof bundle: (vk, zk proof, 3 public fields).
pub struct C3Inner {
    pub vk: UltraHonkVerificationKey,
    pub proof: UltraHonkZKProof,
    pub c3_public_inputs: [Field; C3_INNER_PUBLIC_LEN],
    pub key_hash: Field,
}

/// Batched c3 fold gate: verify one prior accumulator (non-ZK UltraHonk) and
/// B leaf ZK proofs over B distinct slots; emit the `c3_fold` public output.
///
/// # Invariants (soundness)
/// - `anchor_public` must satisfy the `c3_fold` accumulator layout
///   (4 + 3*C3_SLOTS) with every covered slot = 0 (asserted below);
///   uncovered slots are copied through unchanged.
/// - B slot indices must be in-range and pairwise distinct (asserted below);
///   this is what lets the (1) zero-slot + (2) distinct-index checks replace
///   the per-step recursion that used to enforce "one leaf per step".
/// - `is_first_step` (pub) tells the FILL rule, same as `c3_fold`: the very
///   first batch gate over the kernel anchor maps everything else to zero;
///   later gates map uncovered slots to their prior value.
pub fn c3_batch<let B: u32>(
    inners: [C3Inner; B],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C3_FOLD_PUBLIC_LEN],
    acc_key_hash: Field,
    is_first_step: bool,
    slots: [u32; B],
) -> ([Field; C3_SLOTS], [Field; C3_SLOTS], [Field; C3_SLOTS]) {
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    let mut out_pk: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_msg: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_ct: [Field; C3_SLOTS] = [0; C3_SLOTS];
    // Sanity: covered slots exist and are pairwise distinct; anchor zeros there.
    for i in 0..B {
        let s = slots[i];
        assert(s < C3_SLOTS);
        if !is_first_step {
            let base = C3_FOLD_PREFIX_LEN;
            assert(acc_public_inputs[base + s] == 0);
            assert(acc_public_inputs[base + C3_SLOTS + s] == 0);
            assert(acc_public_inputs[base + C3_SLOTS + C3_SLOTS + s] == 0);
        }
        for j in i + 1..B {
            assert(slots[j] != s);
        }
    }
    // Verify each C3 leaf ZK proof and fill its (covered, zeroed) slot.
    for i in 0..B {
        let s = slots[i];
        verify_honk_proof(
            inners[i].vk,
            inners[i].proof,
            inners[i].c3_public_inputs,
            inners[i].key_hash,
        );
        out_pk[s] = inners[i].c3_public_inputs[0];
        out_msg[s] = inners[i].c3_public_inputs[1];
        out_ct[s] = inners[i].c3_public_inputs[2];
    }
    // Copy uncovered slots: for every slot not filled above, prior value (or 0).
    // Noir: we cannot branch on "was this slot covered" cheaply, so re-derive:
    for i in 0..C3_SLOTS {
        let mut hit: u32 = 0;
        for j in 0..B {
            if slots[j] == i {
                hit = 1;
            }
        }
        if hit == 0 {
            if is_first_step {
                let _ = i;
            } else {
                let base = C3_FOLD_PREFIX_LEN;
                out_pk[i] = acc_public_inputs[base + i];
                out_msg[i] = acc_public_inputs[base + C3_SLOTS + i];
                out_ct[i] = acc_public_inputs[base + C3_SLOTS + C3_SLOTS + i];
            }
        }
    }
    (out_pk, out_msg, out_ct)
}
