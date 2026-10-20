// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// `c3_fold` for the l-BFV path: lbfv/chunking's version, folding `share_encryption_chunked` (whose
// public inputs add `party_idx`, `mod_idx`) with lbfv/chunking's VK-manifest binding. The trBFV
// `c3_fold` uses main's VK-tree binding (#2090); moving this path to it is a follow-up.

//! Sequential C3 fold on the l-BFV path: one inner ZK `ShareEncryption` proof per step, chained with
//! the previous accumulator: the `c3_fold_kernel_chunked` proof of the chain's first leaf on the
//! first step, a `c3_fold_chunked` non-ZK proof after that (see `crates/zk/prover` and
//! `c3_fold_kernel_chunked`).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::recursive_vk::predecessor_key_hash;

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

    // The predecessor must declare the same leaf, fold and kernel keys as this step, on every edge.
    // The terminal fold's declared keys are checked against the canonical ones downstream, so
    // this carries that check back to the genesis: the chain's first accumulator was verified
    // under the canonical kernel key, and no other circuit could prefill rows.
    assert(
        acc_key_hash
            == predecessor_key_hash(
                inner_key_hash,
                expected_fold_key_hash,
                expected_kernel_key_hash,
                is_first_step,
                prior_keys(acc_public_inputs),
            ),
    );

    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    let pk_new = c3_public_inputs[0];
    let msg_new = c3_public_inputs[1];
    let ct_new = c3_public_inputs[4];

    let mut out_pk: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_msg: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut out_ct: [Field; C3_SLOTS] = [0; C3_SLOTS];

    // The predecessor's rows carry forward, whether it is the kernel (which holds the chain's first
    // leaf, already bound to its slot, so `is_first_step` only selects its key) or an earlier fold.
    // The new leaf must land in an empty slot.
    for i in 0..C3_SLOTS {
        let idx = i as u32;
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

    (out_pk, out_msg, out_ct)
}

/// The predecessor's declared leaf, fold and kernel keys, in `predecessor_key_hash` order.
fn prior_keys(acc_public_inputs: [Field; C3_FOLD_PUBLIC_LEN]) -> [Field; 3] {
    [
        acc_public_inputs[ACC_CHILD_VK_IDX],
        acc_public_inputs[ACC_EXPECTED_FOLD_IDX],
        acc_public_inputs[ACC_EXPECTED_KERNEL_IDX],
    ]
}

/// One accumulator prefix: child key, predecessor key, first-step flag, slot, kernel key, fold key.
fn accumulator(
    child: Field,
    kernel: Field,
    fold: Field,
    is_first_step: bool,
) -> [Field; C3_FOLD_PUBLIC_LEN] {
    let mut acc = [0; C3_FOLD_PUBLIC_LEN];
    acc[ACC_CHILD_VK_IDX] = child;
    acc[ACC_IS_FIRST_STEP_IDX] = is_first_step as Field;
    acc[ACC_EXPECTED_KERNEL_IDX] = kernel;
    acc[ACC_EXPECTED_FOLD_IDX] = fold;
    acc
}

// L, F and K are the canonical leaf, fold and kernel keys; X is any other circuit's key.
global L: Field = 11;
global F: Field = 22;
global K: Field = 33;
global X: Field = 44;

#[test]
fn an_honest_chain_selects_the_kernel_then_the_fold_key() {
    // The kernel publishes the canonical keys; the first step verifies it under K.
    let kernel = accumulator(L, K, F, true);
    assert(predecessor_key_hash(L, F, K, true, prior_keys(kernel)) == K);
    // Later steps verify the previous fold under F.
    let fold = accumulator(L, K, F, false);
    assert(predecessor_key_hash(L, F, K, false, prior_keys(fold)) == F);
}

// The audit's sequence: a genesis from circuit X, a first step A declaring kernel X, a step B
// carrying X from A, then a step C that declares the canonical K so the chain ends canonical.
// Before this check, C compared only B's fold key, because B was not a first step.
#[test(should_fail)]
fn a_continuation_step_cannot_replace_the_declared_kernel_key() {
    let b = accumulator(L, X, F, false);
    let _ = predecessor_key_hash(L, F, K, false, prior_keys(b));
}

#[test(should_fail)]
fn a_continuation_after_the_first_step_cannot_replace_the_declared_fold_key() {
    let a = accumulator(L, K, X, true);
    let _ = predecessor_key_hash(L, F, K, false, prior_keys(a));
}

#[test(should_fail)]
fn a_first_step_rejects_a_genesis_that_declares_another_kernel_key() {
    let genesis = accumulator(L, X, F, true);
    let _ = predecessor_key_hash(L, F, K, true, prior_keys(genesis));
}

#[test(should_fail)]
fn a_step_rejects_a_predecessor_with_another_leaf_key() {
    let fold = accumulator(X, K, F, false);
    let _ = predecessor_key_hash(L, F, K, false, prior_keys(fold));
}
