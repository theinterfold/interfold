// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C3 fold: `C3_FOLD_LEAVES` inner ZK `ShareEncryption` proofs per step, chained with
//! the previous accumulator: the `c3_fold_kernel` proof of the chain's first leaves on the first
//! step, a `c3_fold` non-ZK proof after that (see `crates/zk/prover` and `c3_fold_kernel`).
//! An empty place has the slot index `C3_SLOTS` and writes nothing (`lib::math::c3_fold`).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::N_PARTIES;
use lib::math::c3_fold::{C3_FOLD_LEAVES, place_leaves};
use lib::math::recursive_vk::predecessor_key_hash;

/// Total slots: one per (party, threshold-modulus) pair.
pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;

/// Three key hashes, `is_first_step`, one slot index per leaf, then three columns of C3 slots.
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

    let acc_key_hash = predecessor_key_hash(
        inner_key_hash,
        fold_key_hash,
        kernel_key_hash,
        is_first_step,
        [acc_public_inputs[0], acc_public_inputs[1], acc_public_inputs[2]],
    );
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    // The predecessor's rows carry forward, whether it is the kernel (which holds the chain's first
    // leaves, so `is_first_step` only selects its key) or an earlier fold. Each new leaf must land
    // in an empty slot.
    let mut prior_pk: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut prior_msg: [Field; C3_SLOTS] = [0; C3_SLOTS];
    let mut prior_ct: [Field; C3_SLOTS] = [0; C3_SLOTS];
    for i in 0..C3_SLOTS {
        prior_pk[i] = acc_public_inputs[C3_FOLD_PREFIX_LEN + i];
        prior_msg[i] = acc_public_inputs[C3_FOLD_PREFIX_LEN + C3_SLOTS + i];
        prior_ct[i] = acc_public_inputs[C3_FOLD_PREFIX_LEN + 2 * C3_SLOTS + i];
    }
    place_leaves(
        prior_pk,
        prior_msg,
        prior_ct,
        c3_public_inputs,
        slot_indices,
    )
}
