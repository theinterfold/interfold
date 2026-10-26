// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C6 fold: each step verifies `C6_FOLD_LEAVES` inner ZK `ThresholdShareDecryption`
//! proofs (`lib::math::c6_fold`) and the previous accumulator: the `c6_fold_kernel` proof on the
//! first step, a `c6_fold` non-ZK proof after that (see `crates/zk/prover` and `c6_fold_kernel`).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::T;
use lib::math::c6_fold::{assert_c6_domain, C6_FOLD_LEAVES, C6_PUBLIC_LEN, place_c6_leaves};
use lib::math::recursive_vk::predecessor_key_hash;

/// Three key hashes, `is_first_step`, one slot index per leaf, the two domain limbs, then four
/// columns of slots.
pub global C6_FOLD_PREFIX_LEN: u32 = 6 + C6_FOLD_LEAVES;
pub global C6_FOLD_PUBLIC_LEN: u32 = C6_FOLD_PREFIX_LEN + (4 * (T + 1));

fn main(
    inner_vk: UltraHonkVerificationKey,
    inner_proofs: [UltraHonkZKProof; C6_FOLD_LEAVES],
    c6_public_inputs: [[Field; C6_PUBLIC_LEN]; C6_FOLD_LEAVES],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C6_FOLD_PUBLIC_LEN],
    inner_key_hash: pub Field,
    fold_key_hash: pub Field,
    kernel_key_hash: pub Field,
    is_first_step: pub bool,
    slot_indices: pub [u32; C6_FOLD_LEAVES],
) -> pub (Field, Field, [Field; T + 1], [Field; T + 1], [Field; T + 1], [Field; T + 1]) {
    for k in 0..C6_FOLD_LEAVES {
        verify_honk_proof(
            inner_vk,
            inner_proofs[k],
            c6_public_inputs[k],
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

    // The kernel records its leaves' domain too, so every step checks it.
    let domain_hi = acc_public_inputs[4 + C6_FOLD_LEAVES];
    let domain_lo = acc_public_inputs[5 + C6_FOLD_LEAVES];
    assert_c6_domain(c6_public_inputs, domain_hi, domain_lo);

    // The predecessor's rows carry forward, whether it is the kernel (which holds the chain's first
    // leaves, so `is_first_step` only selects its key) or an earlier fold. Each new leaf must land
    // in an empty slot.
    let mut prior_sk: [Field; T + 1] = [0; T + 1];
    let mut prior_esm: [Field; T + 1] = [0; T + 1];
    let mut prior_ct: [Field; T + 1] = [0; T + 1];
    let mut prior_d: [Field; T + 1] = [0; T + 1];
    for i in 0..(T + 1) {
        prior_sk[i] = acc_public_inputs[C6_FOLD_PREFIX_LEN + i];
        prior_esm[i] = acc_public_inputs[C6_FOLD_PREFIX_LEN + (T + 1) + i];
        prior_ct[i] = acc_public_inputs[C6_FOLD_PREFIX_LEN + (2 * (T + 1)) + i];
        prior_d[i] = acc_public_inputs[C6_FOLD_PREFIX_LEN + (3 * (T + 1)) + i];
    }
    let (sk, esm, ct, d) = place_c6_leaves(
        prior_sk,
        prior_esm,
        prior_ct,
        prior_d,
        c6_public_inputs,
        slot_indices,
    );
    (domain_hi, domain_lo, sk, esm, ct, d)
}
