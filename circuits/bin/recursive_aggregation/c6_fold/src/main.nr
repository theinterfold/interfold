// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C6 fold: one inner ZK `ThresholdShareDecryption` proof per step, chained with the
//! previous accumulator (`c6_fold` non-ZK proof, or a fixed genesis proof from `c6_fold_kernel` on
//! the first step; see `crates/zk-prover` and `c6_fold_kernel`).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::T;
use lib::math::recursive_vk::predecessor_key_hash;

/// One C6 public row: `expected_sk`, `expected_e_sm`, `ct_commitment`,
/// `domain_hi`, `domain_lo`, `d_commitment` (see C6 leaf).
pub global C6_PUBLIC_LEN: u32 = 6;

/// Five public parameters, the common domain limbs, and four columns of
/// `T + 1` party slots each.
pub global C6_FOLD_PUBLIC_LEN: u32 = 7 + (4 * (T + 1));

pub global C6_FOLD_PREFIX_LEN: u32 = C6_FOLD_PUBLIC_LEN - (4 * (T + 1));

fn main(
    inner_vk: UltraHonkVerificationKey,
    inner_proof: UltraHonkZKProof,
    c6_public_inputs: [Field; C6_PUBLIC_LEN],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; C6_FOLD_PUBLIC_LEN],
    inner_key_hash: pub Field,
    fold_key_hash: pub Field,
    kernel_key_hash: pub Field,
    is_first_step: pub bool,
    slot_index: pub u32,
) -> pub (Field, Field, [Field; T + 1], [Field; T + 1], [Field; T + 1], [Field; T + 1]) {
    assert(slot_index < T + 1);

    verify_honk_proof(inner_vk, inner_proof, c6_public_inputs, inner_key_hash);

    let acc_key_hash = predecessor_key_hash(
        inner_key_hash,
        fold_key_hash,
        kernel_key_hash,
        is_first_step,
        [acc_public_inputs[0], acc_public_inputs[1], acc_public_inputs[2]],
    );
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    let sk_new = c6_public_inputs[0];
    let esm_new = c6_public_inputs[1];
    let ct_new = c6_public_inputs[2];
    let domain_hi = c6_public_inputs[3];
    let domain_lo = c6_public_inputs[4];
    let d_new = c6_public_inputs[5];

    if !is_first_step {
        assert(acc_public_inputs[5] == domain_hi);
        assert(acc_public_inputs[6] == domain_lo);
    }

    let mut out_sk: [Field; T + 1] = [0; T + 1];
    let mut out_esm: [Field; T + 1] = [0; T + 1];
    let mut out_ct: [Field; T + 1] = [0; T + 1];
    let mut out_d: [Field; T + 1] = [0; T + 1];

    for i in 0..(T + 1) {
        let idx = i as u32;
        if is_first_step {
            if idx == slot_index {
                out_sk[i] = sk_new;
                out_esm[i] = esm_new;
                out_ct[i] = ct_new;
                out_d[i] = d_new;
            } else {
                out_sk[i] = 0;
                out_esm[i] = 0;
                out_ct[i] = 0;
                out_d[i] = 0;
            }
        } else {
            let prior_sk = acc_public_inputs[C6_FOLD_PREFIX_LEN + i];
            let prior_esm = acc_public_inputs[C6_FOLD_PREFIX_LEN + (T + 1) + i];
            let prior_ct = acc_public_inputs[C6_FOLD_PREFIX_LEN + (2 * (T + 1)) + i];
            let prior_d = acc_public_inputs[C6_FOLD_PREFIX_LEN + (3 * (T + 1)) + i];

            if idx == slot_index {
                assert(prior_sk == 0);
                assert(prior_esm == 0);
                assert(prior_ct == 0);
                assert(prior_d == 0);
                out_sk[i] = sk_new;
                out_esm[i] = esm_new;
                out_ct[i] = ct_new;
                out_d[i] = d_new;
            } else {
                out_sk[i] = prior_sk;
                out_esm[i] = prior_esm;
                out_ct[i] = prior_ct;
                out_d[i] = prior_d;
            }
        }
    }

    (domain_hi, domain_lo, out_sk, out_esm, out_ct, out_d)
}
