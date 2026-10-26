// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Same IO as [`c6_fold`](../c6_fold/src/main.nr) but **only** verifies its inner
//! `ThresholdShareDecryption` proofs. It proves the chain's first leaves on their own: its proof
//! carries their rows and is the accumulator the first `c6_fold` step verifies (with
//! `is_first_step`, under this circuit's key).

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
};
use lib::configs::default::T;
use lib::math::c6_fold::{assert_c6_domain, C6_FOLD_LEAVES, C6_PUBLIC_LEN, place_c6_leaves};

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

    // Signature parity with `c6_fold`: see `c3_fold_kernel`.
    let _ = (acc_vk, acc_proof, fold_key_hash, kernel_key_hash, acc_public_inputs);

    assert(is_first_step);

    // The first leaf fixes the chain's domain; every later leaf must match it.
    let domain_hi = c6_public_inputs[0][3];
    let domain_lo = c6_public_inputs[0][4];
    assert_c6_domain(c6_public_inputs, domain_hi, domain_lo);

    let (sk, esm, ct, d) = place_c6_leaves(
        [0; T + 1],
        [0; T + 1],
        [0; T + 1],
        [0; T + 1],
        c6_public_inputs,
        slot_indices,
    );
    (domain_hi, domain_lo, sk, esm, ct, d)
}
