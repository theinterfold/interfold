// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Same IO as [`nodes_fold`](../nodes_fold/src/main.nr) but **only** verifies the inner `node_fold`
//! proof. Used to mint a fixed genesis `UltraHonkProof` that bootstraps the real `nodes_fold`
//! circuit, which always runs `verify_honk_proof_non_zk` on the accumulator (see `nodes_fold`).

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::{H, N_PARTIES};

pub global C2_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);
pub global C2AB_FOLD_PUBLIC_LEN: u32 = 6 + (2 * C2_PUBLIC_LEN);
/// Must match `c3ab_fold::C3AB_FOLD_PUBLIC_LEN` (one C3 slot per party and CRT limb).
pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;
pub global C3AB_FOLD_PUBLIC_LEN: u32 = 2 + 2 + (6 * C3_SLOTS);
pub global C4_PUBLIC_LEN: u32 = (H * L_THRESHOLD) + 1;
pub global C4AB_FOLD_PUBLIC_LEN: u32 = 3 + (2 * C4_PUBLIC_LEN);

/// Must match `node_fold::NODE_FOLD_PUBLIC_LEN`.
pub global NODE_FOLD_PUBLIC_LEN: u32 = 14 + N_PARTIES + (2 * (N_PARTIES + H) * L_THRESHOLD);

/// Same shape as `nodes_fold`: 6 pub parameters + `H` full `node_fold` public rows (flattened).
pub global NODES_FOLD_PUBLIC_LEN: u32 = 6 + (H * NODE_FOLD_PUBLIC_LEN);

fn main(
    inner_vk: UltraHonkVerificationKey,
    inner_proof: UltraHonkProof,
    node_fold_public_inputs: [Field; NODE_FOLD_PUBLIC_LEN],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; NODES_FOLD_PUBLIC_LEN],
    inner_key_hash: pub Field,
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    slot_index: pub u32,
    expected_kernel_key_hash: pub Field,
    expected_fold_key_hash: pub Field,
) -> pub [[Field; NODE_FOLD_PUBLIC_LEN]; H] {
    assert(slot_index < H);

    verify_honk_proof_non_zk(
        inner_vk,
        inner_proof,
        node_fold_public_inputs,
        inner_key_hash,
    );

    // Signature parity with `nodes_fold`: see `c3_fold_kernel`.
    let _ = (acc_vk, acc_proof, acc_key_hash, acc_public_inputs, expected_fold_key_hash);

    assert(is_first_step);
    assert(acc_key_hash == expected_kernel_key_hash);

    let mut out: [[Field; NODE_FOLD_PUBLIC_LEN]; H] = [[0; NODE_FOLD_PUBLIC_LEN]; H];

    for i in 0..H {
        let idx = i as u32;
        if idx == slot_index {
            out[i] = node_fold_public_inputs;
        }
    }

    out
}
