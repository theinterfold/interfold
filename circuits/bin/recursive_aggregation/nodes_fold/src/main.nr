// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential fold of `H` per-node `node_fold` proofs (non-ZK), one honest slot per step, chained with
//! the previous `nodes_fold` non-ZK proof, or a fixed genesis proof from `nodes_fold_kernel` on the
//! first step (see `crates/zk-prover` and `nodes_fold_kernel`).

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

/// Same shape as `c6_fold`: 6 pub parameters + `H` full `node_fold` public rows (flattened).
pub global NODES_FOLD_PUBLIC_LEN: u32 = 6 + (H * NODE_FOLD_PUBLIC_LEN);

pub global NODES_FOLD_PARAM_PUBLIC_LEN: u32 = NODES_FOLD_PUBLIC_LEN - (H * NODE_FOLD_PUBLIC_LEN);

/// Named indices into the 6-field accumulator prefix (`nodes_fold` and `nodes_fold_kernel`
/// share this layout; `dkg_aggregator` uses the same offsets).
pub global ACC_CHILD_VK_IDX: u32 = 0;
pub global ACC_ACC_VK_IDX: u32 = 1;
pub global ACC_IS_FIRST_STEP_IDX: u32 = 2;
pub global ACC_SLOT_INDEX_IDX: u32 = 3;
pub global ACC_EXPECTED_KERNEL_IDX: u32 = 4;
pub global ACC_EXPECTED_FOLD_IDX: u32 = 5;

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

    // Bind every fold step to one canonical child VK: the previous accumulator's child VK hash
    // (public input 0) must equal this step's inner `node_fold` VK hash. This closes the VK
    // substitution attack where an intermediate step is proven under a noncanonical child VK.
    assert(acc_public_inputs[ACC_CHILD_VK_IDX] == inner_key_hash);

    if is_first_step {
        assert(acc_key_hash == expected_kernel_key_hash);
    } else {
        assert(acc_key_hash == expected_fold_key_hash);
        if acc_public_inputs[ACC_IS_FIRST_STEP_IDX] == 1 {
            assert(acc_public_inputs[ACC_EXPECTED_KERNEL_IDX] == expected_kernel_key_hash);
        } else {
            assert(acc_public_inputs[ACC_EXPECTED_FOLD_IDX] == expected_fold_key_hash);
        }
    }

    verify_honk_proof_non_zk(
        inner_vk,
        inner_proof,
        node_fold_public_inputs,
        inner_key_hash,
    );

    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public_inputs, acc_key_hash);

    let mut out: [[Field; NODE_FOLD_PUBLIC_LEN]; H] = [[0; NODE_FOLD_PUBLIC_LEN]; H];

    for i in 0..H {
        let idx = i as u32;
        if is_first_step {
            if idx == slot_index {
                out[i] = node_fold_public_inputs;
            }
        } else if idx == slot_index {
            for k in 0..NODE_FOLD_PUBLIC_LEN {
                assert(
                    acc_public_inputs[NODES_FOLD_PARAM_PUBLIC_LEN + i * NODE_FOLD_PUBLIC_LEN + k]
                        == 0,
                );
            }
            out[i] = node_fold_public_inputs;
        } else {
            for k in 0..NODE_FOLD_PUBLIC_LEN {
                out[i][k] =
                    acc_public_inputs[NODES_FOLD_PARAM_PUBLIC_LEN + i * NODE_FOLD_PUBLIC_LEN + k];
            }
        }
    }

    out
}
