// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential fold of `H` per-node `node_fold` proofs (non-ZK), `NODES_FOLD_LEAVES` per step
//! (`lib::math::nodes_fold`), chained with the previous accumulator: the `nodes_fold_kernel` proof
//! of the first nodes on the first step, a `nodes_fold` non-ZK proof after that (see
//! `crates/zk/prover` and `nodes_fold_kernel`).

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::{H, N_PARTIES};
use lib::math::nodes_fold::{NODES_FOLD_LEAVES, place_nodes};
use lib::math::recursive_vk::predecessor_key_hash;

pub global C2_PUBLIC_LEN: u32 = 1 + (N_PARTIES * L_THRESHOLD);
pub global C2AB_FOLD_PUBLIC_LEN: u32 = 3 + (2 * C2_PUBLIC_LEN);
/// Must match `c3ab_fold::C3AB_FOLD_PUBLIC_LEN` (one C3 slot per party and CRT limb).
pub global C3_SLOTS: u32 = N_PARTIES * L_THRESHOLD;
pub global C3AB_FOLD_PUBLIC_LEN: u32 = 2 + 1 + (6 * C3_SLOTS);
pub global C4_PUBLIC_LEN: u32 = (H * L_THRESHOLD) + 1;
pub global C4AB_FOLD_PUBLIC_LEN: u32 = 3 + (2 * C4_PUBLIC_LEN);

/// Must match `node_fold::NODE_FOLD_PUBLIC_LEN`.
pub global NODE_FOLD_PUBLIC_LEN: u32 = 11 + N_PARTIES + (2 * (N_PARTIES + H) * L_THRESHOLD);

/// Three key hashes, `is_first_step`, one slot index per leaf, and `H` complete `node_fold` public
/// rows.
pub global NODES_FOLD_PUBLIC_LEN: u32 = 4 + NODES_FOLD_LEAVES + (H * NODE_FOLD_PUBLIC_LEN);

pub global NODES_FOLD_PARAM_PUBLIC_LEN: u32 = NODES_FOLD_PUBLIC_LEN - (H * NODE_FOLD_PUBLIC_LEN);

fn main(
    inner_vk: UltraHonkVerificationKey,
    inner_proofs: [UltraHonkProof; NODES_FOLD_LEAVES],
    node_fold_public_inputs: [[Field; NODE_FOLD_PUBLIC_LEN]; NODES_FOLD_LEAVES],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public_inputs: [Field; NODES_FOLD_PUBLIC_LEN],
    inner_key_hash: pub Field,
    fold_key_hash: pub Field,
    kernel_key_hash: pub Field,
    is_first_step: pub bool,
    slot_indices: pub [u32; NODES_FOLD_LEAVES],
) -> pub [[Field; NODE_FOLD_PUBLIC_LEN]; H] {
    for k in 0..NODES_FOLD_LEAVES {
        verify_honk_proof_non_zk(
            inner_vk,
            inner_proofs[k],
            node_fold_public_inputs[k],
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
    // nodes, so `is_first_step` only selects its key) or an earlier fold. Each new node must land in
    // an empty row.
    let mut prior: [[Field; NODE_FOLD_PUBLIC_LEN]; H] = [[0; NODE_FOLD_PUBLIC_LEN]; H];
    for i in 0..H {
        for k in 0..NODE_FOLD_PUBLIC_LEN {
            prior[i][k] =
                acc_public_inputs[NODES_FOLD_PARAM_PUBLIC_LEN + i * NODE_FOLD_PUBLIC_LEN + k];
        }
    }
    place_nodes(prior, node_fold_public_inputs, slot_indices)
}
