// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Fold exactly `H` `node_fold_v2` proofs in ascending party order.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::L_THRESHOLD;
use lib::configs::default::{H, N_PARTIES};

pub use lib::configs::default::threshold::L as LBFV_ROWS;
pub global NODE_FOLD_PUBLIC_LEN: u32 = 14 + N_PARTIES + (2 * (N_PARTIES + H) * L_THRESHOLD);
pub global NODE_FOLD_V2_APPEND_LEN: u32 = 3 + (3 * LBFV_ROWS);
pub global NODE_FOLD_V2_PREFIX_LEN: u32 = 4;
pub global NODE_FOLD_V2_PUBLIC_LEN: u32 =
    NODE_FOLD_V2_PREFIX_LEN + NODE_FOLD_PUBLIC_LEN + NODE_FOLD_V2_APPEND_LEN;
pub global NODES_FOLD_V2_PREFIX_LEN: u32 = 6;
pub global NODES_FOLD_V2_PUBLIC_LEN: u32 = NODES_FOLD_V2_PREFIX_LEN + (H * NODE_FOLD_V2_PUBLIC_LEN);

pub global ACC_CHILD_VK_IDX: u32 = 0;
pub global ACC_ACC_VK_IDX: u32 = 1;
pub global ACC_IS_FIRST_STEP_IDX: u32 = 2;
pub global ACC_SLOT_INDEX_IDX: u32 = 3;
pub global ACC_EXPECTED_KERNEL_IDX: u32 = 4;
pub global ACC_EXPECTED_FOLD_IDX: u32 = 5;
pub global NF_PARTY_ID_IDX: u32 = NODE_FOLD_V2_PREFIX_LEN;

fn canonical_party_id(node_public: [Field; NODE_FOLD_V2_PUBLIC_LEN]) -> u32 {
    let party_id = node_public[NF_PARTY_ID_IDX] as u32;
    assert(node_public[NF_PARTY_ID_IDX] == party_id as Field);
    assert(party_id < N_PARTIES);
    party_id
}

fn assert_next_party(previous_party_id: u32, party_id: u32) {
    assert(previous_party_id < party_id);
}

fn main(
    inner_vk: UltraHonkVerificationKey,
    inner_proof: UltraHonkProof,
    node_public: [Field; NODE_FOLD_V2_PUBLIC_LEN],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public: [Field; NODES_FOLD_V2_PUBLIC_LEN],
    inner_key_hash: pub Field,
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    slot_index: pub u32,
    expected_kernel_key_hash: pub Field,
    expected_fold_key_hash: pub Field,
) -> pub [[Field; NODE_FOLD_V2_PUBLIC_LEN]; H] {
    assert(!is_first_step);
    assert(slot_index > 0);
    assert(slot_index < H);

    verify_honk_proof_non_zk(inner_vk, inner_proof, node_public, inner_key_hash);
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public, acc_key_hash);

    assert(acc_public[ACC_CHILD_VK_IDX] == inner_key_hash);
    assert(acc_public[ACC_SLOT_INDEX_IDX] + 1 == slot_index as Field);
    assert(acc_public[ACC_EXPECTED_KERNEL_IDX] == expected_kernel_key_hash);
    assert(acc_public[ACC_EXPECTED_FOLD_IDX] == expected_fold_key_hash);

    if slot_index == 1 {
        assert(acc_public[ACC_IS_FIRST_STEP_IDX] == 1);
        assert(acc_key_hash == expected_kernel_key_hash);
    } else {
        assert(acc_public[ACC_IS_FIRST_STEP_IDX] == 0);
        assert(acc_key_hash == expected_fold_key_hash);
    }

    let party_id = canonical_party_id(node_public);
    let previous_row = NODES_FOLD_V2_PREFIX_LEN + (slot_index - 1) * NODE_FOLD_V2_PUBLIC_LEN;
    let previous_party_id = acc_public[previous_row + NF_PARTY_ID_IDX] as u32;
    assert(acc_public[previous_row + NF_PARTY_ID_IDX] == previous_party_id as Field);
    assert_next_party(previous_party_id, party_id);

    let mut out: [[Field; NODE_FOLD_V2_PUBLIC_LEN]; H] = [[0; NODE_FOLD_V2_PUBLIC_LEN]; H];
    for i in 0..H {
        if i < slot_index {
            for field in 0..NODE_FOLD_V2_PUBLIC_LEN {
                out[i][field] =
                    acc_public[NODES_FOLD_V2_PREFIX_LEN + i * NODE_FOLD_V2_PUBLIC_LEN + field];
            }
        } else if i == slot_index {
            for field in 0..NODE_FOLD_V2_PUBLIC_LEN {
                assert(
                    acc_public[NODES_FOLD_V2_PREFIX_LEN + i * NODE_FOLD_V2_PUBLIC_LEN + field] == 0,
                );
            }
            out[i] = node_public;
        } else {
            for field in 0..NODE_FOLD_V2_PUBLIC_LEN {
                assert(
                    acc_public[NODES_FOLD_V2_PREFIX_LEN + i * NODE_FOLD_V2_PUBLIC_LEN + field] == 0,
                );
            }
        }
    }
    out
}

#[test]
fn test_canonical_party_order_accepts_ascending_ids() {
    assert_next_party(2, 4);
}

#[test(should_fail)]
fn test_canonical_party_order_rejects_duplicate_ids() {
    assert_next_party(2, 2);
}

#[test(should_fail)]
fn test_canonical_party_order_rejects_descending_ids() {
    assert_next_party(4, 2);
}
