// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Create the first-party accumulator for `nodes_fold_v2`.

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

fn assert_valid_party_id(node_public: [Field; NODE_FOLD_V2_PUBLIC_LEN]) {
    let party_id = node_public[NODE_FOLD_V2_PREFIX_LEN] as u32;
    assert(node_public[NODE_FOLD_V2_PREFIX_LEN] == party_id as Field);
    assert(party_id < N_PARTIES);
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
    assert(is_first_step);
    assert(slot_index == 0);
    assert(acc_key_hash == expected_kernel_key_hash);
    assert_valid_party_id(node_public);

    verify_honk_proof_non_zk(inner_vk, inner_proof, node_public, inner_key_hash);
    let _ = (acc_vk, acc_proof, acc_public, expected_fold_key_hash);

    let mut out: [[Field; NODE_FOLD_V2_PUBLIC_LEN]; H] = [[0; NODE_FOLD_V2_PUBLIC_LEN]; H];
    out[0] = node_public;
    out
}

#[test]
fn test_party_id_zero_is_valid() {
    let node_public: [Field; NODE_FOLD_V2_PUBLIC_LEN] = [0; NODE_FOLD_V2_PUBLIC_LEN];
    assert_valid_party_id(node_public);
}

#[test(should_fail)]
fn test_party_id_at_committee_size_is_rejected() {
    let mut node_public: [Field; NODE_FOLD_V2_PUBLIC_LEN] = [0; NODE_FOLD_V2_PUBLIC_LEN];
    node_public[NODE_FOLD_V2_PREFIX_LEN] = N_PARTIES as Field;
    assert_valid_party_id(node_public);
}
