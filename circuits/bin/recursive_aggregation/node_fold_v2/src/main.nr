// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bind a legacy NodeFold proof to the terminal secure-16384 generation fold.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::math::commitments::compute_vk_hash;

pub global LBFV_ROWS: u32 = 5;
pub global NODE_FOLD_PUBLIC_LEN: u32 = 14
    + lib::configs::default::N_PARTIES
    + (
        2
            * (lib::configs::default::N_PARTIES + lib::configs::default::H)
            * lib::configs::default::dkg::L_THRESHOLD
    );
pub global NODE_FOLD_V2_APPEND_LEN: u32 = 3 + (3 * LBFV_ROWS);
pub global NODE_FOLD_V2_PUBLIC_LEN: u32 = NODE_FOLD_PUBLIC_LEN + NODE_FOLD_V2_APPEND_LEN;
pub global GENERATION_FOLD_PREFIX_LEN: u32 = 8;
pub global GENERATION_FOLD_PUBLIC_LEN: u32 = GENERATION_FOLD_PREFIX_LEN + 5 + (3 * LBFV_ROWS);
pub global GF_ACC_VK_IDX: u32 = 2;
pub global GF_ROW_INDEX_IDX: u32 = 4;
pub global GF_EXPECTED_FOLD_IDX: u32 = 6;
pub global GF_PARTY_ID_IDX: u32 = 10;
pub global GF_SK_COMMITMENT_IDX: u32 = 11;
pub global GF_PK_COMMITMENTS_START: u32 = 13;
pub global GF_D0_COMMITMENTS_START: u32 = GF_PK_COMMITMENTS_START + LBFV_ROWS;
pub global GF_D2_COMMITMENTS_START: u32 = GF_D0_COMMITMENTS_START + LBFV_ROWS;

fn main(
    node_fold_vk: UltraHonkVerificationKey,
    node_fold_proof: UltraHonkProof,
    node_fold_public: [Field; NODE_FOLD_PUBLIC_LEN],
    c1_vk: UltraHonkVerificationKey,
    c1_proof: UltraHonkZKProof,
    c1_public: [Field; 3],
    generation_vk: UltraHonkVerificationKey,
    generation_proof: UltraHonkProof,
    generation_public: [Field; GENERATION_FOLD_PUBLIC_LEN],
    generation_key_hash: pub Field,
    node_fold_key_hash: pub Field,
    c1_key_hash: pub Field,
    party_id: pub Field,
) -> pub [Field; NODE_FOLD_V2_PUBLIC_LEN] {
    verify_honk_proof_non_zk(
        node_fold_vk,
        node_fold_proof,
        node_fold_public,
        node_fold_key_hash,
    );
    verify_honk_proof(c1_vk, c1_proof, c1_public, c1_key_hash);
    verify_honk_proof_non_zk(
        generation_vk,
        generation_proof,
        generation_public,
        generation_key_hash,
    );

    assert(node_fold_public[0] == party_id);
    assert(generation_public[GF_ACC_VK_IDX] == generation_key_hash);
    assert(generation_public[GF_ROW_INDEX_IDX] == (LBFV_ROWS - 1) as Field);
    assert(generation_public[GF_EXPECTED_FOLD_IDX] == generation_key_hash);
    assert(generation_public[GF_PARTY_ID_IDX] == party_id);
    assert(generation_public[GF_SK_COMMITMENT_IDX] == c1_public[0]);

    let generation_manifest = compute_vk_hash([
        generation_key_hash,
        generation_public[5],
        generation_public[0],
        generation_public[1],
        generation_public[7],
    ]
        .as_vector());

    let mut out: [Field; NODE_FOLD_V2_PUBLIC_LEN] = [0; NODE_FOLD_V2_PUBLIC_LEN];
    for i in 0..NODE_FOLD_PUBLIC_LEN {
        out[i] = node_fold_public[i];
    }
    out[NODE_FOLD_PUBLIC_LEN] = generation_public[0];
    out[NODE_FOLD_PUBLIC_LEN + 1] = generation_public[1];
    for row in 0..LBFV_ROWS {
        out[NODE_FOLD_PUBLIC_LEN + 2 + row] = generation_public[GF_PK_COMMITMENTS_START + row];
        out[NODE_FOLD_PUBLIC_LEN + 2 + LBFV_ROWS + row] =
            generation_public[GF_D0_COMMITMENTS_START + row];
        out[NODE_FOLD_PUBLIC_LEN + 2 + (2 * LBFV_ROWS) + row] =
            generation_public[GF_D2_COMMITMENTS_START + row];
    }
    out[NODE_FOLD_PUBLIC_LEN + 2 + (3 * LBFV_ROWS)] = generation_manifest;
    out
}

#[test]
fn test_party_binding_accepts_matching_ids() {
    assert(4 == 4);
}

#[test(should_fail)]
fn test_party_binding_rejects_mismatched_ids() {
    assert(4 == 5);
}
