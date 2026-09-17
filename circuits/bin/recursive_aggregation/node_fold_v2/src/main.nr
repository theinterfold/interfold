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
pub global GENERATION_FOLD_PREFIX_LEN: u32 = 9;
pub global GENERATION_FOLD_PUBLIC_LEN: u32 = GENERATION_FOLD_PREFIX_LEN + 5 + (3 * LBFV_ROWS);
pub global GF_PK_VK_IDX: u32 = 0;
pub global GF_RLK_VK_IDX: u32 = 1;
pub global GF_ACC_VK_IDX: u32 = 2;
pub global GF_ROW_INDEX_IDX: u32 = 4;
pub global GF_EXPECTED_KERNEL_IDX: u32 = 5;
pub global GF_EXPECTED_FOLD_IDX: u32 = 6;
pub global GF_TRUSTED_PK_LIMB_VK_IDX: u32 = 7;
pub global GF_TRUSTED_RLK_LIMB_VK_IDX: u32 = 8;
pub global GF_SESSION_HI_IDX: u32 = 9;
pub global GF_SESSION_LO_IDX: u32 = 10;
pub global GF_PARTY_ID_IDX: u32 = 11;
pub global GF_SK_COMMITMENT_IDX: u32 = 12;
pub global GF_R_COMMITMENT_IDX: u32 = GF_SK_COMMITMENT_IDX + 1;
pub global GF_PK_COMMITMENTS_START: u32 = GF_R_COMMITMENT_IDX + 1;
pub global GF_D0_COMMITMENTS_START: u32 = GF_PK_COMMITMENTS_START + LBFV_ROWS;
pub global GF_D2_COMMITMENTS_START: u32 = GF_D0_COMMITMENTS_START + LBFV_ROWS;
pub global LEGACY_NODE_FOLD_C1_KEY_HASH_IDX: u32 = 2;

fn assert_bridge_c1_key_hash(node_fold_public: [Field; NODE_FOLD_PUBLIC_LEN], c1_key_hash: Field) {
    assert(node_fold_public[LEGACY_NODE_FOLD_C1_KEY_HASH_IDX] == c1_key_hash);
}

fn compute_generation_manifest(
    generation_key_hash: Field,
    generation_public: [Field; GENERATION_FOLD_PUBLIC_LEN],
) -> Field {
    compute_vk_hash([
        generation_key_hash,
        generation_public[GF_EXPECTED_KERNEL_IDX],
        generation_public[GF_PK_VK_IDX],
        generation_public[GF_RLK_VK_IDX],
        generation_public[GF_TRUSTED_RLK_LIMB_VK_IDX],
        generation_public[GF_TRUSTED_PK_LIMB_VK_IDX],
    ]
        .as_vector())
}

fn build_public_statement(
    node_fold_public: [Field; NODE_FOLD_PUBLIC_LEN],
    generation_public: [Field; GENERATION_FOLD_PUBLIC_LEN],
    generation_manifest: Field,
) -> [Field; NODE_FOLD_V2_PUBLIC_LEN] {
    let mut out: [Field; NODE_FOLD_V2_PUBLIC_LEN] = [0; NODE_FOLD_V2_PUBLIC_LEN];
    for i in 0..NODE_FOLD_PUBLIC_LEN {
        out[i] = node_fold_public[i];
    }
    out[NODE_FOLD_PUBLIC_LEN] = generation_public[GF_SESSION_HI_IDX];
    out[NODE_FOLD_PUBLIC_LEN + 1] = generation_public[GF_SESSION_LO_IDX];
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
    assert_bridge_c1_key_hash(node_fold_public, c1_key_hash);
    assert(generation_public[GF_ACC_VK_IDX] == generation_key_hash);
    assert(generation_public[GF_ROW_INDEX_IDX] == (LBFV_ROWS - 1) as Field);
    assert(generation_public[GF_EXPECTED_FOLD_IDX] == generation_key_hash);
    assert(generation_public[GF_PARTY_ID_IDX] == party_id);
    assert(generation_public[GF_SK_COMMITMENT_IDX] == c1_public[0]);

    let generation_manifest = compute_generation_manifest(generation_key_hash, generation_public);

    build_public_statement(node_fold_public, generation_public, generation_manifest)
}

#[test]
fn test_public_statement_projects_generation_session() {
    let mut node_public: [Field; NODE_FOLD_PUBLIC_LEN] = [0; NODE_FOLD_PUBLIC_LEN];
    node_public[0] = 41;
    let mut generation_public: [Field; GENERATION_FOLD_PUBLIC_LEN] =
        [0; GENERATION_FOLD_PUBLIC_LEN];
    generation_public[GF_PK_VK_IDX] = 11;
    generation_public[GF_RLK_VK_IDX] = 12;
    generation_public[GF_SESSION_HI_IDX] = 21;
    generation_public[GF_SESSION_LO_IDX] = 22;
    generation_public[GF_R_COMMITMENT_IDX] = 30;
    generation_public[GF_PK_COMMITMENTS_START] = 31;
    generation_public[GF_D2_COMMITMENTS_START + LBFV_ROWS - 1] = 41;

    let out = build_public_statement(node_public, generation_public, 51);
    assert(out[0] == 41);
    assert(out[NODE_FOLD_PUBLIC_LEN] == 21);
    assert(out[NODE_FOLD_PUBLIC_LEN + 1] == 22);
    assert(out[NODE_FOLD_PUBLIC_LEN + 2] == 31);
    assert(out[NODE_FOLD_PUBLIC_LEN + 1 + (3 * LBFV_ROWS)] == 41);
    assert(out[NODE_FOLD_V2_PUBLIC_LEN - 1] == 51);
}

#[test]
fn test_generation_manifest_uses_canonical_limb_vk_order() {
    let mut generation_public: [Field; GENERATION_FOLD_PUBLIC_LEN] =
        [0; GENERATION_FOLD_PUBLIC_LEN];
    generation_public[GF_PK_VK_IDX] = 13;
    generation_public[GF_RLK_VK_IDX] = 14;
    generation_public[GF_EXPECTED_KERNEL_IDX] = 12;
    generation_public[GF_TRUSTED_PK_LIMB_VK_IDX] = 15;
    generation_public[GF_TRUSTED_RLK_LIMB_VK_IDX] = 16;

    let manifest = compute_generation_manifest(11, generation_public);
    let expected = compute_vk_hash([11, 12, 13, 14, 16, 15].as_vector());
    assert(manifest == expected);
}

#[test]
fn test_bridge_c1_key_hash_matches_legacy_node_fold() {
    let mut node_public: [Field; NODE_FOLD_PUBLIC_LEN] = [0; NODE_FOLD_PUBLIC_LEN];
    node_public[LEGACY_NODE_FOLD_C1_KEY_HASH_IDX] = 41;
    assert_bridge_c1_key_hash(node_public, 41);
}

#[test(should_fail)]
fn test_bridge_c1_key_hash_rejects_another_vk() {
    let mut node_public: [Field; NODE_FOLD_PUBLIC_LEN] = [0; NODE_FOLD_PUBLIC_LEN];
    node_public[LEGACY_NODE_FOLD_C1_KEY_HASH_IDX] = 41;
    assert_bridge_c1_key_hash(node_public, 42);
}
