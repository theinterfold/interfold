// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Fold five ordered l-BFV public-key and terminal RLK generation proof pairs.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};

pub global LBFV_ROWS: u32 = 5;
pub global PK_GENERATION_PUBLIC_LEN: u32 = 6;
pub global RLK_GENERATION_PUBLIC_LEN: u32 = 9;

pub global GENERATION_FOLD_PREFIX_LEN: u32 = 8;
pub global GENERATION_FOLD_PUBLIC_LEN: u32 = GENERATION_FOLD_PREFIX_LEN + 5 + (3 * LBFV_ROWS);

pub global ACC_PK_VK_IDX: u32 = 0;
pub global ACC_RLK_VK_IDX: u32 = 1;
pub global ACC_ACC_VK_IDX: u32 = 2;
pub global ACC_IS_FIRST_STEP_IDX: u32 = 3;
pub global ACC_ROW_INDEX_IDX: u32 = 4;
pub global ACC_EXPECTED_KERNEL_IDX: u32 = 5;
pub global ACC_EXPECTED_FOLD_IDX: u32 = 6;
pub global ACC_TRUSTED_LIMB_VK_IDX: u32 = 7;

pub global ACC_SESSION_HI_IDX: u32 = GENERATION_FOLD_PREFIX_LEN;
pub global ACC_SESSION_LO_IDX: u32 = ACC_SESSION_HI_IDX + 1;
pub global ACC_PARTY_ID_IDX: u32 = ACC_SESSION_HI_IDX + 2;
pub global ACC_SK_COMMITMENT_IDX: u32 = ACC_SESSION_HI_IDX + 3;
pub global ACC_R_COMMITMENT_IDX: u32 = ACC_SESSION_HI_IDX + 4;
pub global ACC_PK_COMMITMENTS_START: u32 = ACC_SESSION_HI_IDX + 5;
pub global ACC_D0_COMMITMENTS_START: u32 = ACC_PK_COMMITMENTS_START + LBFV_ROWS;
pub global ACC_D2_COMMITMENTS_START: u32 = ACC_D0_COMMITMENTS_START + LBFV_ROWS;

fn assert_generation_pair(
    pk_public: [Field; PK_GENERATION_PUBLIC_LEN],
    rlk_public: [Field; RLK_GENERATION_PUBLIC_LEN],
    row_index: u32,
    trusted_limb_key_hash: Field,
) {
    assert(row_index < LBFV_ROWS);
    assert(pk_public[0] == rlk_public[0]);
    assert(pk_public[1] == rlk_public[1]);
    assert(pk_public[2] == rlk_public[2]);
    assert(pk_public[3] == row_index as Field);
    assert(rlk_public[3] == row_index as Field);
    assert(pk_public[4] == rlk_public[4]);
    assert(rlk_public[8] == trusted_limb_key_hash);
}

fn assert_accumulator_identity(
    acc_public: [Field; GENERATION_FOLD_PUBLIC_LEN],
    pk_public: [Field; PK_GENERATION_PUBLIC_LEN],
    rlk_public: [Field; RLK_GENERATION_PUBLIC_LEN],
) {
    assert(acc_public[ACC_SESSION_HI_IDX] == pk_public[0]);
    assert(acc_public[ACC_SESSION_LO_IDX] == pk_public[1]);
    assert(acc_public[ACC_PARTY_ID_IDX] == pk_public[2]);
    assert(acc_public[ACC_SK_COMMITMENT_IDX] == pk_public[4]);
    assert(acc_public[ACC_R_COMMITMENT_IDX] == rlk_public[5]);
}

fn main(
    pk_vk: UltraHonkVerificationKey,
    pk_proof: UltraHonkZKProof,
    pk_public: [Field; PK_GENERATION_PUBLIC_LEN],
    rlk_vk: UltraHonkVerificationKey,
    rlk_proof: UltraHonkZKProof,
    rlk_public: [Field; RLK_GENERATION_PUBLIC_LEN],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public: [Field; GENERATION_FOLD_PUBLIC_LEN],
    pk_key_hash: pub Field,
    rlk_key_hash: pub Field,
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    row_index: pub u32,
    expected_kernel_key_hash: pub Field,
    expected_fold_key_hash: pub Field,
    trusted_limb_key_hash: pub Field,
    ) -> pub (Field, Field, Field, Field, Field, [Field; LBFV_ROWS], [Field; LBFV_ROWS], [Field; LBFV_ROWS]) {
    assert(!is_first_step);
    assert(row_index > 0);
    assert_generation_pair(pk_public, rlk_public, row_index, trusted_limb_key_hash);

    verify_honk_proof(pk_vk, pk_proof, pk_public, pk_key_hash);
    verify_honk_proof(rlk_vk, rlk_proof, rlk_public, rlk_key_hash);
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public, acc_key_hash);

    assert(acc_public[ACC_PK_VK_IDX] == pk_key_hash);
    assert(acc_public[ACC_RLK_VK_IDX] == rlk_key_hash);
    assert(acc_public[ACC_ROW_INDEX_IDX] + 1 == row_index as Field);
    assert(acc_public[ACC_EXPECTED_KERNEL_IDX] == expected_kernel_key_hash);
    assert(acc_public[ACC_EXPECTED_FOLD_IDX] == expected_fold_key_hash);
    assert(acc_public[ACC_TRUSTED_LIMB_VK_IDX] == trusted_limb_key_hash);
    assert_accumulator_identity(acc_public, pk_public, rlk_public);

    if row_index == 1 {
        assert(acc_public[ACC_IS_FIRST_STEP_IDX] == 1);
        assert(acc_key_hash == expected_kernel_key_hash);
    } else {
        assert(acc_public[ACC_IS_FIRST_STEP_IDX] == 0);
        assert(acc_key_hash == expected_fold_key_hash);
    }

    let mut pk_commitments: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    let mut d0_commitments: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    let mut d2_commitments: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    for i in 0..LBFV_ROWS {
        if i < row_index {
            pk_commitments[i] = acc_public[ACC_PK_COMMITMENTS_START + i];
            d0_commitments[i] = acc_public[ACC_D0_COMMITMENTS_START + i];
            d2_commitments[i] = acc_public[ACC_D2_COMMITMENTS_START + i];
        } else if i == row_index {
            assert(acc_public[ACC_PK_COMMITMENTS_START + i] == 0);
            assert(acc_public[ACC_D0_COMMITMENTS_START + i] == 0);
            assert(acc_public[ACC_D2_COMMITMENTS_START + i] == 0);
            pk_commitments[i] = pk_public[5];
            d0_commitments[i] = rlk_public[6];
            d2_commitments[i] = rlk_public[7];
        } else {
            assert(acc_public[ACC_PK_COMMITMENTS_START + i] == 0);
            assert(acc_public[ACC_D0_COMMITMENTS_START + i] == 0);
            assert(acc_public[ACC_D2_COMMITMENTS_START + i] == 0);
        }
    }

    (
        pk_public[0], pk_public[1], pk_public[2], pk_public[4], rlk_public[5], pk_commitments,
        d0_commitments, d2_commitments,
    )
}

#[test]
fn test_generation_pair_accepts_matching_row() {
    assert_generation_pair([1, 2, 3, 4, 5, 6], [1, 2, 3, 4, 5, 7, 8, 9, 10], 4, 10);
}

#[test(should_fail)]
fn test_generation_pair_rejects_mixed_session() {
    assert_generation_pair([1, 2, 3, 4, 5, 6], [11, 2, 3, 4, 5, 7, 8, 9, 10], 4, 10);
}

#[test(should_fail)]
fn test_generation_pair_rejects_wrong_limb_key() {
    assert_generation_pair([1, 2, 3, 4, 5, 6], [1, 2, 3, 4, 5, 7, 8, 9, 10], 4, 11);
}
