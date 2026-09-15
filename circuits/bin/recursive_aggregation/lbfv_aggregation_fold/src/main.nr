// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Fold five ordered l-BFV public-key and RLK aggregation proof pairs.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};
use lib::configs::default::H;

pub global LBFV_ROWS: u32 = 5;
pub global PK_AGGREGATION_PUBLIC_LEN: u32 = 7 + H;
pub global RLK_AGGREGATION_PUBLIC_LEN: u32 = 8 + (2 * H);

pub global AGGREGATION_FOLD_PREFIX_LEN: u32 = 7;
pub global AGGREGATION_FOLD_PUBLIC_LEN: u32 =
    AGGREGATION_FOLD_PREFIX_LEN + 5 + (3 * LBFV_ROWS * H) + (3 * LBFV_ROWS);

pub global ACC_PK_VK_IDX: u32 = 0;
pub global ACC_RLK_VK_IDX: u32 = 1;
pub global ACC_ACC_VK_IDX: u32 = 2;
pub global ACC_IS_FIRST_STEP_IDX: u32 = 3;
pub global ACC_ROW_INDEX_IDX: u32 = 4;
pub global ACC_EXPECTED_KERNEL_IDX: u32 = 5;
pub global ACC_EXPECTED_FOLD_IDX: u32 = 6;

pub global ACC_SESSION_HI_IDX: u32 = AGGREGATION_FOLD_PREFIX_LEN;
pub global ACC_SESSION_LO_IDX: u32 = ACC_SESSION_HI_IDX + 1;
pub global ACC_AGGREGATOR_ID_IDX: u32 = ACC_SESSION_HI_IDX + 2;
pub global ACC_ACCEPTED_SET_HI_IDX: u32 = ACC_SESSION_HI_IDX + 3;
pub global ACC_ACCEPTED_SET_LO_IDX: u32 = ACC_SESSION_HI_IDX + 4;
pub global ACC_EXPECTED_PK_START: u32 = ACC_SESSION_HI_IDX + 5;
pub global ACC_EXPECTED_D0_START: u32 = ACC_EXPECTED_PK_START + (LBFV_ROWS * H);
pub global ACC_EXPECTED_D2_START: u32 = ACC_EXPECTED_D0_START + (LBFV_ROWS * H);
pub global ACC_AGGREGATE_PK_START: u32 = ACC_EXPECTED_D2_START + (LBFV_ROWS * H);
pub global ACC_AGGREGATE_D0_START: u32 = ACC_AGGREGATE_PK_START + LBFV_ROWS;
pub global ACC_AGGREGATE_D2_START: u32 = ACC_AGGREGATE_D0_START + LBFV_ROWS;

fn assert_aggregation_pair(
    pk_public: [Field; PK_AGGREGATION_PUBLIC_LEN],
    rlk_public: [Field; RLK_AGGREGATION_PUBLIC_LEN],
    row_index: u32,
) {
    assert(row_index < LBFV_ROWS);
    for i in 0..5 {
        assert(pk_public[i] == rlk_public[i]);
    }
    assert(pk_public[5] == row_index as Field);
    assert(rlk_public[5] == row_index as Field);
}

fn assert_accumulator_identity(
    acc_public: [Field; AGGREGATION_FOLD_PUBLIC_LEN],
    pk_public: [Field; PK_AGGREGATION_PUBLIC_LEN],
) {
    assert(acc_public[ACC_SESSION_HI_IDX] == pk_public[0]);
    assert(acc_public[ACC_SESSION_LO_IDX] == pk_public[1]);
    assert(acc_public[ACC_AGGREGATOR_ID_IDX] == pk_public[2]);
    assert(acc_public[ACC_ACCEPTED_SET_HI_IDX] == pk_public[3]);
    assert(acc_public[ACC_ACCEPTED_SET_LO_IDX] == pk_public[4]);
}

fn main(
    pk_vk: UltraHonkVerificationKey,
    pk_proof: UltraHonkZKProof,
    pk_public: [Field; PK_AGGREGATION_PUBLIC_LEN],
    rlk_vk: UltraHonkVerificationKey,
    rlk_proof: UltraHonkZKProof,
    rlk_public: [Field; RLK_AGGREGATION_PUBLIC_LEN],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public: [Field; AGGREGATION_FOLD_PUBLIC_LEN],
    pk_key_hash: pub Field,
    rlk_key_hash: pub Field,
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    row_index: pub u32,
    expected_kernel_key_hash: pub Field,
    expected_fold_key_hash: pub Field,
    ) -> pub (Field, Field, Field, Field, Field, [[Field; H]; LBFV_ROWS], [[Field; H]; LBFV_ROWS], [[Field; H]; LBFV_ROWS], [Field; LBFV_ROWS], [Field; LBFV_ROWS], [Field; LBFV_ROWS]) {
    assert(!is_first_step);
    assert(row_index > 0);
    assert_aggregation_pair(pk_public, rlk_public, row_index);

    verify_honk_proof(pk_vk, pk_proof, pk_public, pk_key_hash);
    verify_honk_proof(rlk_vk, rlk_proof, rlk_public, rlk_key_hash);
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public, acc_key_hash);

    assert(acc_public[ACC_PK_VK_IDX] == pk_key_hash);
    assert(acc_public[ACC_RLK_VK_IDX] == rlk_key_hash);
    assert(acc_public[ACC_ROW_INDEX_IDX] + 1 == row_index as Field);
    assert(acc_public[ACC_EXPECTED_KERNEL_IDX] == expected_kernel_key_hash);
    assert(acc_public[ACC_EXPECTED_FOLD_IDX] == expected_fold_key_hash);
    assert_accumulator_identity(acc_public, pk_public);

    if row_index == 1 {
        assert(acc_public[ACC_IS_FIRST_STEP_IDX] == 1);
        assert(acc_key_hash == expected_kernel_key_hash);
    } else {
        assert(acc_public[ACC_IS_FIRST_STEP_IDX] == 0);
        assert(acc_key_hash == expected_fold_key_hash);
    }

    let mut expected_pk: [[Field; H]; LBFV_ROWS] = [[0; H]; LBFV_ROWS];
    let mut expected_d0: [[Field; H]; LBFV_ROWS] = [[0; H]; LBFV_ROWS];
    let mut expected_d2: [[Field; H]; LBFV_ROWS] = [[0; H]; LBFV_ROWS];
    let mut aggregate_pk: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    let mut aggregate_d0: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    let mut aggregate_d2: [Field; LBFV_ROWS] = [0; LBFV_ROWS];

    for row in 0..LBFV_ROWS {
        if row < row_index {
            for party in 0..H {
                expected_pk[row][party] = acc_public[ACC_EXPECTED_PK_START + row * H + party];
                expected_d0[row][party] = acc_public[ACC_EXPECTED_D0_START + row * H + party];
                expected_d2[row][party] = acc_public[ACC_EXPECTED_D2_START + row * H + party];
            }
            aggregate_pk[row] = acc_public[ACC_AGGREGATE_PK_START + row];
            aggregate_d0[row] = acc_public[ACC_AGGREGATE_D0_START + row];
            aggregate_d2[row] = acc_public[ACC_AGGREGATE_D2_START + row];
        } else if row == row_index {
            for party in 0..H {
                assert(acc_public[ACC_EXPECTED_PK_START + row * H + party] == 0);
                assert(acc_public[ACC_EXPECTED_D0_START + row * H + party] == 0);
                assert(acc_public[ACC_EXPECTED_D2_START + row * H + party] == 0);
                expected_pk[row][party] = pk_public[6 + party];
                expected_d0[row][party] = rlk_public[6 + party];
                expected_d2[row][party] = rlk_public[6 + H + party];
            }
            assert(acc_public[ACC_AGGREGATE_PK_START + row] == 0);
            assert(acc_public[ACC_AGGREGATE_D0_START + row] == 0);
            assert(acc_public[ACC_AGGREGATE_D2_START + row] == 0);
            aggregate_pk[row] = pk_public[6 + H];
            aggregate_d0[row] = rlk_public[6 + (2 * H)];
            aggregate_d2[row] = rlk_public[7 + (2 * H)];
        } else {
            for party in 0..H {
                assert(acc_public[ACC_EXPECTED_PK_START + row * H + party] == 0);
                assert(acc_public[ACC_EXPECTED_D0_START + row * H + party] == 0);
                assert(acc_public[ACC_EXPECTED_D2_START + row * H + party] == 0);
            }
            assert(acc_public[ACC_AGGREGATE_PK_START + row] == 0);
            assert(acc_public[ACC_AGGREGATE_D0_START + row] == 0);
            assert(acc_public[ACC_AGGREGATE_D2_START + row] == 0);
        }
    }

    (
        pk_public[0], pk_public[1], pk_public[2], pk_public[3], pk_public[4], expected_pk,
        expected_d0, expected_d2, aggregate_pk, aggregate_d0, aggregate_d2,
    )
}

#[test]
fn test_aggregation_pair_accepts_matching_identity() {
    let pk: [Field; PK_AGGREGATION_PUBLIC_LEN] = [0; PK_AGGREGATION_PUBLIC_LEN];
    let rlk: [Field; RLK_AGGREGATION_PUBLIC_LEN] = [0; RLK_AGGREGATION_PUBLIC_LEN];
    assert_aggregation_pair(pk, rlk, 0);
}

#[test(should_fail)]
fn test_aggregation_pair_rejects_wrong_row() {
    let pk: [Field; PK_AGGREGATION_PUBLIC_LEN] = [0; PK_AGGREGATION_PUBLIC_LEN];
    let mut rlk: [Field; RLK_AGGREGATION_PUBLIC_LEN] = [0; RLK_AGGREGATION_PUBLIC_LEN];
    rlk[5] = 1;
    assert_aggregation_pair(pk, rlk, 0);
}
