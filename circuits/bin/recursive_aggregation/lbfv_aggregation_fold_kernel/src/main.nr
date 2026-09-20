// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Create the row-zero accumulator for `lbfv_aggregation_fold`.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
};
use lib::configs::default::H;

pub use lib::configs::default::threshold::L as LBFV_ROWS;
pub global PK_AGGREGATION_PUBLIC_LEN: u32 = 7 + H;
pub global RLK_AGGREGATION_PUBLIC_LEN: u32 = 8 + (2 * H);
pub global AGGREGATION_FOLD_PREFIX_LEN: u32 = 7;
pub global AGGREGATION_FOLD_PUBLIC_LEN: u32 =
    AGGREGATION_FOLD_PREFIX_LEN + 5 + (3 * LBFV_ROWS * H) + (3 * LBFV_ROWS);

fn assert_aggregation_pair(
    pk_public: [Field; PK_AGGREGATION_PUBLIC_LEN],
    rlk_public: [Field; RLK_AGGREGATION_PUBLIC_LEN],
    row_index: u32,
) {
    assert(row_index == 0);
    for i in 0..5 {
        assert(pk_public[i] == rlk_public[i]);
    }
    assert(pk_public[5] == row_index as Field);
    assert(rlk_public[5] == row_index as Field);
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
    assert(is_first_step);
    assert(acc_key_hash == expected_kernel_key_hash);
    assert_aggregation_pair(pk_public, rlk_public, row_index);

    verify_honk_proof(pk_vk, pk_proof, pk_public, pk_key_hash);
    verify_honk_proof(rlk_vk, rlk_proof, rlk_public, rlk_key_hash);

    let _ = (acc_vk, acc_proof, acc_public, expected_fold_key_hash);

    let mut expected_pk: [[Field; H]; LBFV_ROWS] = [[0; H]; LBFV_ROWS];
    let mut expected_d0: [[Field; H]; LBFV_ROWS] = [[0; H]; LBFV_ROWS];
    let mut expected_d2: [[Field; H]; LBFV_ROWS] = [[0; H]; LBFV_ROWS];
    let mut aggregate_pk: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    let mut aggregate_d0: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    let mut aggregate_d2: [Field; LBFV_ROWS] = [0; LBFV_ROWS];

    for party in 0..H {
        expected_pk[0][party] = pk_public[6 + party];
        expected_d0[0][party] = rlk_public[6 + party];
        expected_d2[0][party] = rlk_public[6 + H + party];
    }
    aggregate_pk[0] = pk_public[6 + H];
    aggregate_d0[0] = rlk_public[6 + (2 * H)];
    aggregate_d2[0] = rlk_public[7 + (2 * H)];

    (
        pk_public[0], pk_public[1], pk_public[2], pk_public[3], pk_public[4], expected_pk,
        expected_d0, expected_d2, aggregate_pk, aggregate_d0, aggregate_d2,
    )
}

#[test]
fn test_kernel_accepts_row_zero() {
    let pk: [Field; PK_AGGREGATION_PUBLIC_LEN] = [0; PK_AGGREGATION_PUBLIC_LEN];
    let rlk: [Field; RLK_AGGREGATION_PUBLIC_LEN] = [0; RLK_AGGREGATION_PUBLIC_LEN];
    assert_aggregation_pair(pk, rlk, 0);
}

#[test(should_fail)]
fn test_kernel_rejects_nonzero_row() {
    let mut pk: [Field; PK_AGGREGATION_PUBLIC_LEN] = [0; PK_AGGREGATION_PUBLIC_LEN];
    let mut rlk: [Field; RLK_AGGREGATION_PUBLIC_LEN] = [0; RLK_AGGREGATION_PUBLIC_LEN];
    pk[5] = 1;
    rlk[5] = 1;
    assert_aggregation_pair(pk, rlk, 1);
}
