// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Create the row-zero accumulator for `lbfv_generation_fold`.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
};

pub use lib::configs::default::threshold::L as LBFV_ROWS;
pub global PK_GENERATION_PUBLIC_LEN: u32 = 7;
pub global RLK_GENERATION_PUBLIC_LEN: u32 = 9;
pub global GENERATION_FOLD_PREFIX_LEN: u32 = 9;
pub global GENERATION_FOLD_PUBLIC_LEN: u32 = GENERATION_FOLD_PREFIX_LEN + 5 + (3 * LBFV_ROWS);

fn assert_generation_pair(
    pk_public: [Field; PK_GENERATION_PUBLIC_LEN],
    rlk_public: [Field; RLK_GENERATION_PUBLIC_LEN],
    row_index: u32,
    trusted_pk_limb_key_hash: Field,
    trusted_rlk_limb_key_hash: Field,
) {
    assert(row_index == 0);
    assert(pk_public[0] == rlk_public[0]);
    assert(pk_public[1] == rlk_public[1]);
    assert(pk_public[2] == rlk_public[2]);
    assert(pk_public[3] == row_index as Field);
    assert(rlk_public[3] == row_index as Field);
    assert(pk_public[4] == rlk_public[4]);
    assert(pk_public[6] == trusted_pk_limb_key_hash);
    assert(rlk_public[8] == trusted_rlk_limb_key_hash);
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
    trusted_pk_limb_key_hash: pub Field,
    trusted_rlk_limb_key_hash: pub Field,
    ) -> pub (Field, Field, Field, Field, Field, [Field; LBFV_ROWS], [Field; LBFV_ROWS], [Field; LBFV_ROWS]) {
    assert(is_first_step);
    assert(acc_key_hash == expected_kernel_key_hash);
    assert_generation_pair(
        pk_public,
        rlk_public,
        row_index,
        trusted_pk_limb_key_hash,
        trusted_rlk_limb_key_hash,
    );

    verify_honk_proof(pk_vk, pk_proof, pk_public, pk_key_hash);
    verify_honk_proof(rlk_vk, rlk_proof, rlk_public, rlk_key_hash);

    let _ = (acc_vk, acc_proof, acc_public, expected_fold_key_hash);

    let mut pk_commitments: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    let mut d0_commitments: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    let mut d2_commitments: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    pk_commitments[0] = pk_public[5];
    d0_commitments[0] = rlk_public[6];
    d2_commitments[0] = rlk_public[7];

    (
        pk_public[0], pk_public[1], pk_public[2], pk_public[4], rlk_public[5], pk_commitments,
        d0_commitments, d2_commitments,
    )
}

#[test]
fn test_kernel_accepts_row_zero() {
    assert_generation_pair(
        [1, 2, 3, 0, 5, 6, 11],
        [1, 2, 3, 0, 5, 7, 8, 9, 10],
        0,
        11,
        10,
    );
}

#[test(should_fail)]
fn test_kernel_rejects_nonzero_row() {
    assert_generation_pair(
        [1, 2, 3, 1, 5, 6, 11],
        [1, 2, 3, 1, 5, 7, 8, 9, 10],
        1,
        11,
        10,
    );
}
