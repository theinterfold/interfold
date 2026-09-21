// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! MEASUREMENT ONLY - sequential fold of the l-BFV public-key rows, one step per row.
//!
//! See `lbfv_pk_fold_kernel` for why this exists and what it deliberately leaves out. Folding all
//! `LBFV_ROWS` rows gives one proof for public-key generation, so the cost of that task can be
//! measured without proving the relinearization family.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
    verify_honk_proof_non_zk,
};

pub global LBFV_ROWS: u32 = 5;
pub global PK_GENERATION_PUBLIC_LEN: u32 = 7;

pub global PK_FOLD_PREFIX_LEN: u32 = 7;
pub global PK_FOLD_PUBLIC_LEN: u32 = PK_FOLD_PREFIX_LEN + 4 + LBFV_ROWS;

pub global ACC_SESSION_HI_IDX: u32 = PK_FOLD_PREFIX_LEN;
pub global ACC_SESSION_LO_IDX: u32 = ACC_SESSION_HI_IDX + 1;
pub global ACC_PARTY_ID_IDX: u32 = ACC_SESSION_HI_IDX + 2;
pub global ACC_SK_COMMITMENT_IDX: u32 = ACC_SESSION_HI_IDX + 3;
pub global ACC_PK_COMMITMENTS_START: u32 = ACC_SESSION_HI_IDX + 4;

fn assert_generation_row(
    pk_public: [Field; PK_GENERATION_PUBLIC_LEN],
    row_index: u32,
    trusted_pk_limb_key_hash: Field,
) {
    assert(row_index < LBFV_ROWS);
    assert(pk_public[3] == row_index as Field);
    assert(pk_public[6] == trusted_pk_limb_key_hash);
}

/// Every row must carry the session, party, and secret key the accumulator already committed to.
/// This is what makes the five rows one party's contribution rather than five unrelated proofs.
fn assert_accumulator_identity(
    acc_public: [Field; PK_FOLD_PUBLIC_LEN],
    pk_public: [Field; PK_GENERATION_PUBLIC_LEN],
) {
    assert(acc_public[ACC_SESSION_HI_IDX] == pk_public[0]);
    assert(acc_public[ACC_SESSION_LO_IDX] == pk_public[1]);
    assert(acc_public[ACC_PARTY_ID_IDX] == pk_public[2]);
    assert(acc_public[ACC_SK_COMMITMENT_IDX] == pk_public[4]);
}

fn main(
    pk_vk: UltraHonkVerificationKey,
    pk_proof: UltraHonkZKProof,
    pk_public: [Field; PK_GENERATION_PUBLIC_LEN],
    acc_vk: UltraHonkVerificationKey,
    acc_proof: UltraHonkProof,
    acc_public: [Field; PK_FOLD_PUBLIC_LEN],
    pk_key_hash: pub Field,
    acc_key_hash: pub Field,
    is_first_step: pub bool,
    row_index: pub u32,
    expected_kernel_key_hash: pub Field,
    expected_fold_key_hash: pub Field,
    trusted_pk_limb_key_hash: pub Field,
) -> pub (Field, Field, Field, Field, [Field; LBFV_ROWS]) {
    assert(!is_first_step);
    assert(row_index > 0);
    // Step 1 consumes the kernel; later steps consume this same circuit.
    assert(
        (acc_key_hash == expected_kernel_key_hash) | (acc_key_hash == expected_fold_key_hash),
    );

    assert_generation_row(pk_public, row_index, trusted_pk_limb_key_hash);
    assert_accumulator_identity(acc_public, pk_public);

    verify_honk_proof(pk_vk, pk_proof, pk_public, pk_key_hash);
    verify_honk_proof_non_zk(acc_vk, acc_proof, acc_public, acc_key_hash);

    // Carry the rows already folded and add this one in its own slot, so the output pins every
    // row's public-key commitment by position.
    let mut pk_commitments: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    for row in 0..LBFV_ROWS {
        pk_commitments[row] = acc_public[ACC_PK_COMMITMENTS_START + row];
    }
    assert(pk_commitments[row_index] == 0);
    pk_commitments[row_index] = pk_public[5];

    (
        acc_public[ACC_SESSION_HI_IDX], acc_public[ACC_SESSION_LO_IDX],
        acc_public[ACC_PARTY_ID_IDX], acc_public[ACC_SK_COMMITMENT_IDX], pk_commitments,
    )
}
