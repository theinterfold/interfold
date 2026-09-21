// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! MEASUREMENT ONLY - genesis accumulator for `lbfv_pk_fold`.
//!
//! Not part of the protocol. The shipped chain folds each public-key row together with its
//! relinearization-key row (`lbfv_generation_fold`), which binds both families to one
//! `sk_commitment` per step. That pairing means a public-key measurement has to prove the whole
//! relinearization family too - 2.8x the gates - so this pair folds the public-key rows alone to
//! give one proof for public-key generation to measure against.
//!
//! It is deliberately absent from the protocol artifact set in `build-circuits.ts`. If the
//! public-key and relinearization folds are ever split for real, the binding these drop
//! (`pk_public[4] == rlk_public[4]`) has to reappear one layer up, as an assertion that the two
//! accumulators carry the same `sk_commitment`.

use bb_proof_verification::{
    UltraHonkProof, UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof,
};

pub global LBFV_ROWS: u32 = 5;
pub global PK_GENERATION_PUBLIC_LEN: u32 = 7;

/// pk_vk_hash, acc_vk_hash, is_first_step, row_index, expected_kernel, expected_fold,
/// trusted_pk_limb_vk_hash.
pub global PK_FOLD_PREFIX_LEN: u32 = 7;
/// Prefix, then session_hi, session_lo, party_id, sk_commitment, then one commitment per row.
pub global PK_FOLD_PUBLIC_LEN: u32 = PK_FOLD_PREFIX_LEN + 4 + LBFV_ROWS;

fn assert_generation_row(
    pk_public: [Field; PK_GENERATION_PUBLIC_LEN],
    row_index: u32,
    trusted_pk_limb_key_hash: Field,
) {
    assert(row_index == 0);
    assert(pk_public[3] == row_index as Field);
    assert(pk_public[6] == trusted_pk_limb_key_hash);
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
    assert(is_first_step);
    assert(acc_key_hash == expected_kernel_key_hash);
    assert_generation_row(pk_public, row_index, trusted_pk_limb_key_hash);
    verify_honk_proof(pk_vk, pk_proof, pk_public, pk_key_hash);

    // The genesis step has no prior accumulator to verify; keep the shape so both circuits take
    // the same inputs and one driver can call either.
    let _ = (acc_vk, acc_proof, acc_public, expected_fold_key_hash);

    let mut pk_commitments: [Field; LBFV_ROWS] = [0; LBFV_ROWS];
    pk_commitments[0] = pk_public[5];

    (pk_public[0], pk_public[1], pk_public[2], pk_public[4], pk_commitments)
}
