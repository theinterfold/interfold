// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Statement checks shared by the l-BFV generation and aggregation folds and their kernels. Each
//! fold step pairs one public-key proof with its RLK proof(s); the pair must come from the same
//! session and party and sit at the same row. The row-range condition differs between a fold step
//! (`row_index < rows`) and its kernel (`row_index == 0`), so each circuit asserts it before
//! calling these.

/// Index of the component (`0` = `d0`, `1` = `d2`) in `rlk_aggregation`'s public inputs.
pub global RLK_COMPONENT_IDX: u32 = 6;

/// `lbfv_pk_generation` and `rlk_generation` public inputs, in order: session hi and lo, party id,
/// row, secret-key commitment (`pk_public[0..5]` / `rlk_public[0..5]`). They must agree on all of
/// them, and both rows must equal `row_index`.
pub fn assert_generation_pair_matches<let PK_LEN: u32, let RLK_LEN: u32>(
    pk_public: [Field; PK_LEN],
    rlk_public: [Field; RLK_LEN],
    row_index: u32,
) {
    assert(pk_public[0] == rlk_public[0]);
    assert(pk_public[1] == rlk_public[1]);
    assert(pk_public[2] == rlk_public[2]);
    assert(pk_public[3] == row_index as Field);
    assert(rlk_public[3] == row_index as Field);
    assert(pk_public[4] == rlk_public[4]);
}

/// `lbfv_pk_aggregation`'s and both `rlk_aggregation` components' public inputs start with the same
/// five identity fields (session, aggregator, accepted party set) and then the row; the two RLK
/// proofs must be components 0 and 1.
pub fn assert_aggregation_pair_matches<let PK_LEN: u32, let RLK_LEN: u32>(
    pk_public: [Field; PK_LEN],
    rlk_d0_public: [Field; RLK_LEN],
    rlk_d2_public: [Field; RLK_LEN],
    row_index: u32,
) {
    for i in 0..5 {
        assert(pk_public[i] == rlk_d0_public[i]);
        assert(pk_public[i] == rlk_d2_public[i]);
    }
    assert(pk_public[5] == row_index as Field);
    assert(rlk_d0_public[5] == row_index as Field);
    assert(rlk_d2_public[5] == row_index as Field);
    assert(rlk_d0_public[RLK_COMPONENT_IDX] == 0);
    assert(rlk_d2_public[RLK_COMPONENT_IDX] == 1);
}

#[test]
fn test_generation_pair_accepts_matching_row() {
    assert_generation_pair_matches([1, 2, 3, 2, 5, 6], [1, 2, 3, 2, 5, 7, 8, 9], 2);
}

#[test(should_fail)]
fn test_generation_pair_rejects_mixed_session() {
    assert_generation_pair_matches([1, 2, 3, 2, 5, 6], [11, 2, 3, 2, 5, 7, 8, 9], 2);
}

#[test(should_fail)]
fn test_generation_pair_rejects_mismatched_sk_commitment() {
    assert_generation_pair_matches([1, 2, 3, 2, 5, 6], [1, 2, 3, 2, 15, 7, 8, 9], 2);
}

#[test(should_fail)]
fn test_generation_pair_rejects_wrong_row() {
    assert_generation_pair_matches([1, 2, 3, 2, 5, 6], [1, 2, 3, 2, 5, 7, 8, 9], 3);
}

fn aggregation_fixture() -> ([Field; 8], [Field; 9], [Field; 9]) {
    let pk = [0; 8];
    let d0 = [0; 9];
    let mut d2 = [0; 9];
    d2[RLK_COMPONENT_IDX] = 1;
    (pk, d0, d2)
}

#[test]
fn test_aggregation_pair_accepts_matching_identity() {
    let (pk, d0, d2) = aggregation_fixture();
    assert_aggregation_pair_matches(pk, d0, d2, 0);
}

#[test(should_fail)]
fn test_aggregation_pair_rejects_wrong_row() {
    let (pk, d0, mut d2) = aggregation_fixture();
    d2[5] = 1;
    assert_aggregation_pair_matches(pk, d0, d2, 0);
}

#[test(should_fail)]
fn test_aggregation_pair_rejects_swapped_components() {
    let (pk, mut d0, d2) = aggregation_fixture();
    d0[RLK_COMPONENT_IDX] = 1;
    assert_aggregation_pair_matches(pk, d0, d2, 0);
}

#[test(should_fail)]
fn test_aggregation_pair_rejects_a_d2_proof_from_another_session() {
    let (pk, d0, mut d2) = aggregation_fixture();
    d2[0] = 9;
    assert_aggregation_pair_matches(pk, d0, d2, 0);
}
