// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Tests on the tiny fixtures (N = 16, t = 97, n = 2, B = 4). Real `fhe.rs` plaintexts made the
//! `k1` polynomials: `bid_circuit --params tiny` wrote them. The failing tests tamper with one input
//! of an honest run. Each strategy has the same set, for both designs.

use crate::{fixture, fixture_compact, ntt, Polynomial, sparse, table};
use crate::ntt::NttConstants;
use crate::sparse::SparseConstants;

fn polys<let N: u32, let C: u32>(k1s: [[Field; N]; C]) -> [Polynomial<N>; C] {
    let mut out = [Polynomial::new([0; N]); C];
    for c in 0..C {
        out[c] = Polynomial::new(k1s[c]);
    }
    out
}

/// The coefficients of each `k1` at the support positions.
fn support_of<let N: u32, let C: u32, let S: u32>(
    k1s: [[Field; N]; C],
    positions: [u32; S],
) -> [[Field; S]; C] {
    let mut support = [[0; S]; C];
    for c in 0..C {
        for j in 0..S {
            support[c][j] = k1s[c][positions[j]];
        }
    }
    support
}

fn vickrey_sparse(b: Field, k1s: [[Field; 16]; 2]) -> [Field; 2] {
    sparse::prove::<fixture::sparse::N, fixture::sparse::B, fixture::sparse::CTS, fixture::sparse::S, fixture::sparse::CLASSES, fixture::sparse::BIT_K, fixture::sparse::QUOTIENT_BITS>(
        b,
        support_of(k1s, fixture::sparse::POSITIONS),
        SparseConstants {
            t: fixture::sparse::PLAINTEXT_MODULUS,
            positions: fixture::sparse::POSITIONS,
            class_level: fixture::sparse::CLASS_LEVEL,
            weights: fixture::sparse::WEIGHTS,
            target_at: fixture::sparse::TARGET_AT,
            target_next: fixture::sparse::TARGET_NEXT,
        },
    )
}

fn compact_sparse(b: Field, k1s: [[Field; 16]; 1]) -> [Field; 1] {
    sparse::prove::<fixture_compact::sparse::N, fixture_compact::sparse::B, fixture_compact::sparse::CTS, fixture_compact::sparse::S, fixture_compact::sparse::CLASSES, fixture_compact::sparse::BIT_K, fixture_compact::sparse::QUOTIENT_BITS>(
        b,
        support_of(k1s, fixture_compact::sparse::POSITIONS),
        SparseConstants {
            t: fixture_compact::sparse::PLAINTEXT_MODULUS,
            positions: fixture_compact::sparse::POSITIONS,
            class_level: fixture_compact::sparse::CLASS_LEVEL,
            weights: fixture_compact::sparse::WEIGHTS,
            target_at: fixture_compact::sparse::TARGET_AT,
            target_next: fixture_compact::sparse::TARGET_NEXT,
        },
    )
}

fn vickrey_ntt(b: Field, k1s: [[Field; 16]; 2]) -> [Field; 2] {
    ntt::prove::<fixture::ntt::N, fixture::ntt::LOG_N, fixture::ntt::B, fixture::ntt::CTS, fixture::ntt::BIT_K, fixture::ntt::QUOTIENT_BITS>(
        b,
        polys(k1s),
        NttConstants {
            t: fixture::ntt::PLAINTEXT_MODULUS,
            twiddles: fixture::ntt::TWIDDLES,
            level_of: fixture::ntt::LEVEL_OF,
            target_at: fixture::ntt::TARGET_AT,
            target_next: fixture::ntt::TARGET_NEXT,
        },
    )
}

fn vickrey_table(b: Field, k1s: [[Field; 16]; 2]) -> [Field; 2] {
    table::prove::<fixture::table::N, fixture::table::B, fixture::table::CTS, fixture::table::BIT_K, fixture::table::QUOTIENT_BITS>(
        b,
        polys(k1s),
        fixture::table::PLAINTEXT_MODULUS,
        fixture::table::COEF_AT,
        fixture::table::COEF_NEXT,
        fixture::table::TABLE,
    )
}

fn compact_ntt(b: Field, k1s: [[Field; 16]; 1]) -> [Field; 1] {
    ntt::prove::<fixture_compact::ntt::N, fixture_compact::ntt::LOG_N, fixture_compact::ntt::B, fixture_compact::ntt::CTS, fixture_compact::ntt::BIT_K, fixture_compact::ntt::QUOTIENT_BITS>(
        b,
        polys(k1s),
        NttConstants {
            t: fixture_compact::ntt::PLAINTEXT_MODULUS,
            twiddles: fixture_compact::ntt::TWIDDLES,
            level_of: fixture_compact::ntt::LEVEL_OF,
            target_at: fixture_compact::ntt::TARGET_AT,
            target_next: fixture_compact::ntt::TARGET_NEXT,
        },
    )
}

fn compact_table(b: Field, k1s: [[Field; 16]; 1]) -> [Field; 1] {
    table::prove::<fixture_compact::table::N, fixture_compact::table::B, fixture_compact::table::CTS, fixture_compact::table::BIT_K, fixture_compact::table::QUOTIENT_BITS>(
        b,
        polys(k1s),
        fixture_compact::table::PLAINTEXT_MODULUS,
        fixture_compact::table::COEF_AT,
        fixture_compact::table::COEF_NEXT,
        fixture_compact::table::TABLE,
    )
}

#[test]
fn vickrey_honest_bids_pass_and_both_strategies_commit_alike() {
    for bid in 0..4 {
        let k1s = fixture::K1_HONEST[bid];
        let from_ntt = vickrey_ntt(bid as Field, k1s);
        let from_table = vickrey_table(bid as Field, k1s);
        let from_sparse = vickrey_sparse(bid as Field, k1s);
        assert_eq(from_ntt, from_table);
        assert_eq(from_ntt, from_sparse);
    }
}

#[test]
fn compact_honest_bids_pass_and_both_strategies_commit_alike() {
    for bid in 0..4 {
        let k1s = fixture_compact::K1_HONEST[bid];
        let from_ntt = compact_ntt(bid as Field, k1s);
        let from_table = compact_table(bid as Field, k1s);
        let from_sparse = compact_sparse(bid as Field, k1s);
        assert_eq(from_ntt, from_table);
        assert_eq(from_ntt, from_sparse);
    }
}

#[test]
fn different_bids_give_different_commitments() {
    let first = vickrey_ntt(0, fixture::K1_HONEST[0]);
    let second = vickrey_ntt(1, fixture::K1_HONEST[1]);
    assert(first[0] != second[0]);
    assert(first[1] != second[1]);
}

// k1 of the bid 2 while the bid 1 is claimed.
#[test(should_fail)]
fn vickrey_ntt_rejects_a_k1_for_bid_plus_one() {
    let _ = vickrey_ntt(1, fixture::K1_HONEST[2]);
}

#[test(should_fail)]
fn vickrey_table_rejects_a_k1_for_bid_plus_one() {
    let _ = vickrey_table(1, fixture::K1_HONEST[2]);
}

#[test(should_fail)]
fn vickrey_sparse_rejects_a_k1_for_bid_plus_one() {
    let _ = vickrey_sparse(1, fixture::K1_HONEST[2]);
}

#[test(should_fail)]
fn compact_ntt_rejects_a_k1_for_bid_plus_one() {
    let _ = compact_ntt(1, fixture_compact::K1_HONEST[2]);
}

#[test(should_fail)]
fn compact_table_rejects_a_k1_for_bid_plus_one() {
    let _ = compact_table(1, fixture_compact::K1_HONEST[2]);
}

#[test(should_fail)]
fn compact_sparse_rejects_a_k1_for_bid_plus_one() {
    let _ = compact_sparse(1, fixture_compact::K1_HONEST[2]);
}

// A thermometer with a hole at level 2, for the claimed bid 1.
#[test(should_fail)]
fn vickrey_ntt_rejects_a_slot_vector_that_is_not_a_thermometer() {
    let _ = vickrey_ntt(fixture::FIXTURE_BID, fixture::K1_NON_THERMOMETER);
}

#[test(should_fail)]
fn vickrey_table_rejects_a_slot_vector_that_is_not_a_thermometer() {
    let _ = vickrey_table(fixture::FIXTURE_BID, fixture::K1_NON_THERMOMETER);
}

#[test(should_fail)]
fn vickrey_sparse_rejects_a_slot_vector_that_is_not_a_thermometer() {
    let _ = vickrey_sparse(fixture::FIXTURE_BID, fixture::K1_NON_THERMOMETER);
}

#[test(should_fail)]
fn compact_ntt_rejects_a_slot_vector_that_is_not_a_thermometer() {
    let _ = compact_ntt(
        fixture_compact::FIXTURE_BID,
        fixture_compact::K1_NON_THERMOMETER,
    );
}

#[test(should_fail)]
fn compact_table_rejects_a_slot_vector_that_is_not_a_thermometer() {
    let _ = compact_table(
        fixture_compact::FIXTURE_BID,
        fixture_compact::K1_NON_THERMOMETER,
    );
}

#[test(should_fail)]
fn compact_sparse_rejects_a_slot_vector_that_is_not_a_thermometer() {
    let _ = compact_sparse(
        fixture_compact::FIXTURE_BID,
        fixture_compact::K1_NON_THERMOMETER,
    );
}

// Two valid thermometers from 2 different bids.
#[test(should_fail)]
fn vickrey_ntt_rejects_ciphertexts_of_different_bids() {
    let _ = vickrey_ntt(fixture::FIXTURE_BID, fixture::K1_MISMATCHED_PAIR);
}

#[test(should_fail)]
fn vickrey_table_rejects_ciphertexts_of_different_bids() {
    let _ = vickrey_table(fixture::FIXTURE_BID, fixture::K1_MISMATCHED_PAIR);
}

#[test(should_fail)]
fn vickrey_sparse_rejects_ciphertexts_of_different_bids() {
    let _ = vickrey_sparse(fixture::FIXTURE_BID, fixture::K1_MISMATCHED_PAIR);
}

// The claimed bid is B = 4; the k1 polynomials encode the largest bid, 3.
#[test(should_fail)]
fn vickrey_ntt_rejects_a_bid_at_the_level_count() {
    let _ = vickrey_ntt(4, fixture::K1_HONEST[3]);
}

#[test(should_fail)]
fn vickrey_table_rejects_a_bid_at_the_level_count() {
    let _ = vickrey_table(4, fixture::K1_HONEST[3]);
}

#[test(should_fail)]
fn vickrey_sparse_rejects_a_bid_at_the_level_count() {
    let _ = vickrey_sparse(4, fixture::K1_HONEST[3]);
}

#[test(should_fail)]
fn compact_ntt_rejects_a_bid_at_the_level_count() {
    let _ = compact_ntt(4, fixture_compact::K1_HONEST[3]);
}

#[test(should_fail)]
fn compact_table_rejects_a_bid_at_the_level_count() {
    let _ = compact_table(4, fixture_compact::K1_HONEST[3]);
}

#[test(should_fail)]
fn compact_sparse_rejects_a_bid_at_the_level_count() {
    let _ = compact_sparse(4, fixture_compact::K1_HONEST[3]);
}

// A bid far above B has no one-hot vector.
#[test(should_fail)]
fn vickrey_ntt_rejects_a_bid_above_the_level_count() {
    let _ = vickrey_ntt(9, fixture::K1_HONEST[3]);
}

// A negative bid wraps to a huge field element, and has no one-hot vector either.
#[test(should_fail)]
fn vickrey_table_rejects_a_negative_bid() {
    let _ = vickrey_table(-1, fixture::K1_HONEST[0]);
}
