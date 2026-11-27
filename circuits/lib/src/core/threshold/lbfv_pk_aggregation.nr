// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_commitment, compute_lbfv_pk_row_commitment_from_carriers,
    compute_packed_polynomials_commitment, DS_PK_AGGREGATION,
};
use crate::math::packed_sum::reduce_packed_sum;

/// Threshold l-BFV public-key aggregation for one fixed CRS row, summing the parties' `pk0` rows
/// while still packed (see `math::packed_sum`).
///
/// The row's `pk1` is the fixed CRS row, so its commitment is the generated constant
/// `LBFV_CRS_ROW_COMMITMENTS[row]` (`crs_row_commitment`) rather than a hash of the row computed
/// in-circuit; the generated commitments must equal the hash of each CRS row, or every aggregation
/// proof would commit to a key that does not match its `pk1`.
///
/// `pk0_carriers[party][limb]` are the carriers `lbfv_pk_generation` hashed into the party's row
/// commitment (a hash of its limb commitments); they open that commitment directly, and the
/// centred aggregate is derived from their sum, so it needs no witness or range check of its own.
/// `row_index` must be the statement's range-checked row: each party's row commitment binds it
/// through every limb commitment. Returns the commitment `pk_aggregation` (C5) returns for the same
/// keys and the same CRS row.
pub fn packed_lbfv_pk_aggregation<let N: u32, let H: u32, let L: u32, let BIT_PK: u32>(
    qis: [Field; L],
    row_index: u32,
    crs_row_commitment: Field,
    expected_pk_generation_commitments: [Field; H],
    pk0_carriers: [[[Field; N / 4]; L]; H],
) -> Field {
    for i in 0..H {
        assert(
            compute_lbfv_pk_row_commitment_from_carriers::<N, L>(row_index, pk0_carriers[i])
                == expected_pk_generation_commitments[i],
            "PK commitment mismatch",
        );
    }
    // Centred residues fit `BIT_PK` bits of magnitude, so the moduli fit `BIT_PK + 1`.
    let mut aggregate: [[Field; N / 4]; L] = [[0; N / 4]; L];
    for l in 0..L {
        aggregate[l] = reduce_packed_sum::<N / 4, H, BIT_PK, BIT_PK + 1, _>(
            |party, g| pk0_carriers[party][l][g],
            qis[l],
            true,
        );
    }
    let commit_pk0 =
        compute_packed_polynomials_commitment::<N / 4, L>(aggregate, DS_PK_AGGREGATION);
    compute_commitment(
        [commit_pk0, crs_row_commitment].as_vector(),
        DS_PK_AGGREGATION,
    )
}

use crate::core::threshold::pk_aggregation::{Configs, PkAggregation};
use crate::math::commitments::compute_multiple_polynomial_commitment;
use crate::math::commitments::compute_threshold_pk_commitment_checked;
use crate::math::helpers::pack;
use crate::math::polynomial::Polynomial;

/// Same fixture as `pk_aggregation`'s tests: three parties, `N = 4`, `q = [101, 97]`.
fn fixture_pk0() -> ([[Polynomial<4>; 2]; 3], [Polynomial<4>; 2]) {
    (
        [
            [Polynomial::new([50, 0 - 50, 10, 0]), Polynomial::new([48, 0 - 48, 5, 7])],
            [Polynomial::new([50, 0 - 50, 20, 1]), Polynomial::new([48, 0 - 48, 5, 0 - 7])],
            [Polynomial::new([50, 0 - 50, 0 - 30, 2]), Polynomial::new([48, 0 - 48, 5, 1])],
        ], [Polynomial::new([49, 0 - 49, 0, 3]), Polynomial::new([47, 0 - 47, 15, 1])],
    )
}

fn fixture_crp() -> [Polynomial<4>; 2] {
    [Polynomial::new([1, 2, 3, 4]), Polynomial::new([5, 6, 7, 8])]
}

/// Packs each party's limbs the way `lbfv_pk_generation` does at a four-slot width (`BIT = 50`).
fn packed_fixture_carriers(pk0: [[Polynomial<4>; 2]; 3]) -> [[[Field; 1]; 2]; 3] {
    let mut carriers = [[[0; 1]; 2]; 3];
    for i in 0..3 {
        for l in 0..2 {
            carriers[i][l] = [pack::<4, 50>(pk0[i][l].coefficients)[0]];
        }
    }
    carriers
}

/// The row commitments `lbfv_pk_generation` would output for each party, for `commitment_row`.
fn row_commitments(carriers: [[[Field; 1]; 2]; 3], commitment_row: u32) -> [Field; 3] {
    let mut commitments = [0; 3];
    for i in 0..3 {
        commitments[i] =
            compute_lbfv_pk_row_commitment_from_carriers::<4, 2>(commitment_row, carriers[i]);
    }
    commitments
}

fn crp_commitment() -> Field {
    compute_multiple_polynomial_commitment::<4, 2, 50>(fixture_crp(), DS_PK_AGGREGATION)
}

/// The packed l-BFV circuit returns what C5's `execute` returns for the same key and CRS row.
#[test]
fn test_packed_lbfv_aggregation_matches_c5_on_the_same_row() {
    let (pk0, pk0_agg) = fixture_pk0();
    let mut c1_commitments = [0; 3];
    for i in 0..3 {
        c1_commitments[i] = compute_threshold_pk_commitment_checked::<4, 2, 50>(pk0[i]);
    }
    let full: PkAggregation<4, 3, 2, 50> = PkAggregation::new(
        Configs::new([101, 97]),
        fixture_crp(),
        c1_commitments,
        pk0,
        pk0_agg,
    );
    let carriers = packed_fixture_carriers(pk0);
    let packed = packed_lbfv_pk_aggregation::<4, 3, 2, 50>(
        [101, 97],
        2,
        crp_commitment(),
        row_commitments(carriers, 2),
        carriers,
    );
    assert(packed == full.execute());
}

/// A row commitment bound to another row does not open.
#[test(should_fail_with = "PK commitment mismatch")]
fn test_packed_lbfv_aggregation_rejects_another_rows_commitment() {
    let (pk0, _) = fixture_pk0();
    let carriers = packed_fixture_carriers(pk0);
    let _ = packed_lbfv_pk_aggregation::<4, 3, 2, 50>(
        [101, 97],
        2,
        crp_commitment(),
        row_commitments(carriers, 3),
        carriers,
    );
}

/// C1-form commitments (the ones `pk_aggregation` opens) do not open as l-BFV row commitments.
#[test(should_fail_with = "PK commitment mismatch")]
fn test_packed_lbfv_aggregation_rejects_c1_form_commitments() {
    let (pk0, _) = fixture_pk0();
    let mut c1_commitments = [0; 3];
    for i in 0..3 {
        c1_commitments[i] = compute_threshold_pk_commitment_checked::<4, 2, 50>(pk0[i]);
    }
    let _ = packed_lbfv_pk_aggregation::<4, 3, 2, 50>(
        [101, 97],
        2,
        crp_commitment(),
        c1_commitments,
        packed_fixture_carriers(pk0),
    );
}
