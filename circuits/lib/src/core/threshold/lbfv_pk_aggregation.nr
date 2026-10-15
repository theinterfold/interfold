// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::configs::default::threshold::{
    GADGET_DIM, L, LBFV_CRS_GADGET_ROWS, LBFV_CRS_ROW_COMMITMENTS, N, PK_AGGREGATION_BIT_PK,
};
use crate::core::threshold::pk_aggregation::{Configs, PkAggregation};
use crate::math::commitments::{
    compute_commitment, compute_lbfv_pk_row_commitment,
    compute_lbfv_pk_row_commitment_from_carriers, compute_multiple_polynomial_commitment,
    compute_packed_polynomials_commitment, compute_threshold_pk_commitment_checked,
    DS_PK_AGGREGATION,
};
use crate::math::helpers::pack;
use crate::math::packed_sum::reduce_packed_sum;
use crate::math::polynomial::Polynomial;

/// Threshold l-BFV public-key aggregation for one fixed CRS row.
///
/// The row's `pk1` is the fixed CRS row, so its commitment is the generated constant
/// `LBFV_CRS_ROW_COMMITMENTS[row]` rather than a hash of the row computed in-circuit. Each party's
/// `pk0` row is opened in the form `lbfv_pk_generation` commits it: a hash of its limb
/// commitments, which pack with checked digits and so carry the limbs' centered bound.
pub struct LbfvPkAggregation<let N: u32, let H: u32, let L: u32, let BIT_PK: u32> {
    configs: Configs<L>,
    row_index: u32,
    crs_row_commitment: Field,
    expected_pk_generation_commitments: [Field; H],
    pk0: [[Polynomial<N>; L]; H],
    pk0_agg: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32, let BIT_PK: u32> LbfvPkAggregation<N, H, L, BIT_PK> {
    pub fn new(
        configs: Configs<L>,
        row_index: u32,
        crs_row_commitment: Field,
        expected_pk_generation_commitments: [Field; H],
        pk0: [[Polynomial<N>; L]; H],
        pk0_agg: [Polynomial<N>; L],
    ) -> Self {
        LbfvPkAggregation {
            configs,
            row_index,
            crs_row_commitment,
            expected_pk_generation_commitments,
            pk0,
            pk0_agg,
        }
    }

    /// Apply the audited C5 relation to the selected l-BFV CRS row.
    ///
    /// `row_index` must be the statement's range-checked row: each party's row commitment binds it
    /// through every limb commitment.
    pub fn execute(self) -> Field {
        for i in 0..H {
            assert(
                compute_lbfv_pk_row_commitment::<N, L, BIT_PK>(self.row_index, self.pk0[i])
                    == self.expected_pk_generation_commitments[i],
                "PK commitment mismatch",
            );
        }
        let unused_crp: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
        let circuit: PkAggregation<N, H, L, BIT_PK> = PkAggregation::new(
            self.configs,
            unused_crp,
            self.expected_pk_generation_commitments,
            self.pk0,
            self.pk0_agg,
        );
        circuit.execute_opened_with_crp_commitment(self.crs_row_commitment)
    }
}

/// The generated row commitments must equal the in-circuit hash of each CRS row, or every l-BFV
/// aggregation proof would commit to a key that does not match its `pk1`.
/// [`LbfvPkAggregation::execute`] summing the parties' `pk0` rows while still packed (see
/// `math::packed_sum`). `pk0_carriers[party][limb]` are the carriers `lbfv_pk_generation` hashed
/// into the party's row commitment; they open that commitment directly, and the centred aggregate
/// is derived from their sum, so it needs no witness or range check of its own. Returns the same
/// commitment as the coefficient-wise circuit.
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

#[test]
fn test_generated_crs_row_commitments_match_the_rows() {
    for row in 0..GADGET_DIM {
        let expected = compute_multiple_polynomial_commitment::<N, L, PK_AGGREGATION_BIT_PK>(
            LBFV_CRS_GADGET_ROWS[row],
            DS_PK_AGGREGATION,
        );
        assert(LBFV_CRS_ROW_COMMITMENTS[row] == expected);
    }
}

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

fn lbfv_fixture(row_index: u32, commitment_row: u32) -> LbfvPkAggregation<4, 3, 2, 7> {
    let (pk0, pk0_agg) = fixture_pk0();
    let crp = [Polynomial::new([1, 2, 3, 4]), Polynomial::new([5, 6, 7, 8])];
    let mut commitments = [0; 3];
    for i in 0..3 {
        commitments[i] = compute_lbfv_pk_row_commitment::<4, 2, 7>(commitment_row, pk0[i]);
    }
    let crp_commitment = compute_multiple_polynomial_commitment::<4, 2, 7>(crp, DS_PK_AGGREGATION);
    LbfvPkAggregation::new(
        Configs::new([101, 97]),
        row_index,
        crp_commitment,
        commitments,
        pk0,
        pk0_agg,
    )
}

/// The l-BFV path returns what C5's `execute` returns for the same key and CRS row, while opening
/// each party row in the l-BFV row form.
#[test]
fn test_lbfv_aggregation_matches_c5_on_the_same_row() {
    let (pk0, pk0_agg) = fixture_pk0();
    let crp = [Polynomial::new([1, 2, 3, 4]), Polynomial::new([5, 6, 7, 8])];
    let mut c1_commitments = [0; 3];
    for i in 0..3 {
        c1_commitments[i] = compute_threshold_pk_commitment_checked::<4, 2, 7>(pk0[i]);
    }
    let full: PkAggregation<4, 3, 2, 7> =
        PkAggregation::new(Configs::new([101, 97]), crp, c1_commitments, pk0, pk0_agg);
    assert(lbfv_fixture(2, 2).execute() == full.execute());
}

/// A row commitment bound to another row does not open.
#[test(should_fail_with = "PK commitment mismatch")]
fn test_lbfv_aggregation_rejects_another_rows_commitment() {
    let _ = lbfv_fixture(2, 3).execute();
}

/// C1-form commitments (what this circuit wrongly accepted before) do not open.
#[test(should_fail_with = "PK commitment mismatch")]
fn test_lbfv_aggregation_rejects_c1_form_commitments() {
    let (pk0, pk0_agg) = fixture_pk0();
    let mut c1_commitments = [0; 3];
    for i in 0..3 {
        c1_commitments[i] = compute_threshold_pk_commitment_checked::<4, 2, 7>(pk0[i]);
    }
    let crp = [Polynomial::new([1, 2, 3, 4]), Polynomial::new([5, 6, 7, 8])];
    let crp_commitment = compute_multiple_polynomial_commitment::<4, 2, 7>(crp, DS_PK_AGGREGATION);
    let lbfv: LbfvPkAggregation<4, 3, 2, 7> = LbfvPkAggregation::new(
        Configs::new([101, 97]),
        2,
        crp_commitment,
        c1_commitments,
        pk0,
        pk0_agg,
    );
    let _ = lbfv.execute();
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

/// The coefficient-wise circuit on `fixture_pk0` at the four-slot width, row commitments for
/// `commitment_row`.
fn wide_lbfv_fixture(row_index: u32, commitment_row: u32) -> LbfvPkAggregation<4, 3, 2, 50> {
    let (pk0, pk0_agg) = fixture_pk0();
    let crp = [Polynomial::new([1, 2, 3, 4]), Polynomial::new([5, 6, 7, 8])];
    let mut commitments = [0; 3];
    for i in 0..3 {
        commitments[i] = compute_lbfv_pk_row_commitment::<4, 2, 50>(commitment_row, pk0[i]);
    }
    let crp_commitment = compute_multiple_polynomial_commitment::<4, 2, 50>(crp, DS_PK_AGGREGATION);
    LbfvPkAggregation::new(
        Configs::new([101, 97]),
        row_index,
        crp_commitment,
        commitments,
        pk0,
        pk0_agg,
    )
}

#[test]
fn test_packed_lbfv_aggregation_matches_the_coefficient_wise_circuit() {
    let (pk0, _) = fixture_pk0();
    let circuit = wide_lbfv_fixture(2, 2);
    let packed = packed_lbfv_pk_aggregation::<4, 3, 2, 50>(
        [101, 97],
        2,
        circuit.crs_row_commitment,
        circuit.expected_pk_generation_commitments,
        packed_fixture_carriers(pk0),
    );
    assert(packed == circuit.execute());
}

#[test(should_fail_with = "PK commitment mismatch")]
fn test_packed_lbfv_aggregation_rejects_another_rows_commitment() {
    let (pk0, _) = fixture_pk0();
    let circuit = wide_lbfv_fixture(2, 3);
    let _ = packed_lbfv_pk_aggregation::<4, 3, 2, 50>(
        [101, 97],
        2,
        circuit.crs_row_commitment,
        circuit.expected_pk_generation_commitments,
        packed_fixture_carriers(pk0),
    );
}
