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
    compute_multiple_polynomial_commitment, compute_threshold_pk_commitment_checked,
    DS_PK_AGGREGATION,
};
use crate::math::polynomial::Polynomial;

/// Threshold l-BFV public-key aggregation for one fixed CRS row.
///
/// The row's `pk1` is the fixed CRS row, so its commitment is the generated constant
/// `LBFV_CRS_ROW_COMMITMENTS[row]` rather than a hash of the row computed in-circuit.
pub struct LbfvPkAggregation<let N: u32, let H: u32, let L: u32, let BIT_PK: u32> {
    configs: Configs<L>,
    crs_row_commitment: Field,
    expected_pk_generation_commitments: [Field; H],
    pk0: [[Polynomial<N>; L]; H],
    pk0_agg: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32, let BIT_PK: u32> LbfvPkAggregation<N, H, L, BIT_PK> {
    pub fn new(
        configs: Configs<L>,
        crs_row_commitment: Field,
        expected_pk_generation_commitments: [Field; H],
        pk0: [[Polynomial<N>; L]; H],
        pk0_agg: [Polynomial<N>; L],
    ) -> Self {
        LbfvPkAggregation {
            configs,
            crs_row_commitment,
            expected_pk_generation_commitments,
            pk0,
            pk0_agg,
        }
    }

    /// Apply the audited C5 relation to the selected l-BFV CRS row.
    pub fn execute(self) -> Field {
        let unused_crp: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
        let circuit: PkAggregation<N, H, L, BIT_PK> = PkAggregation::new(
            self.configs,
            unused_crp,
            self.expected_pk_generation_commitments,
            self.pk0,
            self.pk0_agg,
        );
        circuit.execute_with_crp_commitment(self.crs_row_commitment)
    }
}

/// The generated row commitments must equal the in-circuit hash of each CRS row, or every l-BFV
/// aggregation proof would commit to a key that does not match its `pk1`.
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

/// `execute_with_crp_commitment` must return what `execute` returns for the same row. Same
/// fixture as `pk_aggregation`'s tests: three parties, `N = 4`, `q = [101, 97]`.
#[test]
fn test_crp_commitment_path_matches_hashing_the_row() {
    let configs = Configs::new([101, 97]);
    let pk0 = [
        [Polynomial::new([50, 0 - 50, 10, 0]), Polynomial::new([48, 0 - 48, 5, 7])],
        [Polynomial::new([50, 0 - 50, 20, 1]), Polynomial::new([48, 0 - 48, 5, 0 - 7])],
        [Polynomial::new([50, 0 - 50, 0 - 30, 2]), Polynomial::new([48, 0 - 48, 5, 1])],
    ];
    let pk0_agg = [Polynomial::new([49, 0 - 49, 0, 3]), Polynomial::new([47, 0 - 47, 15, 1])];
    let crp = [Polynomial::new([1, 2, 3, 4]), Polynomial::new([5, 6, 7, 8])];
    let mut commitments = [0; 3];
    for i in 0..3 {
        commitments[i] = compute_threshold_pk_commitment_checked::<4, 2, 7>(pk0[i]);
    }

    let full: PkAggregation<4, 3, 2, 7> =
        PkAggregation::new(configs, crp, commitments, pk0, pk0_agg);
    let crp_commitment = compute_multiple_polynomial_commitment::<4, 2, 7>(crp, DS_PK_AGGREGATION);
    let lbfv: LbfvPkAggregation<4, 3, 2, 7> =
        LbfvPkAggregation::new(configs, crp_commitment, commitments, pk0, pk0_agg);
    assert(lbfv.execute() == full.execute());
}
