// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::core::threshold::pk_aggregation::{Configs, PkAggregation};
use crate::math::polynomial::Polynomial;

/// Threshold l-BFV public-key aggregation for one fixed CRS row.
pub struct LbfvPkAggregation<let N: u32, let H: u32, let L: u32, let BIT_PK: u32> {
    configs: Configs<L>,
    crs_row: [Polynomial<N>; L],
    expected_pk_generation_commitments: [Field; H],
    pk0: [[Polynomial<N>; L]; H],
    pk0_agg: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32, let BIT_PK: u32> LbfvPkAggregation<N, H, L, BIT_PK> {
    pub fn new(
        configs: Configs<L>,
        crs_row: [Polynomial<N>; L],
        expected_pk_generation_commitments: [Field; H],
        pk0: [[Polynomial<N>; L]; H],
        pk0_agg: [Polynomial<N>; L],
    ) -> Self {
        LbfvPkAggregation { configs, crs_row, expected_pk_generation_commitments, pk0, pk0_agg }
    }

    /// Apply the audited C5 relation to the selected l-BFV CRS row.
    pub fn execute(self) -> Field {
        let circuit: PkAggregation<N, H, L, BIT_PK> = PkAggregation::new(
            self.configs,
            self.crs_row,
            self.expected_pk_generation_commitments,
            self.pk0,
            self.pk0_agg,
        );
        circuit.execute()
    }
}
