// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::H;
use lib::configs::default::threshold::{CRP, L, N, PK_AGGREGATION_BIT_PK, PK_AGGREGATION_CONFIGS};
use lib::core::threshold::pk_aggregation::PkAggregation;
use lib::math::polynomial::Polynomial;

fn main(
    expected_threshold_pk_commitments: pub [Field; H],
    pk0: [[Polynomial<N>; L]; H],
    pk0_agg: [Polynomial<N>; L],
) -> pub Field {
    let pk_aggregation: PkAggregation<N, H, L, PK_AGGREGATION_BIT_PK> = PkAggregation::new(
        PK_AGGREGATION_CONFIGS,
        CRP,
        expected_threshold_pk_commitments,
        pk0,
        pk0_agg,
    );

    pk_aggregation.execute()
}
