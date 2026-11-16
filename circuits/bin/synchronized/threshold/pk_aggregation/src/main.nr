// SPDX-License-Identifier: LGPL-3.0-only

//! Disabled C5 definition. Reuses the bounded aggregation statement with threshold parameters.

use lib::configs::synchronized::sync_insecure_64::{
    AGGREGATE_BIT, CRP, H, L_THRESHOLD, N, QIS_THRESHOLD,
};
use lib::core::threshold::pk_aggregation::{Configs, PkAggregation};
use lib::math::polynomial::Polynomial;

fn main(
    expected_threshold_pk_commitments: pub [Field; H],
    pk0: [[Polynomial<N>; L_THRESHOLD]; H],
    pk0_agg: [Polynomial<N>; L_THRESHOLD],
) -> pub Field {
    PkAggregation::<N, H, L_THRESHOLD, AGGREGATE_BIT>::new(
        Configs::new(QIS_THRESHOLD),
        CRP,
        expected_threshold_pk_commitments,
        pk0,
        pk0_agg,
    )
        .execute()
}
