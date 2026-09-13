// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::{H, N_PARTIES};
use lib::configs::default::threshold::{
    GADGET_DIM, L, LBFV_CRS_GADGET_ROWS, N, PK_AGGREGATION_BIT_PK, PK_AGGREGATION_CONFIGS,
};
use lib::core::threshold::lbfv_pk_aggregation::LbfvPkAggregation;
use lib::core::threshold::lbfv_proof_domain::{
    LbfvAcceptedPartySet, LbfvProofSession, validate_aggregation_statement,
};
use lib::math::polynomial::Polynomial;

/// Aggregate one row of `H` threshold l-BFV public-key contributions.
fn main(
    session_id_hi: pub Field,
    session_id_lo: pub Field,
    aggregator_party_id: pub u32,
    accepted_party_set_hash_hi: pub Field,
    accepted_party_set_hash_lo: pub Field,
    row_index: pub u32,
    expected_pk_generation_commitments: pub [Field; H],
    pk0: [[Polynomial<N>; L]; H],
    pk0_agg: [Polynomial<N>; L],
) -> pub Field {
    validate_aggregation_statement::<N_PARTIES, GADGET_DIM>(
        LbfvProofSession { session_id_hi, session_id_lo },
        aggregator_party_id,
        LbfvAcceptedPartySet {
            hash_hi: accepted_party_set_hash_hi,
            hash_lo: accepted_party_set_hash_lo,
        },
        row_index,
    );
    let crs_row = LBFV_CRS_GADGET_ROWS[row_index];
    let circuit: LbfvPkAggregation<N, H, L, PK_AGGREGATION_BIT_PK> = LbfvPkAggregation::new(
        PK_AGGREGATION_CONFIGS,
        crs_row,
        expected_pk_generation_commitments,
        pk0,
        pk0_agg,
    );
    circuit.execute()
}
