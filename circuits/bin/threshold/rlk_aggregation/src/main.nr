// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::{H, N_PARTIES};
use lib::configs::default::threshold::{
    GADGET_DIM, L, N, RLK_AGGREGATION_BIT_D, RLK_AGGREGATION_CONFIGS,
};
use lib::core::threshold::lbfv_proof_domain::{
    LbfvAcceptedPartySet, LbfvProofSession, validate_aggregation_statement,
};
use lib::core::threshold::rlk_aggregation::RlkAggregation;
use lib::math::polynomial::Polynomial;

/// l-BFV: this circuit aggregates H honest parties' RLK `(d0, d2)` contributions
/// for one gadget row, returning `(commit(d0_agg), commit(d2_agg))`. The same
/// compiled circuit is reused for every row `row_index in 0..GADGET_DIM`.
///
/// `d1`/`a` are not circuit inputs here: both are compile-time constants
/// pinned by the verification key (same as `pk_generation`/`pk_aggregation`'s
/// `CRP`), so binding them into this proof's output would be redundant.
/// `row_index` is a public input and is constrained to the compiled gadget-row range.
///
/// TODO: when folding lands, this may be replaced/supplemented by a batched
/// entry point that loops all GADGET_DIM rows into one proof instead of one
/// row per invocation.
fn main(
    session_id_hi: pub Field,
    session_id_lo: pub Field,
    aggregator_party_id: pub u32,
    accepted_party_set_hash_hi: pub Field,
    accepted_party_set_hash_lo: pub Field,
    row_index: pub u32,
    expected_d0_commitments: pub [Field; H],
    expected_d2_commitments: pub [Field; H],
    d0: [[Polynomial<N>; L]; H],
    d2: [[Polynomial<N>; L]; H],
    d0_agg: [Polynomial<N>; L],
    d2_agg: [Polynomial<N>; L],
) -> pub (Field, Field) {
    validate_aggregation_statement::<N_PARTIES, GADGET_DIM>(
        LbfvProofSession { session_id_hi, session_id_lo },
        aggregator_party_id,
        LbfvAcceptedPartySet {
            hash_hi: accepted_party_set_hash_hi,
            hash_lo: accepted_party_set_hash_lo,
        },
        row_index,
    );

    let rlk_aggregation: RlkAggregation<N, H, L, RLK_AGGREGATION_BIT_D> = RlkAggregation::new(
        RLK_AGGREGATION_CONFIGS,
        expected_d0_commitments,
        expected_d2_commitments,
        d0,
        d2,
        d0_agg,
        d2_agg,
    );

    rlk_aggregation.execute()
}
