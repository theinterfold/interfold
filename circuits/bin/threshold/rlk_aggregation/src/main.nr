// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::{H, N_PARTIES};
use lib::configs::default::threshold::{
    GADGET_DIM, L, N, RLK_AGGREGATION_BIT_D, RLK_AGGREGATION_CONFIGS, RLK_GENERATION_BIT_D,
};
use lib::core::threshold::lbfv_proof_domain::{
    LbfvAcceptedPartySet, LbfvProofSession, validate_aggregation_statement,
};
use lib::core::threshold::rlk_aggregation::packed_rlk_aggregation;

/// l-BFV: aggregates `H` honest parties' RLK contributions for one component of one gadget row:
/// `d0` when `component == 0`, `d2` when `component == 1`. Returns `commit(agg)`. The same
/// compiled circuit serves every row and both components, so each row takes two proofs;
/// `lbfv_aggregation_fold` binds them to components 0 and 1.
///
/// `d1`/`a` are not circuit inputs here: both are compile-time constants pinned by the verification
/// key. `row_index` is a public input constrained to the compiled gadget-row range, and `component`
/// is bound through the kind tag of every commitment the circuit opens.
fn main(
    session_id_hi: pub Field,
    session_id_lo: pub Field,
    aggregator_party_id: pub u32,
    accepted_party_set_hash_hi: pub Field,
    accepted_party_set_hash_lo: pub Field,
    row_index: pub u32,
    component: pub u32,
    expected_commitments: pub [Field; H],
    value_carriers: [[[Field; N / 4]; L]; H],
) -> pub Field {
    // Opens the d0/d2 commitments rlk_generation made, so the digit widths must agree.
    assert(RLK_AGGREGATION_BIT_D == RLK_GENERATION_BIT_D);
    validate_aggregation_statement::<N_PARTIES, GADGET_DIM>(
        LbfvProofSession { session_id_hi, session_id_lo },
        aggregator_party_id,
        LbfvAcceptedPartySet {
            hash_hi: accepted_party_set_hash_hi,
            hash_lo: accepted_party_set_hash_lo,
        },
        row_index,
    );

    // The parties' d0 or d2 rows arrive as the carriers rlk_generation packed into their
    // commitments; their centred sum is derived in-circuit (see `math::packed_sum`).
    packed_rlk_aggregation::<N, H, L, RLK_AGGREGATION_BIT_D>(
        RLK_AGGREGATION_CONFIGS.qis,
        row_index,
        component,
        expected_commitments,
        value_carriers,
    )
}
