// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Canonical field limbs of the versioned l-BFV proof-session identifier.
pub struct LbfvProofSession {
    pub session_id_hi: Field,
    pub session_id_lo: Field,
}

/// Canonical field limbs of the accepted aggregation party-set hash.
pub struct LbfvAcceptedPartySet {
    pub hash_hi: Field,
    pub hash_lo: Field,
}

fn assert_canonical_limb(value: Field) {
    assert(value == (value as u128) as Field, "l-BFV hash limb is not canonical");
}

/// Validate the common generation statement before the circuit proves its row relation.
pub fn validate_generation_statement<let N_PARTIES: u32, let N_ROWS: u32>(
    session: LbfvProofSession,
    party_id: u32,
    row_index: u32,
) {
    assert_canonical_limb(session.session_id_hi);
    assert_canonical_limb(session.session_id_lo);
    assert(party_id < N_PARTIES, "party_id out of range");
    assert(row_index < N_ROWS, "row_index out of range");
}

/// Validate the common aggregation statement before the circuit proves its row relation.
pub fn validate_aggregation_statement<let N_PARTIES: u32, let N_ROWS: u32>(
    session: LbfvProofSession,
    aggregator_party_id: u32,
    accepted_party_set: LbfvAcceptedPartySet,
    row_index: u32,
) {
    assert_canonical_limb(session.session_id_hi);
    assert_canonical_limb(session.session_id_lo);
    assert_canonical_limb(accepted_party_set.hash_hi);
    assert_canonical_limb(accepted_party_set.hash_lo);
    assert(aggregator_party_id < N_PARTIES, "aggregator_party_id out of range");
    assert(row_index < N_ROWS, "row_index out of range");
}
