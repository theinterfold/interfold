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

fn session(hi: Field, lo: Field) -> LbfvProofSession {
    LbfvProofSession { session_id_hi: hi, session_id_lo: lo }
}

fn party_set(hi: Field, lo: Field) -> LbfvAcceptedPartySet {
    LbfvAcceptedPartySet { hash_hi: hi, hash_lo: lo }
}

/// The largest canonical limb and the last in-range party and row are accepted.
#[test]
fn test_generation_statement_accepts_the_domain_edges() {
    let max_limb = 0xffffffffffffffffffffffffffffffff;
    validate_generation_statement::<3, 2>(session(max_limb, 0), 2, 1);
}

#[test(should_fail_with = "l-BFV hash limb is not canonical")]
fn test_generation_statement_rejects_a_limb_of_128_bits_or_more() {
    validate_generation_statement::<3, 2>(session(0x100000000000000000000000000000000, 0), 0, 0);
}

#[test(should_fail_with = "l-BFV hash limb is not canonical")]
fn test_generation_statement_rejects_a_non_canonical_low_limb() {
    validate_generation_statement::<3, 2>(session(0, 0x100000000000000000000000000000000), 0, 0);
}

#[test(should_fail_with = "party_id out of range")]
fn test_generation_statement_rejects_party_id_equal_to_the_committee_size() {
    validate_generation_statement::<3, 2>(session(0, 0), 3, 0);
}

#[test(should_fail_with = "row_index out of range")]
fn test_generation_statement_rejects_row_index_equal_to_the_row_count() {
    validate_generation_statement::<3, 2>(session(0, 0), 0, 2);
}

#[test]
fn test_aggregation_statement_accepts_the_domain_edges() {
    let max_limb = 0xffffffffffffffffffffffffffffffff;
    validate_aggregation_statement::<3, 2>(
        session(max_limb, max_limb),
        2,
        party_set(max_limb, max_limb),
        1,
    );
}

#[test(should_fail_with = "l-BFV hash limb is not canonical")]
fn test_aggregation_statement_rejects_a_non_canonical_session_limb() {
    validate_aggregation_statement::<3, 2>(
        session(0x100000000000000000000000000000000, 0),
        0,
        party_set(0, 0),
        0,
    );
}

#[test(should_fail_with = "l-BFV hash limb is not canonical")]
fn test_aggregation_statement_rejects_a_non_canonical_party_set_limb() {
    validate_aggregation_statement::<3, 2>(
        session(0, 0),
        0,
        party_set(0, 0x100000000000000000000000000000000),
        0,
    );
}

#[test(should_fail_with = "aggregator_party_id out of range")]
fn test_aggregation_statement_rejects_aggregator_id_equal_to_the_committee_size() {
    validate_aggregation_statement::<3, 2>(session(0, 0), 3, party_set(0, 0), 0);
}

#[test(should_fail_with = "row_index out of range")]
fn test_aggregation_statement_rejects_row_index_equal_to_the_row_count() {
    validate_aggregation_statement::<3, 2>(session(0, 0), 0, party_set(0, 0), 2);
}
