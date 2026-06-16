// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C2 (ShareComputation) → C3 (ShareEncryption) message commitment link.
//!
//! C2's inner circuit outputs per-party-per-modulus share commitments via
//! `commit_to_party_shares`. C3 claims `expected_message_commitment` which must
//! match the commitment C2 produced for the share being encrypted.
//!
//! The signed C2 proof is the **inner** circuit proof (SkShareComputation /
//! ESmShareComputation, `CircuitVariant::Recursive`). Its public signals layout:
//!   - field 0: `expected_secret_commitment` (public input, skip)
//!   - fields 1..(N_PARTIES × L_THRESHOLD): share commitments from `commit_to_party_shares`
//!
//! Source is C3 (the claimant — it declares what commitment it encrypts).
//! Target is C2 (the provider — it produced the actual share commitments).
//! Fault is attributed to C3 when its `expected_message_commitment` does not
//! appear anywhere in C2's share commitment section.
//!
//! C2a/C3a and C2b/C3b use the same Noir circuits (`ShareComputation` /
//! `ShareEncryption`) but different [`ProofType`] values, so we register two links.

use super::{CommitmentLink, FieldValue, LinkScope};
use e3_events::{CircuitName, ProofType};
use e3_zk_helpers::FIELD_BYTE_LEN;

/// C3a → C2a: SK share encryption `expected_message_commitment` vs SK share
/// computation per-party share commitment outputs.
pub struct C3aToC2aShareEncryptionLink;

impl CommitmentLink for C3aToC2aShareEncryptionLink {
    fn name(&self) -> &'static str {
        "C3a->C2a expected_message_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C3aSkShareEncryption
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C2aSkShareComputation
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SameParty
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        extract_message_commitment(public_signals)
    }

    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        commitment_in_c2_outputs(source_values, target_public_signals)
    }
}

/// C3b → C2b: E_SM share encryption `expected_message_commitment` vs E_SM share
/// computation per-party share commitment outputs.
pub struct C3bToC2bShareEncryptionLink;

impl CommitmentLink for C3bToC2bShareEncryptionLink {
    fn name(&self) -> &'static str {
        "C3b->C2b expected_message_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C3bESmShareEncryption
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C2bESmShareComputation
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SameParty
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        extract_message_commitment(public_signals)
    }

    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        commitment_in_c2_outputs(source_values, target_public_signals)
    }
}

/// Extract `expected_message_commitment` from a C3 proof's public signals.
///
/// C3 public signals layout (from `CircuitInputLayout::Fixed`):
///   - field 0: `expected_pk_commitment`   (HEAD position 0)
///   - field 1: `expected_message_commitment` (HEAD position 1)
fn extract_message_commitment(public_signals: &[u8]) -> Vec<FieldValue> {
    let layout = CircuitName::ShareEncryption.input_layout();
    let Some(bytes) = layout.extract_field(public_signals, "expected_message_commitment") else {
        return vec![];
    };
    let mut value = [0u8; FIELD_BYTE_LEN];
    value.copy_from_slice(bytes);
    vec![value]
}

/// Check whether `source_values[0]` (from a C3 proof) appears in the share
/// commitment section of a C2 inner proof's public signals.
///
/// C2 inner circuit public signals layout:
///   - field 0:       `expected_secret_commitment` (public input, skipped)
///   - fields 1..:    `commit_to_party_shares[party_idx][mod_idx]` outputs
///
/// Barretenberg's `noir-recursive` variant sometimes doubles the signal
/// buffer (448 = 2×224 bytes for a 7-field circuit).  We detect and
/// deduplicate this before scanning.
fn commitment_in_c2_outputs(source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
    if source_values.is_empty() {
        return false;
    }
    let expected = &source_values[0];
    let signals = deduplicate(target_public_signals);
    // Skip first field (expected_secret_commitment public input).
    if signals.len() < 2 * FIELD_BYTE_LEN {
        return false;
    }
    signals[FIELD_BYTE_LEN..]
        .chunks(FIELD_BYTE_LEN)
        .any(|chunk| chunk == expected.as_slice())
}

/// If the signal buffer is a perfect duplication of its first half, return the
/// first half.  Otherwise return the original slice unchanged.
fn deduplicate(signals: &[u8]) -> &[u8] {
    if signals.len() >= 2 * FIELD_BYTE_LEN && signals.len().is_multiple_of(2 * FIELD_BYTE_LEN) {
        let half = signals.len() / 2;
        if signals[..half] == signals[half..] {
            return &signals[..half];
        }
    }
    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_field(val: u8) -> [u8; 32] {
        let mut f = [0u8; 32];
        f[31] = val;
        f
    }

    /// C3 signals: [expected_pk_commitment (32B)] + [expected_message_commitment (32B)]
    fn c3_signals(pk: [u8; 32], msg: [u8; 32]) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v[0..32].copy_from_slice(&pk);
        v[32..64].copy_from_slice(&msg);
        v
    }

    /// C2 inner signals: [expected_secret_commitment] + N share commitments.
    fn c2_signals(commitments: &[[u8; 32]]) -> Vec<u8> {
        let mut v = vec![0u8; 32 + commitments.len() * 32];
        v[0..32].copy_from_slice(&make_field(0xFF)); // expected_secret_commitment
        for (i, c) in commitments.iter().enumerate() {
            v[32 + i * 32..32 + (i + 1) * 32].copy_from_slice(c);
        }
        v
    }

    #[test]
    fn extract_message_commitment_from_c3() {
        let link = C3aToC2aShareEncryptionLink;
        let msg = make_field(42);
        let vals = link.extract_source_values(&c3_signals(make_field(99), msg));
        assert_eq!(vals.len(), 1);
        assert_eq!(vals[0], msg);
    }

    #[test]
    fn consistency_passes_when_commitment_found_in_c2() {
        let link = C3aToC2aShareEncryptionLink;
        let msg = make_field(42);
        let c2 = c2_signals(&[make_field(1), make_field(2), msg, make_field(4)]);
        assert!(link.check_signals(&[msg], &c2));
    }

    #[test]
    fn consistency_fails_when_commitment_absent() {
        let link = C3aToC2aShareEncryptionLink;
        let msg = make_field(42);
        let c2 = c2_signals(&[make_field(1), make_field(2), make_field(3)]);
        assert!(!link.check_signals(&[msg], &c2));
    }

    #[test]
    fn consistency_ignores_first_field_secret_commitment() {
        // The first field is expected_secret_commitment and must not be matched.
        let link = C3aToC2aShareEncryptionLink;
        let msg = make_field(0xFF); // same value as the secret_commitment placeholder
        let c2 = c2_signals(&[make_field(1)]); // share commitments don't include 0xFF
        assert!(!link.check_signals(&[msg], &c2));
    }

    #[test]
    fn consistency_handles_bb_duplicated_buffer() {
        let link = C3aToC2aShareEncryptionLink;
        let msg = make_field(42);
        let half = c2_signals(&[make_field(1), msg, make_field(3)]);
        // Simulate BB doubling the buffer.
        let doubled = [half.clone(), half].concat();
        assert!(link.check_signals(&[msg], &doubled));
    }

    #[test]
    fn short_or_empty_signals() {
        let link = C3aToC2aShareEncryptionLink;
        assert!(link.extract_source_values(&[]).is_empty());
        assert!(link.extract_source_values(&[0u8; 31]).is_empty());
        assert!(!link.check_signals(&[], &c2_signals(&[make_field(1)])));
        // C2 signals too short to have any share commitments after skipping first field.
        assert!(!link.check_signals(&[make_field(1)], &[0u8; 32]));
    }

    #[test]
    fn c3b_link_works_same_as_c3a() {
        let link = C3bToC2bShareEncryptionLink;
        let msg = make_field(7);
        let c2 = c2_signals(&[make_field(1), msg]);
        assert!(link.check_signals(&[msg], &c2));
        assert!(!link.check_signals(&[make_field(8)], &c2));
    }
}
