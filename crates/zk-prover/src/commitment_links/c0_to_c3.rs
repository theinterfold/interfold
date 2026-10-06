// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C3a/C3b (ShareEncryption) → C0 (PkBfv) pk_commitment consistency links.
//!
//! Each C3 proof declares an `expected_pk_commitment` (the recipient's
//! individual DKG public key commitment). This link verifies that the
//! declared value matches some C0 proof's `pk_commitment` output.
//!
//! ## Direction
//!
//! Source is C3 (the proof making the claim), target is C0 (the proof that
//! established the commitment). Fault is attributed to the C3 sender if its
//! claimed pk_commitment doesn't match any C0 output.
//!
//! ## Scope
//!
//! `SourceMustExistInTargets` — each C3's `expected_pk_commitment` must
//! appear among the set of C0 `pk_commitment` outputs from any party.

use super::{CommitmentLink, FieldValue, LinkScope};
use e3_events::{CircuitName, ProofType};
use e3_zk_helpers::FIELD_BYTE_LEN;

/// C3a → C0 pk_commitment consistency link.
pub struct C3aToC0PkCommitmentLink;

impl CommitmentLink for C3aToC0PkCommitmentLink {
    fn name(&self) -> &'static str {
        "C3a->C0 pk_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C3aSkShareEncryption
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C0PkBfv
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SourceMustExistInTargets
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        extract_expected_pk_commitment(public_signals)
    }

    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        check_pk_exists_in_c0(source_values, target_public_signals)
    }
}

/// Extract `expected_pk_commitment` from C3's public inputs (HEAD of signals).
fn extract_expected_pk_commitment(public_signals: &[u8]) -> Vec<FieldValue> {
    let layout = CircuitName::ShareEncryption.input_layout();
    let Some(bytes) = layout.extract_field(public_signals, "expected_pk_commitment") else {
        return vec![];
    };
    let mut value = [0u8; FIELD_BYTE_LEN];
    value.copy_from_slice(bytes);
    vec![value]
}

/// Check whether the source's `expected_pk_commitment` matches C0's
/// `pk_commitment` output.
fn check_pk_exists_in_c0(source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
    if source_values.is_empty() {
        return false;
    }
    let layout = CircuitName::PkBfv.output_layout();
    let Some(target_bytes) = layout.extract_field(target_public_signals, "pk_commitment") else {
        return false;
    };
    target_bytes == source_values[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_field(val: u8) -> [u8; 32] {
        let mut f = [0u8; 32];
        f[31] = val;
        f
    }

    /// Build C3 public signals: 2 inputs at HEAD + ciphertext bytes after.
    fn c3_signals(expected_pk: [u8; 32], expected_msg: [u8; 32]) -> Vec<u8> {
        let mut signals = Vec::new();
        signals.extend_from_slice(&expected_pk);
        signals.extend_from_slice(&expected_msg);
        signals
    }

    /// Build C0 public signals: just 1 output (pk_commitment).
    fn c0_signals(pk_commitment: [u8; 32]) -> Vec<u8> {
        pk_commitment.to_vec()
    }

    #[test]
    fn extract_expected_pk_from_c3() {
        let link = C3aToC0PkCommitmentLink;
        let pk = make_field(42);
        let signals = c3_signals(pk, make_field(99));
        let values = link.extract_source_values(&signals);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], pk);
    }

    #[test]
    fn consistency_passes_when_c3_pk_matches_c0() {
        let link = C3aToC0PkCommitmentLink;
        let pk = make_field(42);
        let source_values = vec![pk];
        let target = c0_signals(pk);
        assert!(link.check_signals(&source_values, &target));
    }

    #[test]
    fn consistency_fails_when_c3_pk_doesnt_match_c0() {
        let link = C3aToC0PkCommitmentLink;
        let source_values = vec![make_field(42)];
        let target = c0_signals(make_field(99));
        assert!(!link.check_signals(&source_values, &target));
    }

    #[test]
    fn empty_source_is_inconsistent() {
        let link = C3aToC0PkCommitmentLink;
        assert!(!link.check_signals(&[], &c0_signals(make_field(1))));
    }

    #[test]
    fn short_target_signals_is_inconsistent() {
        let link = C3aToC0PkCommitmentLink;
        assert!(!link.check_signals(&[make_field(1)], &[0u8; 16]));
    }

    #[test]
    fn short_source_signals_returns_empty() {
        let link = C3aToC0PkCommitmentLink;
        assert!(link.extract_source_values(&[0u8; 16]).is_empty());
    }
}
