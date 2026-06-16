// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C4b (ESM share decryption) → C6 (ThresholdShareDecryption) e_sm_commitment link.
//!
//! C4b outputs a single `commitment` field (the e_sm_commitment).
//! C6 takes `expected_e_sm_commitment` as a public input.

use super::{CommitmentLink, FieldValue, LinkScope};
use e3_events::{CircuitName, ProofType};
use e3_zk_helpers::FIELD_BYTE_LEN;

pub struct C4bToC6ESmCommitmentLink;

impl CommitmentLink for C4bToC6ESmCommitmentLink {
    fn name(&self) -> &'static str {
        "C4b->C6 e_sm_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C4bESmShareDecryption
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C6ThresholdShareDecryption
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SameParty
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        let layout = CircuitName::DkgShareDecryption.output_layout();
        let Some(bytes) = layout.extract_field(public_signals, "commitment") else {
            return vec![];
        };
        let mut value = [0u8; FIELD_BYTE_LEN];
        value.copy_from_slice(bytes);
        vec![value]
    }

    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        if source_values.is_empty() {
            return false;
        }
        let layout = CircuitName::ThresholdShareDecryption.input_layout();
        layout
            .extract_field(target_public_signals, "expected_e_sm_commitment")
            .is_some_and(|extracted| extracted == source_values[0].as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_field(val: u8) -> [u8; 32] {
        let mut f = [0u8; 32];
        f[31] = val;
        f
    }

    #[test]
    fn extract_commitment_from_c4b() {
        let link = C4bToC6ESmCommitmentLink;
        let signals = make_field(77);
        let values = link.extract_source_values(&signals);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], make_field(77));
    }

    #[test]
    fn consistency_passes_when_esm_matches() {
        let link = C4bToC6ESmCommitmentLink;
        let esm_commitment = make_field(99);
        let source_values = vec![esm_commitment];

        let mut c6_signals = Vec::new();
        c6_signals.extend_from_slice(&make_field(42));
        c6_signals.extend_from_slice(&esm_commitment);
        c6_signals.extend_from_slice(&make_field(1));

        assert!(link.check_signals(&source_values, &c6_signals));
    }

    #[test]
    fn consistency_fails_when_esm_differs() {
        let link = C4bToC6ESmCommitmentLink;
        let source_values = vec![make_field(99)];

        let mut c6_signals = Vec::new();
        c6_signals.extend_from_slice(&make_field(42));
        c6_signals.extend_from_slice(&make_field(42));
        c6_signals.extend_from_slice(&make_field(1));

        assert!(!link.check_signals(&source_values, &c6_signals));
    }

    #[test]
    fn short_signals() {
        let link = C4bToC6ESmCommitmentLink;
        assert!(link.extract_source_values(&[0u8; 10]).is_empty());
        // Empty source values means malformed proof — should be inconsistent
        assert!(!link.check_signals(&[], &[0u8; 3 * FIELD_BYTE_LEN]));
    }
}
