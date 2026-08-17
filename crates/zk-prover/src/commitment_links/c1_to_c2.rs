// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C1 (PkGeneration) → C2a/C2b (ShareComputation) secret commitment links.
//!
//! ## Circuit layouts
//!
//! **C1 (PkGeneration)** outputs `(sk_commitment, pk_commitment, e_sm_commitment)`.
//! Public signals contain 3 fields (no public inputs):
//! - field 0: `sk_commitment`   (byte offset   0..32)
//! - field 1: `pk_commitment`   (byte offset  32..64)
//! - field 2: `e_sm_commitment` (byte offset  64..96)
//!
//! **C2a/C2b** expose the recursive child VK hash at field 0 and the
//! expected secret root commitment at field 1 (chunk-finalizer proof).
//!
//! ## Checks
//!
//! - **C1→C2a**: `C1.sk_commitment` must equal `C2a.expected_secret_commitment`.
//!   Prevents a party from Shamir-splitting a different sk than the one committed
//!   to in their C1 (TrBFV pk_generation) proof.
//!
//! - **C1→C2b**: `C1.e_sm_commitment` must equal `C2b.expected_secret_commitment`.
//!   Prevents a party from Shamir-splitting a different e_sm than the one committed
//!   to in their C1 proof.

use super::{CommitmentLink, FieldValue, LinkScope};
use e3_events::{CircuitName, ProofType};
use e3_zk_helpers::FIELD_BYTE_LEN;

/// C1 → C2a: `sk_commitment` from PkGeneration must match C2a's `expected_secret_commitment`.
pub struct C1ToC2aSkCommitmentLink;

impl CommitmentLink for C1ToC2aSkCommitmentLink {
    fn name(&self) -> &'static str {
        "C1->C2a sk_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C1PkGeneration
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C2aSkShareComputation
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SameParty
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        let layout = CircuitName::PkGeneration.output_layout();
        let Some(bytes) = layout.extract_field(public_signals, "sk_commitment") else {
            return vec![];
        };
        let mut value = [0u8; FIELD_BYTE_LEN];
        value.copy_from_slice(bytes);
        vec![value]
    }

    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        if source_values.is_empty() || target_public_signals.len() < 2 * FIELD_BYTE_LEN {
            return false;
        }
        target_public_signals[FIELD_BYTE_LEN..2 * FIELD_BYTE_LEN] == source_values[0]
    }
}

/// C1 → C2b: `e_sm_commitment` from PkGeneration must match C2b's `expected_secret_commitment`.
pub struct C1ToC2bESmCommitmentLink;

impl CommitmentLink for C1ToC2bESmCommitmentLink {
    fn name(&self) -> &'static str {
        "C1->C2b e_sm_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C1PkGeneration
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C2bESmShareComputation
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SameParty
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        let layout = CircuitName::PkGeneration.output_layout();
        let Some(bytes) = layout.extract_field(public_signals, "e_sm_commitment") else {
            return vec![];
        };
        let mut value = [0u8; FIELD_BYTE_LEN];
        value.copy_from_slice(bytes);
        vec![value]
    }

    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        if source_values.is_empty() || target_public_signals.len() < 2 * FIELD_BYTE_LEN {
            return false;
        }
        target_public_signals[FIELD_BYTE_LEN..2 * FIELD_BYTE_LEN] == source_values[0]
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

    /// C1 public signals: [sk_commitment, pk_commitment, e_sm_commitment]
    fn c1_signals(sk: [u8; 32], pk: [u8; 32], esm: [u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(96);
        v.extend_from_slice(&sk);
        v.extend_from_slice(&pk);
        v.extend_from_slice(&esm);
        v
    }

    /// C2 terminal public signals: [child_vk_hash, expected_secret_commitment] + share commitments...
    fn c2_signals(secret_commitment: [u8; 32], share_commitments: &[[u8; 32]]) -> Vec<u8> {
        let mut v = Vec::with_capacity(64 + share_commitments.len() * 32);
        v.extend_from_slice(&make_field(0xFE));
        v.extend_from_slice(&secret_commitment);
        for c in share_commitments {
            v.extend_from_slice(c);
        }
        v
    }

    // ── C1→C2a ──────────────────────────────────────────────────────────────

    #[test]
    fn extract_sk_commitment_from_c1() {
        let link = C1ToC2aSkCommitmentLink;
        let sk = make_field(1);
        let values = link.extract_source_values(&c1_signals(sk, make_field(2), make_field(3)));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], sk);
    }

    #[test]
    fn c2a_consistency_passes_when_sk_matches() {
        let link = C1ToC2aSkCommitmentLink;
        let sk = make_field(42);
        let c2 = c2_signals(sk, &[make_field(10), make_field(11)]);
        assert!(link.check_signals(&[sk], &c2));
    }

    #[test]
    fn c2a_consistency_fails_when_sk_differs() {
        let link = C1ToC2aSkCommitmentLink;
        let c2 = c2_signals(make_field(99), &[make_field(10)]);
        assert!(!link.check_signals(&[make_field(42)], &c2));
    }

    #[test]
    fn c2a_does_not_match_the_child_vk_field() {
        let link = C1ToC2aSkCommitmentLink;
        let sk = make_field(42);
        let mut c2 = Vec::new();
        c2.extend_from_slice(&sk);
        c2.extend_from_slice(&make_field(99));
        assert!(!link.check_signals(&[sk], &c2));
    }

    #[test]
    fn c2a_short_or_empty_signals() {
        let link = C1ToC2aSkCommitmentLink;
        // C1 too short to extract sk_commitment
        assert!(link.extract_source_values(&[0u8; 60]).is_empty());
        // Empty source values
        assert!(!link.check_signals(&[], &c2_signals(make_field(1), &[])));
        // C2 target too short
        assert!(!link.check_signals(&[make_field(1)], &[0u8; 10]));
    }

    // ── C1→C2b ──────────────────────────────────────────────────────────────

    #[test]
    fn extract_esm_commitment_from_c1() {
        let link = C1ToC2bESmCommitmentLink;
        let esm = make_field(7);
        let values = link.extract_source_values(&c1_signals(make_field(1), make_field(2), esm));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], esm);
    }

    #[test]
    fn c2b_consistency_passes_when_esm_matches() {
        let link = C1ToC2bESmCommitmentLink;
        let esm = make_field(77);
        let c2 = c2_signals(esm, &[make_field(10), make_field(11)]);
        assert!(link.check_signals(&[esm], &c2));
    }

    #[test]
    fn c2b_consistency_fails_when_esm_differs() {
        let link = C1ToC2bESmCommitmentLink;
        let c2 = c2_signals(make_field(99), &[make_field(10)]);
        assert!(!link.check_signals(&[make_field(77)], &c2));
    }

    #[test]
    fn c2b_short_or_empty_signals() {
        let link = C1ToC2bESmCommitmentLink;
        // C1 too short to extract e_sm_commitment (need 96 bytes, providing 64)
        assert!(link.extract_source_values(&[0u8; 64]).is_empty());
        // Empty source values
        assert!(!link.check_signals(&[], &c2_signals(make_field(1), &[])));
        // C2 target too short
        assert!(!link.check_signals(&[make_field(1)], &[0u8; 10]));
    }
}
