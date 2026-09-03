// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C1-CKKS (pk share) → C6-CKKS (decryption share) secret-commitment
//! anchor.
//!
//! ## Why a direct C1 → C6 link for CKKS
//!
//! BFV anchors C6's `expected_sk_commitment` through C4a (the DKG
//! share-decryption proof). CKKS has NO C4 round: a party's aggregated
//! share polynomial is derived locally from the dealt rows. What C6-CKKS
//! commits to as `expected_sk_commitment` is the AGGREGATED share (Shamir
//! sum over every dealer's row), which is NOT the dealer secret C1 commits
//! to — so a byte-equality link between the two is not the right check.
//! The anchoring the protocol needs is that the SAME party stands behind
//! both proofs and that C6's commitment is the one every peer can
//! recompute; the aggregator's `d_commitment` cross-check
//! (`verify_ckks_shares_match_c6_commitments`) closes the share-bytes gap
//! and the ShareVerificationActor's signer-slot check closes the identity
//! gap.
//!
//! What THIS link pins is the surface that IS byte-equal across circuits:
//! the C1-CKKS sk commitment (the DKG secret the party dealt) must equal
//! the C8-hybrid `s_commitment` of every digit proof — the ceremony secret
//! IS the DKG secret. That check runs in the CKKS keyshare machine
//! (`check_relin_round_1_bindings`, against the machine's recorded anchor);
//! the link registered here lets the slashing-side consistency checker
//! evaluate the same equality over the cached verified proofs so a
//! mismatch is also slashable evidence.
//!
//! ## Layouts
//!
//! **C1-CKKS** (`pk_generation_ckks_ps<N>`) outputs
//! `(sk commitment, pk_commitment, e_sm_commitment)` — the BFV C1 layout.
//!
//! **C8-CKKS digit** (`relin_round1_hybrid_ckks_digit`) public inputs are
//! `(s_commitment, u_commitment, digit)` at the HEAD of `public_signals`,
//! then the `share_commitment` output at the tail.

use super::{CommitmentLink, FieldValue, LinkScope};
use e3_events::{CircuitName, ProofType};
use e3_zk_helpers::FIELD_BYTE_LEN;

/// C1-CKKS → C8-CKKS: sk commitment must equal every digit proof's
/// `s_commitment`.
pub struct C1CkksToC8SkCommitmentLink;

impl CommitmentLink for C1CkksToC8SkCommitmentLink {
    fn name(&self) -> &'static str {
        "C1-CKKS->C8 sk/s_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C1PkGeneration
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C8RelinRound1
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SameParty
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        // Same output layout for BFV and every CKKS param set.
        let layout = CircuitName::PkGenerationCkksPs0.output_layout();
        let name = e3_zk_helpers::PK_GENERATION_OUTPUTS[0].name;
        let Some(bytes) = layout.extract_field(public_signals, name) else {
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
        let layout = CircuitName::RelinRound1HybridCkksDigit.input_layout();
        let Some(s_c) = layout.extract_field(target_public_signals, "s_commitment") else {
            return false;
        };
        s_c == source_values[0]
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

    fn c1_signals(sk: [u8; 32]) -> Vec<u8> {
        let mut v = sk.to_vec();
        v.extend_from_slice(&make_field(2));
        v.extend_from_slice(&make_field(3));
        v
    }

    fn c8_digit_signals(s: [u8; 32], u: [u8; 32], digit: u8, share: [u8; 32]) -> Vec<u8> {
        let mut v = s.to_vec();
        v.extend_from_slice(&u);
        v.extend_from_slice(&make_field(digit));
        v.extend_from_slice(&share);
        v
    }

    #[test]
    fn c1_sk_commitment_anchors_every_digit_proof() {
        let link = C1CkksToC8SkCommitmentLink;
        let sk = make_field(7);
        let vals = link.extract_source_values(&c1_signals(sk));
        assert_eq!(vals, vec![sk]);
        for digit in 0..13u8 {
            assert!(link.check_signals(
                &vals,
                &c8_digit_signals(sk, make_field(9), digit, make_field(digit))
            ));
        }
        assert!(!link.check_signals(
            &vals,
            &c8_digit_signals(make_field(8), make_field(9), 0, make_field(1))
        ));
        assert!(!link.check_signals(&vals, &[0u8; 16]));
        assert!(!link.check_signals(&[], &c8_digit_signals(sk, sk, 0, sk)));
        assert!(link.extract_source_values(&[0u8; 32]).is_empty());
    }
}
