// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Legacy C1 to l-BFV public-key generation secret-key commitment link.

use super::{CommitmentLink, FieldValue, LinkScope};
use e3_events::{CircuitName, ProofType};
use e3_zk_helpers::FIELD_BYTE_LEN;

/// Require every l-BFV public-key row to use the secret key bound by C1.
pub struct C1ToLbfvPkGenerationSkCommitmentLink;

impl CommitmentLink for C1ToLbfvPkGenerationSkCommitmentLink {
    fn name(&self) -> &'static str {
        "l-BFV PK generation->C1 sk_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::LbfvPkGeneration
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C1PkGeneration
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SameParty
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        let Some(bytes) = CircuitName::LbfvPkGeneration
            .output_layout()
            .extract_field(public_signals, "sk_commitment")
        else {
            return Vec::new();
        };
        let mut value = [0u8; FIELD_BYTE_LEN];
        value.copy_from_slice(bytes);
        vec![value]
    }

    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        let Some(target) = CircuitName::PkGeneration
            .output_layout()
            .extract_field(target_public_signals, "sk_commitment")
        else {
            return false;
        };
        source_values.first().is_some_and(|source| target == source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_each_generation_row_to_the_c1_secret_key_output() {
        let link = C1ToLbfvPkGenerationSkCommitmentLink;
        let mut lbfv_rows = vec![vec![0u8; 6 * FIELD_BYTE_LEN]; 5];
        let mut c1 = vec![0u8; 3 * FIELD_BYTE_LEN];
        c1[31] = 7;

        for lbfv in &mut lbfv_rows {
            lbfv[4 * FIELD_BYTE_LEN + 31] = 7;
            let source = link.extract_source_values(lbfv);
            assert!(link.check_signals(&source, &c1));
        }

        c1[31] = 8;
        for lbfv in &lbfv_rows {
            let source = link.extract_source_values(lbfv);
            assert!(!link.check_signals(&source, &c1));
        }
    }
}
