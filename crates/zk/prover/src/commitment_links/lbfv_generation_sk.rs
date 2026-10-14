// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! l-BFV generation secret-key commitment links.
//!
//! The l-BFV path proves no C1. Every l-BFV PK-generation and RLK-generation row proof
//! range-checks the party's `sk` and outputs its chunk root as `sk_commitment`. The C2a chunk
//! finalizer exposes the chunk root of the `sk` it Shamir-splits at field 1.
//!
//! ## Checks
//!
//! - **PK row → RLK row**: the PK and RLK proofs of one row commit the same `sk`.
//! - **C2a → PK rows / RLK rows**: C2a's secret root equals every row's `sk_commitment`. This
//!   prevents a party from sharing an `sk` other than the bounded one its rows prove, and with one
//!   C2a per party it makes all rows of that party commit one `sk`.

use super::{CommitmentLink, FieldValue, LinkScope};
use e3_events::{CircuitName, ProofType};
use e3_zk_helpers::FIELD_BYTE_LEN;

/// Index of C2a's secret root in the chunk finalizer's public signals.
const C2A_SECRET_ROOT_FIELD: usize = 1;

fn row_sk_commitment(circuit: CircuitName, public_signals: &[u8]) -> Option<&[u8]> {
    circuit
        .output_layout()
        .extract_field(public_signals, "sk_commitment")
}

fn c2a_secret_root(public_signals: &[u8]) -> Option<&[u8]> {
    let start = C2A_SECRET_ROOT_FIELD * FIELD_BYTE_LEN;
    public_signals.get(start..start + FIELD_BYTE_LEN)
}

fn field_value(bytes: Option<&[u8]>) -> Vec<FieldValue> {
    let Some(bytes) = bytes else {
        return Vec::new();
    };
    let mut value = [0u8; FIELD_BYTE_LEN];
    value.copy_from_slice(bytes);
    vec![value]
}

/// PK row → RLK row: both proofs of one row commit the same `sk`.
pub struct LbfvPkToRlkGenerationSkCommitmentLink;

impl CommitmentLink for LbfvPkToRlkGenerationSkCommitmentLink {
    fn name(&self) -> &'static str {
        "l-BFV PK generation->RLK generation sk_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::LbfvPkGeneration
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::RlkGeneration
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SameParty
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        field_value(row_sk_commitment(
            CircuitName::LbfvPkGeneration,
            public_signals,
        ))
    }

    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        let Some(target) = row_sk_commitment(CircuitName::RlkGeneration, target_public_signals)
        else {
            return false;
        };
        source_values.first().is_some_and(|source| target == source)
    }
}

/// C2a → PK rows: C2a's secret root equals every PK row's `sk_commitment`.
pub struct C2aToLbfvPkGenerationSkCommitmentLink;

impl CommitmentLink for C2aToLbfvPkGenerationSkCommitmentLink {
    fn name(&self) -> &'static str {
        "C2a->l-BFV PK generation sk_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C2aSkShareComputation
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::LbfvPkGeneration
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SameParty
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        field_value(c2a_secret_root(public_signals))
    }

    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        let Some(target) = row_sk_commitment(CircuitName::LbfvPkGeneration, target_public_signals)
        else {
            return false;
        };
        source_values.first().is_some_and(|source| target == source)
    }
}

/// C2a → RLK rows: C2a's secret root equals every RLK row's `sk_commitment`.
pub struct C2aToRlkGenerationSkCommitmentLink;

impl CommitmentLink for C2aToRlkGenerationSkCommitmentLink {
    fn name(&self) -> &'static str {
        "C2a->RLK generation sk_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C2aSkShareComputation
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::RlkGeneration
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SameParty
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        field_value(c2a_secret_root(public_signals))
    }

    fn check_signals(&self, source_values: &[FieldValue], target_public_signals: &[u8]) -> bool {
        let Some(target) = row_sk_commitment(CircuitName::RlkGeneration, target_public_signals)
        else {
            return false;
        };
        source_values.first().is_some_and(|source| target == source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value: u8) -> [u8; FIELD_BYTE_LEN] {
        let mut field = [0u8; FIELD_BYTE_LEN];
        field[FIELD_BYTE_LEN - 1] = value;
        field
    }

    /// PK row public signals: session hi/lo, party, row, then `sk_commitment`, `pk_commitment`.
    fn pk_row(sk: u8, row: u8) -> Vec<u8> {
        [
            field(1),
            field(2),
            field(3),
            field(row),
            field(sk),
            field(40 + row),
        ]
        .concat()
    }

    /// RLK row public signals: session hi/lo, party, row, then `sk`, `r`, `d0`, `d2` commitments.
    fn rlk_row(sk: u8, row: u8) -> Vec<u8> {
        [
            field(1),
            field(2),
            field(3),
            field(row),
            field(sk),
            field(22),
            field(50 + row),
            field(60 + row),
        ]
        .concat()
    }

    /// C2a finalizer public signals: batch VK hash, secret root, then share roots.
    fn c2a(secret_root: u8) -> Vec<u8> {
        [field(0xFE), field(secret_root), field(10), field(11)].concat()
    }

    #[test]
    fn pk_and_rlk_rows_must_commit_one_sk() {
        let link = LbfvPkToRlkGenerationSkCommitmentLink;
        for row in 0..5 {
            let source = link.extract_source_values(&pk_row(21, row));
            assert!(link.check_signals(&source, &rlk_row(21, row)));
            assert!(!link.check_signals(&source, &rlk_row(22, row)));
        }
    }

    #[test]
    fn c2a_secret_root_must_equal_every_row_sk_commitment() {
        let pk_link = C2aToLbfvPkGenerationSkCommitmentLink;
        let rlk_link = C2aToRlkGenerationSkCommitmentLink;
        let source = pk_link.extract_source_values(&c2a(21));
        assert_eq!(source, rlk_link.extract_source_values(&c2a(21)));
        for row in 0..5 {
            assert!(pk_link.check_signals(&source, &pk_row(21, row)));
            assert!(rlk_link.check_signals(&source, &rlk_row(21, row)));
        }

        // A row of another `sk`, or a C2a sharing another `sk`, is inconsistent.
        assert!(!pk_link.check_signals(&source, &pk_row(22, 3)));
        assert!(!rlk_link.check_signals(&source, &rlk_row(22, 3)));
        let other = pk_link.extract_source_values(&c2a(22));
        assert!(!pk_link.check_signals(&other, &pk_row(21, 0)));
        assert!(!rlk_link.check_signals(&other, &rlk_row(21, 0)));
    }

    #[test]
    fn c2a_root_is_not_the_batch_vk_hash_field() {
        let link = C2aToLbfvPkGenerationSkCommitmentLink;
        let source = link.extract_source_values(&c2a(21));
        assert!(!link.check_signals(&source, &pk_row(0xFE, 0)));
    }

    #[test]
    fn short_or_empty_signals_never_match() {
        let pk_link = C2aToLbfvPkGenerationSkCommitmentLink;
        let row_link = LbfvPkToRlkGenerationSkCommitmentLink;
        assert!(pk_link.extract_source_values(&[0u8; 40]).is_empty());
        assert!(row_link.extract_source_values(&[0u8; 40]).is_empty());
        assert!(!pk_link.check_signals(&[], &pk_row(21, 0)));
        assert!(!pk_link.check_signals(&[field(21)], &[0u8; 10]));
        assert!(!row_link.check_signals(&[field(21)], &[0u8; 10]));
    }
}
