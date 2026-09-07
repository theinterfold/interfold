// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C1 (PkGeneration) row-to-row secret-key commitment consistency.
//!
//! l-BFV: each party generates `GADGET_DIM` C1 proofs, one per gadget row
//! (`circuits/bin/threshold/pk_generation` proves a single row's `(pk0, a)`
//! pair over `L` CRT limbs and is reused per row — see
//! `circuits/lib/src/configs/{insecure,secure}/threshold.nr`, `CRP_GADGET_ROWS`).
//! All rows must be generated from the same `sk`.
//!
//! This link is self-referential: source and target proof type are both
//! `C1PkGeneration`. Under `LinkScope::SameParty`, `find_mismatches` compares
//! every cached C1 proof for a party against every other cached C1 proof for
//! that party (a proof trivially matches itself), so this enforces pairwise
//! `sk_commitment` equality across all of a party's row proofs without any
//! extra machinery.
//!
//! This is the same-party analogue of Sync Point 1 (`agent/flow-trace/04_DKG_AND_COMPUTATION.md`):
//! catches a party using a different `sk` across rows before other parties
//! depend on that party's output in C3.

use super::{CommitmentLink, FieldValue, LinkScope};
use e3_events::{CircuitName, ProofType};
use e3_zk_helpers::FIELD_BYTE_LEN;

/// C1 row i -> C1 row j (same party): `sk_commitment` must match across all
/// of a party's gadget-row proofs.
pub struct C1RowsSkCommitmentLink;

impl CommitmentLink for C1RowsSkCommitmentLink {
    fn name(&self) -> &'static str {
        "C1 rows sk_commitment"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C1PkGeneration
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C1PkGeneration
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
        if source_values.is_empty() {
            return false;
        }
        let layout = CircuitName::PkGeneration.output_layout();
        let Some(bytes) = layout.extract_field(target_public_signals, "sk_commitment") else {
            return false;
        };
        bytes == source_values[0]
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

    fn c1_row_signals(row: u8, sk: [u8; 32], pk: [u8; 32], esm: [u8; 32]) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[31] = row;
        v.extend_from_slice(&c1_signals(sk, pk, esm));
        v
    }

    #[test]
    fn extract_sk_commitment_from_c1_row() {
        let link = C1RowsSkCommitmentLink;
        let sk = make_field(1);
        let values = link.extract_source_values(&c1_signals(sk, make_field(2), make_field(3)));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], sk);
    }

    #[test]
    fn rows_consistency_passes_when_sk_matches() {
        let link = C1RowsSkCommitmentLink;
        let sk = make_field(42);
        // Another row's proof, different pk/e_sm commitments (different a_j, eek_j)
        // but the same sk_commitment.
        let other_row = c1_row_signals(1, sk, make_field(77), make_field(88));
        assert!(link.check_signals(&[sk], &other_row));
    }

    #[test]
    fn rows_consistency_fails_when_sk_differs() {
        let link = C1RowsSkCommitmentLink;
        let other_row = c1_row_signals(1, make_field(99), make_field(2), make_field(3));
        assert!(!link.check_signals(&[make_field(42)], &other_row));
    }

    #[test]
    fn self_pair_trivially_matches() {
        let link = C1RowsSkCommitmentLink;
        let sk = make_field(7);
        let row = c1_row_signals(1, sk, make_field(1), make_field(2));
        let vals = link.extract_source_values(&row);
        assert!(link.check_signals(&vals, &row));
    }

    #[test]
    fn short_or_empty_signals() {
        let link = C1RowsSkCommitmentLink;
        assert!(link.extract_source_values(&[0u8; 60]).is_empty());
        assert!(!link.check_signals(
            &[],
            &c1_signals(make_field(1), make_field(2), make_field(3))
        ));
        assert!(!link.check_signals(&[make_field(1)], &[0u8; 10]));
    }
}
