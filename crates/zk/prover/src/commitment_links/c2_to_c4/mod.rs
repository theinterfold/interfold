// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C2a/C2b (ShareComputation) → C4a/C4b (ShareDecryption)
//! share-commitment consistency links.
//!
//! ## Purpose
//!
//! Each C2 proof outputs per-party-per-modulus share commitments via
//! `commit_to_party_shares`. The aggregator's C4 proof must list those same
//! values in its `expected_commitments` input array. This link verifies that
//! every share computed in C2 has a matching decryption expectation in C4.
//!
//! ## Direction
//!
//! Source is C2 (the sender's share-computation proof), target is C4 (the
//! recipient/aggregator's share-decryption proof). C2 and C4 are produced by
//! different parties. Fault is attributed to the C2 sender if its L share
//! commitments for the C4 recipient do not exactly match the corresponding
//! row in C4's `expected_commitments`.
//!
//! ## C2 terminal public signals layout
//!
//! ```text
//! [child_vk_hash (32 B, skip)]
//! [secret_root_commitment (32 B, skip)]
//! [party_0_mod_0 (32 B)] [party_0_mod_1] ... [party_0_mod_{L-1}]
//! [party_1_mod_0] ...
//! [party_{N-1}_mod_{L-1}]
//! [trailing field (32 B, skip): the hash of the C2 chain's chunk keys on trBFV, the batch VK hash
//!  on l-BFV]
//! ```
//!
//! On trBFV the first field is the `expected_secret_commitment` public input and is skipped; on
//! l-BFV the first two are the child VK hash and the secret root commitment. The remaining
//! N_PARTIES × L fields are share commitments output by the C2 proof (trBFV) or the chunk
//! finalizer (l-BFV), indexed in row-major order (party first, then modulus).
//!
//! ## C4 public signals layout
//!
//! ```text
//! [expected_commitments[0][0] (32 B)] ... [expected_commitments[0][L-1]]
//! [expected_commitments[1][0]] ...
//! [expected_commitments[H-1][L-1]]
//! [commitment (32 B, aggregated output)]
//! [key_tree (32 B, hash of the limb keys, last; trBFV only)]
//! ```
//!
//! ## Precise check
//!
//! Given:
//! - `src_party_id` = C2 sender's row in the selected H-party roster (= X)
//! - `tgt_party_id` = C4 recipient's index in the full N-party committee (= R)
//!
//! The L commitments from C2 at slot R (`source_values[R*L .. (R+1)*L]`)
//! must exactly match C4's selected row X (`expected_commitments[X][0..L]`).
//! The caller maps the sender's full-committee ID to this row.
//! This verifies all L moduli, not just one.
//!
//! ## Scope
//!
//! `SourceMustExistInTargets` — C2 is produced by the sender, C4 by the
//! aggregator/recipient; they are different parties. Fault is attributed to C2
//! if its L share commitments for the C4 recipient do not appear at the correct
//! row in any C4 proof.

use super::{CommitmentLink, FieldValue, LinkScope};
use e3_events::ProofType;
use e3_zk_config::FIELD_BYTE_LEN;

/// C2a (SkShareComputation) → C4a (SkShareDecryption) commitment link.
pub struct C2aToC4aShareCommitmentLink {
    /// Number of threshold CRT moduli (L). Determines the block size in both
    /// C2 and C4 public signals.
    pub l: usize,
    /// Whether the C2 source is the l-BFV chunk finalizer and the target the chunked C4.
    pub chunked: bool,
}

impl CommitmentLink for C2aToC4aShareCommitmentLink {
    fn name(&self) -> &'static str {
        "C2a->C4a share commitments"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C2aSkShareComputation
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C4aSkShareDecryption
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SourceMustExistInTargets
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        extract_share_commitments(public_signals, self.chunked)
    }

    fn check_consistency(
        &self,
        source_values: &[FieldValue],
        target_public_signals: &[u8],
        src_party_id: u64,
        tgt_party_id: u64,
    ) -> bool {
        check_exact_l_commitments(
            source_values,
            target_public_signals,
            src_party_id,
            tgt_party_id,
            self.l,
            c4_output_fields(self.chunked),
        )
    }
}

/// C2b (ESmShareComputation) → C4b (ESmShareDecryption) commitment link.
pub struct C2bToC4bShareCommitmentLink {
    /// Number of threshold CRT moduli (L).
    pub l: usize,
    /// Whether the C2 source is the l-BFV chunk finalizer and the target the chunked C4.
    pub chunked: bool,
}

impl CommitmentLink for C2bToC4bShareCommitmentLink {
    fn name(&self) -> &'static str {
        "C2b->C4b share commitments"
    }

    fn source_proof_type(&self) -> ProofType {
        ProofType::C2bESmShareComputation
    }

    fn target_proof_type(&self) -> ProofType {
        ProofType::C4bESmShareDecryption
    }

    fn scope(&self) -> LinkScope {
        LinkScope::SourceMustExistInTargets
    }

    fn extract_source_values(&self, public_signals: &[u8]) -> Vec<FieldValue> {
        extract_share_commitments(public_signals, self.chunked)
    }

    fn check_consistency(
        &self,
        source_values: &[FieldValue],
        target_public_signals: &[u8],
        src_party_id: u64,
        tgt_party_id: u64,
    ) -> bool {
        check_exact_l_commitments(
            source_values,
            target_public_signals,
            src_party_id,
            tgt_party_id,
            self.l,
            c4_output_fields(self.chunked),
        )
    }
}

/// The outputs a C4 proof returns after its rows: the l-BFV chunked circuit returns only the
/// aggregate commitment, the trBFV one also its limb key tree.
fn c4_output_fields(chunked: bool) -> usize {
    if chunked {
        1
    } else {
        2
    }
}

/// Extract all share commitments from C2's public signals ([`super::c2_share_commitments`]), in
/// row-major order (party first, modulus second).
fn extract_share_commitments(public_signals: &[u8], chunked: bool) -> Vec<FieldValue> {
    super::c2_share_commitments(public_signals, chunked)
        .chunks(FIELD_BYTE_LEN)
        .filter_map(|chunk| {
            if chunk.len() == FIELD_BYTE_LEN {
                let mut value = [0u8; FIELD_BYTE_LEN];
                value.copy_from_slice(chunk);
                Some(value)
            } else {
                None
            }
        })
        .collect()
}

/// Precise L-way check: verifies that the L share commitments C2_X computed
/// for recipient R exactly match C4_R's expected_commitments row for sender X.
///
/// - `source_values`: C2 commitments after the explicit prefix and before the
///   trailing batch VK hash
/// - `target_public_signals`: C4_R's public signals
/// - `src_party_id`: C2 sender's row X in the selected H-party roster
/// - `tgt_party_id`: C4 recipient R in the full N-party committee
/// - `l`: number of CRT moduli
///
/// Extracts `source_values[R*L .. (R+1)*L]` and checks it equals
/// `target_public_signals[X*L*32 .. (X+1)*L*32]`.
fn check_exact_l_commitments(
    source_values: &[FieldValue],
    target_public_signals: &[u8],
    src_party_id: u64,
    tgt_party_id: u64,
    l: usize,
    target_output_fields: usize,
) -> bool {
    if source_values.is_empty() || l == 0 {
        return false;
    }

    let tgt_idx = tgt_party_id as usize;
    let src_idx = src_party_id as usize;

    if source_values.len() % l != 0 {
        return false;
    }

    // Slice L commits from C2 at slot tgt_idx (the C4 recipient's position).
    let Some(c2_start) = tgt_idx.checked_mul(l) else {
        return false;
    };
    let Some(c2_end) = c2_start.checked_add(l) else {
        return false;
    };
    if source_values.len() < c2_end {
        return false;
    }
    let c2_block = &source_values[c2_start..c2_end];

    // C4 row for src_idx (the C2 sender): bytes [X*L*32 .. (X+1)*L*32].
    // C4's outputs follow the rows: the aggregate commitment, then on trBFV the limb key tree.
    let Some(c4_row_start) = src_idx
        .checked_mul(l)
        .and_then(|offset| offset.checked_mul(FIELD_BYTE_LEN))
    else {
        return false;
    };
    let Some(c4_row_len) = l.checked_mul(FIELD_BYTE_LEN) else {
        return false;
    };
    let Some(c4_row_end) = c4_row_start.checked_add(c4_row_len) else {
        return false;
    };
    let Some(c4_min_len) = target_output_fields
        .checked_mul(FIELD_BYTE_LEN)
        .and_then(|outputs| c4_row_end.checked_add(outputs))
    else {
        return false;
    };
    if target_public_signals.len() < c4_min_len {
        return false;
    }

    // Verify all L commitments match exactly.
    c2_block.iter().enumerate().all(|(i, expected)| {
        let offset = c4_row_start + i * FIELD_BYTE_LEN;
        &target_public_signals[offset..offset + FIELD_BYTE_LEN] == expected.as_slice()
    })
}

#[cfg(test)]
mod tests;
