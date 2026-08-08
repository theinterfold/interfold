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
//! [expected_secret_commitment (32 B, skip)]
//! [party_0_mod_0 (32 B)] [party_0_mod_1] ... [party_0_mod_{L-1}]
//! [party_1_mod_0] ...
//! [party_{N-1}_mod_{L-1}]
//! ```
//!
//! The first two fields are the child VK hash and `expected_secret_commitment`.
//! The remaining N_PARTIES × L fields are share commitments output by
//! `commit_to_party_shares`, indexed in row-major order (party first, then
//! modulus).
//!
//! ## C4 public signals layout
//!
//! ```text
//! [expected_commitments[0][0] (32 B)] ... [expected_commitments[0][L-1]]
//! [expected_commitments[1][0]] ...
//! [expected_commitments[H-1][L-1]]
//! [commitment (32 B, TAIL aggregated output)]
//! ```
//!
//! ## Precise check
//!
//! Given:
//! - `src_party_id` = C2 sender's 0-based committee index (= X)
//! - `tgt_party_id` = C4 recipient's 0-based committee index (= R)
//!
//! The L commitments from C2 at slot R (`source_values[R*L .. (R+1)*L]`)
//! must exactly match C4's row X (`expected_commitments[X][0..L]`).
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
use e3_zk_helpers::FIELD_BYTE_LEN;

/// C2a (SkShareComputation) → C4a (SkShareDecryption) commitment link.
pub struct C2aToC4aShareCommitmentLink {
    /// Number of threshold CRT moduli (L). Determines the block size in both
    /// C2 and C4 public signals.
    pub l: usize,
    /// Number of non-commitment fields at the start of the C2 terminal proof.
    pub source_prefix_fields: usize,
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
        extract_share_commitments(public_signals, self.source_prefix_fields)
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
        )
    }
}

/// C2b (ESmShareComputation) → C4b (ESmShareDecryption) commitment link.
pub struct C2bToC4bShareCommitmentLink {
    /// Number of threshold CRT moduli (L).
    pub l: usize,
    /// Number of non-commitment fields at the start of the C2 terminal proof.
    pub source_prefix_fields: usize,
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
        extract_share_commitments(public_signals, self.source_prefix_fields)
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
        )
    }
}

/// Extract all share commitments after the explicit C2 terminal prefix.
fn extract_share_commitments(
    public_signals: &[u8],
    source_prefix_fields: usize,
) -> Vec<FieldValue> {
    let prefix_bytes = source_prefix_fields.saturating_mul(FIELD_BYTE_LEN);
    if source_prefix_fields == 0 || public_signals.len() < prefix_bytes {
        return vec![];
    }
    public_signals[prefix_bytes..]
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
/// - `source_values`: C2 commitments after the legacy prefix; chunked layouts
///   still contain the child-VK field until this function removes it
/// - `target_public_signals`: C4_R's public signals
/// - `src_party_id`: C2 sender X (0-based committee index)
/// - `tgt_party_id`: C4 recipient R (0-based committee index)
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
    // C4 must also have the aggregated output as the last field.
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
    if target_public_signals.len() < c4_row_end + FIELD_BYTE_LEN {
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
