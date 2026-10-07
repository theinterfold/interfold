// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Public IO layout of the node fold proofs (must stay aligned with the `node_fold`,
//! `node_fold_chunked` and `node_fold_v2` mains). The trBFV path's [`CircuitName::NodeFold`] ends
//! with the SK/ESM aggregate commitments. The l-BFV path's [`CircuitName::NodeFoldChunked`] adds
//! two C2 chunk hashes after the key hash and a recursive VK manifest after the commitments, and
//! [`CircuitName::NodeFoldV2`] wraps it behind a prefix.

use crate::circuits::utils::bytes_to_field_strings;
use crate::error::ZkError;
use e3_events::{CircuitName, DkgFoldAggCommits, Proof};

const NODE_FOLD_V2_PUBLIC_PREFIX_LEN: usize = 4;

/// Total public field count for `node_fold` at committee size `n`, honest `h`, threshold moduli `l`.
pub fn node_fold_public_field_count(n: usize, h: usize, l: usize) -> usize {
    11 + n + 2 * (n + h) * l
}

/// Total public field count for `node_fold_chunked`: `node_fold`'s plus the two C2 chunk hashes
/// and the VK manifest.
pub fn node_fold_chunked_public_field_count(n: usize, h: usize, l: usize) -> usize {
    node_fold_public_field_count(n, h, l) + 3
}

/// Total public field count for the V2 node fold.
pub fn node_fold_v2_public_field_count(n: usize, h: usize, l: usize) -> usize {
    NODE_FOLD_V2_PUBLIC_PREFIX_LEN + node_fold_chunked_public_field_count(n, h, l) + 3 + (3 * l)
}

fn field_hex_to_bytes32(field: &str) -> Result<[u8; 32], ZkError> {
    let s = field.strip_prefix("0x").unwrap_or(field);
    if s.len() > 64 {
        return Err(ZkError::InvalidInput(format!(
            "field hex too long for bytes32: {field}"
        )));
    }
    let mut out = [0u8; 32];
    let decoded = hex::decode(s).map_err(|e| ZkError::InvalidInput(e.to_string()))?;
    let start = 32usize.saturating_sub(decoded.len());
    out[start..].copy_from_slice(&decoded);
    Ok(out)
}

fn field_hex_to_u64(field: &str) -> Result<u64, ZkError> {
    let s = field.strip_prefix("0x").unwrap_or(field);
    let trimmed = s.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    u64::from_str_radix(trimmed, 16).map_err(|e| ZkError::InvalidInput(e.to_string()))
}

/// Read `party_id`, `sk_agg_commit`, and `esm_agg_commit` from a `NodeFold` proof.
pub fn extract_node_fold_agg_commits(
    proof: &Proof,
    committee_n: usize,
    committee_h: usize,
    n_moduli: usize,
) -> Result<(u64, DkgFoldAggCommits), ZkError> {
    // (party_id index, field count, sk commitment index); the ESM commitment follows the SK one.
    let chunked = node_fold_chunked_public_field_count(committee_n, committee_h, n_moduli);
    let (party_idx, expected, sk_commitment_idx) = match proof.circuit {
        CircuitName::NodeFold => {
            let count = node_fold_public_field_count(committee_n, committee_h, n_moduli);
            (0, count, count - 2)
        }
        CircuitName::NodeFoldChunked => (0, chunked, chunked - 3),
        CircuitName::NodeFoldV2 => (
            NODE_FOLD_V2_PUBLIC_PREFIX_LEN,
            node_fold_v2_public_field_count(committee_n, committee_h, n_moduli),
            NODE_FOLD_V2_PUBLIC_PREFIX_LEN + chunked - 3,
        ),
        other => {
            return Err(ZkError::InvalidInput(format!(
                "expected a node fold proof, got {other}"
            )))
        }
    };
    let fields = bytes_to_field_strings(proof.public_signals.as_ref())?;
    if fields.len() != expected {
        return Err(ZkError::InvalidInput(format!(
            "{} public field count {} != expected {} (n={committee_n}, h={committee_h}, l={n_moduli})",
            proof.circuit,
            fields.len(),
            expected
        )));
    }
    let party_id = field_hex_to_u64(&fields[party_idx])?;
    let esm_commitment_idx = sk_commitment_idx + 1;
    let sk_agg_commit = field_hex_to_bytes32(&fields[sk_commitment_idx])?;
    let esm_agg_commit = field_hex_to_bytes32(&fields[esm_commitment_idx])?;
    Ok((
        party_id,
        DkgFoldAggCommits {
            sk_agg_commit,
            esm_agg_commit,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_utils::ArcBytes;

    #[test]
    fn extracts_expected_fields_from_golden_layout_vector() {
        // Golden layout vector: verifies positional extraction
        // (party_id at index 0, sk/esm commits at tail).
        let n = 3usize;
        let h = 3usize;
        let l = 2usize;
        let field_count = node_fold_public_field_count(n, h, l);

        let mut fields = vec![[0u8; 32]; field_count];
        fields[0][31] = 2; // party_id = 2
        fields[field_count - 2] = [0x11; 32];
        fields[field_count - 1] = [0x22; 32];

        let mut public_signals = Vec::with_capacity(field_count * 32);
        for f in fields {
            public_signals.extend_from_slice(&f);
        }

        let proof = Proof::new(
            CircuitName::NodeFold,
            ArcBytes::from_bytes(&[]),
            ArcBytes::from_bytes(&public_signals),
        );

        let (party_id, commits) =
            extract_node_fold_agg_commits(&proof, n, h, l).expect("extract should succeed");
        assert_eq!(party_id, 2);
        assert_eq!(commits.sk_agg_commit, [0x11; 32]);
        assert_eq!(commits.esm_agg_commit, [0x22; 32]);
    }

    #[test]
    fn extracts_legacy_commitments_from_the_v2_prefix() {
        let n = 3usize;
        let h = 2usize;
        let l = 5usize;
        let legacy_field_count = node_fold_chunked_public_field_count(n, h, l);
        let field_count = node_fold_v2_public_field_count(n, h, l);

        let mut fields = vec![[0u8; 32]; field_count];
        fields[NODE_FOLD_V2_PUBLIC_PREFIX_LEN][31] = 2;
        fields[NODE_FOLD_V2_PUBLIC_PREFIX_LEN + legacy_field_count - 3] = [0x11; 32];
        fields[NODE_FOLD_V2_PUBLIC_PREFIX_LEN + legacy_field_count - 2] = [0x22; 32];
        fields[field_count - 3] = [0x33; 32];
        fields[field_count - 2] = [0x44; 32];

        let mut public_signals = Vec::with_capacity(field_count * 32);
        for field in fields {
            public_signals.extend_from_slice(&field);
        }

        let proof = Proof::new(
            CircuitName::NodeFoldV2,
            ArcBytes::from_bytes(&[]),
            ArcBytes::from_bytes(&public_signals),
        );

        let (party_id, commits) =
            extract_node_fold_agg_commits(&proof, n, h, l).expect("extract should succeed");
        assert_eq!(party_id, 2);
        assert_eq!(commits.sk_agg_commit, [0x11; 32]);
        assert_eq!(commits.esm_agg_commit, [0x22; 32]);
    }

    #[test]
    fn extracts_commitments_before_the_chunked_manifest() {
        let (n, h, l) = (3usize, 2usize, 3usize);
        let field_count = node_fold_chunked_public_field_count(n, h, l);
        let mut fields = vec![[0u8; 32]; field_count];
        fields[0][31] = 1;
        fields[field_count - 3] = [0x11; 32];
        fields[field_count - 2] = [0x22; 32];
        fields[field_count - 1] = [0x33; 32]; // VK manifest
        let public_signals = fields.into_iter().flatten().collect::<Vec<_>>();
        let proof = Proof::new(
            CircuitName::NodeFoldChunked,
            ArcBytes::from_bytes(&[]),
            ArcBytes::from_bytes(&public_signals),
        );

        let (party_id, commits) =
            extract_node_fold_agg_commits(&proof, n, h, l).expect("extract should succeed");
        assert_eq!(party_id, 1);
        assert_eq!(commits.sk_agg_commit, [0x11; 32]);
        assert_eq!(commits.esm_agg_commit, [0x22; 32]);

        // The same signals under the trBFV circuit name have the wrong length.
        let proof = Proof::new(
            CircuitName::NodeFold,
            ArcBytes::from_bytes(&[]),
            proof.public_signals.clone(),
        );
        assert!(extract_node_fold_agg_commits(&proof, n, h, l).is_err());
    }

    #[test]
    fn v2_field_count_uses_the_preset_row_count() {
        assert_eq!(node_fold_v2_public_field_count(3, 2, 3), 63);
        assert_eq!(node_fold_v2_public_field_count(3, 2, 5), 89);
    }
}
