// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Cross-circuit commitment consistency links.
//!
//! Concrete implementations of [`CommitmentLink`](e3_events::CommitmentLink)
//! for each ZK proof pair. The trait and supporting types live in `e3-events`.

pub mod c0_to_c3;
pub mod c1_to_c2;
pub mod c1_to_c5;
pub mod c2_to_c3;
pub mod c2_to_c4;
pub mod c4a_to_c6;
pub mod c4b_to_c6;
pub mod c6_to_c7;
pub mod lbfv_generation_sk;
pub mod lbfv_share_transport;

// Re-export the canonical trait and types from e3-events.
pub use e3_events::{CommitmentLink, FieldValue, LinkScope};
use e3_fhe_params::BfvPreset;

/// Returns the default set of commitment links to register.
///
/// C4→C6 links verify that C4's aggregated share commitment matches C6's
/// `expected_sk_commitment` / `expected_e_sm_commitment`. The C4 circuit
/// normalizes its aggregated polynomial (reverse + center per CRT modulus)
/// before hashing, matching the representation C6's Rust witness computes.
///
/// C3→C4 links are replaced by C2→C4: C2 directly outputs share commitments
/// that C4 consumes as `expected_commitments`. Since C2→C3 already ensures
/// C3 encrypts the correct share, C2→C4 closes the remaining gap (preventing
/// a party from using different commitments in C4 than they computed in C2).
///
/// The C1 links apply on the trBFV path only. The l-BFV path proves no C1: its generation rows
/// bind `sk` instead ([`lbfv_generation_sk`]), and its C2b chunk leaves bound `e_sm`.
pub fn default_links(preset: BfvPreset) -> Vec<Box<dyn CommitmentLink>> {
    let l = preset.metadata().num_moduli;
    let lbfv = e3_fhe_params::is_lbfv_path(preset);
    // C2's public signals around its share commitments: the l-BFV chunk finalizer has a child VK
    // hash and the secret root before them and the batch VK hash after; the trBFV single C2 proof
    // has only its `expected_secret_commitment` before them.
    let (c2_prefix_fields, c2_suffix_fields) = if lbfv { (2, 1) } else { (1, 0) };
    let mut links: Vec<Box<dyn CommitmentLink>> = vec![
        Box::new(c0_to_c3::C3aToC0PkCommitmentLink),
        Box::new(c0_to_c3::C3bToC0PkCommitmentLink),
    ];
    if lbfv {
        links.push(Box::new(
            lbfv_generation_sk::LbfvPkToRlkGenerationSkCommitmentLink,
        ));
        links.push(Box::new(
            lbfv_generation_sk::C2aToLbfvPkGenerationSkCommitmentLink,
        ));
        links.push(Box::new(
            lbfv_generation_sk::C2aToRlkGenerationSkCommitmentLink,
        ));
    } else {
        links.push(Box::new(c1_to_c2::C1ToC2aSkCommitmentLink));
        links.push(Box::new(c1_to_c2::C1ToC2bESmCommitmentLink));
        links.push(Box::new(c1_to_c5::C1ToC5PkCommitmentLink));
    }
    let shared: [Box<dyn CommitmentLink>; 7] = [
        Box::new(c2_to_c3::C3aToC2aShareEncryptionLink { chunked: lbfv }),
        Box::new(c2_to_c3::C3bToC2bShareEncryptionLink { chunked: lbfv }),
        Box::new(c2_to_c4::C2aToC4aShareCommitmentLink {
            l,
            source_prefix_fields: c2_prefix_fields,
            source_suffix_fields: c2_suffix_fields,
        }),
        Box::new(c2_to_c4::C2bToC4bShareCommitmentLink {
            l,
            source_prefix_fields: c2_prefix_fields,
            source_suffix_fields: c2_suffix_fields,
        }),
        Box::new(c6_to_c7::C6ToC7DCommitmentLink),
        Box::new(c4a_to_c6::C4aToC6SkCommitmentLink),
        Box::new(c4b_to_c6::C4bToC6ESmCommitmentLink),
    ];
    links.extend(shared);
    links
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::ProofType;

    fn link_pairs(preset: BfvPreset) -> Vec<(ProofType, ProofType)> {
        default_links(preset)
            .iter()
            .map(|link| (link.source_proof_type(), link.target_proof_type()))
            .collect()
    }

    #[test]
    fn c1_links_apply_on_the_trbfv_path_only() {
        let touches_c1 = |(source, target): &(ProofType, ProofType)| {
            *source == ProofType::C1PkGeneration || *target == ProofType::C1PkGeneration
        };
        let binds_rows_to_c2a = (
            ProofType::C2aSkShareComputation,
            ProofType::LbfvPkGeneration,
        );

        for preset in [
            BfvPreset::SecureThreshold16384,
            BfvPreset::InsecureThresholdLbfv,
        ] {
            let pairs = link_pairs(preset);
            assert!(!pairs.iter().any(touches_c1), "{preset:?}");
            assert!(pairs.contains(&binds_rows_to_c2a), "{preset:?}");
            assert!(pairs.contains(&(ProofType::C2aSkShareComputation, ProofType::RlkGeneration)));
            assert!(pairs.contains(&(ProofType::LbfvPkGeneration, ProofType::RlkGeneration)));
        }
        for preset in [BfvPreset::SecureThreshold8192, BfvPreset::InsecureThreshold] {
            let pairs = link_pairs(preset);
            assert_eq!(pairs.iter().filter(|pair| touches_c1(pair)).count(), 3);
            assert!(!pairs.contains(&binds_rows_to_c2a), "{preset:?}");
        }
    }
}
