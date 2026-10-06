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
pub mod c1_to_lbfv;
pub mod c2_to_c3;
pub mod c2_to_c4;
pub mod c4a_to_c6;
pub mod c6_to_c7;
pub mod lbfv_share_transport;

// Re-export the canonical trait and types from e3-events.
pub use e3_events::{CommitmentLink, FieldValue, LinkScope};
use e3_fhe_params::BfvPreset;

/// Returns the default set of commitment links to register.
///
/// C4→C6 verifies that C4's aggregated share commitment matches C6's
/// `expected_sk_commitment`. The C4 circuit normalizes its aggregated polynomial
/// before hashing, matching the representation C6's Rust witness computes.
///
/// C2→C4 checks that C2's share commitments are the `expected_commitments` C4
/// consumes. C2→C3 already checks that C3 encrypts that share.
pub fn default_links(preset: BfvPreset) -> Vec<Box<dyn CommitmentLink>> {
    let l = preset.metadata().num_moduli;
    vec![
        Box::new(c0_to_c3::C3aToC0PkCommitmentLink),
        Box::new(c1_to_c2::C1ToC2aSkCommitmentLink),
        Box::new(c1_to_c5::C1ToC5PkCommitmentLink),
        Box::new(c1_to_lbfv::C1ToLbfvPkGenerationSkCommitmentLink),
        Box::new(c2_to_c3::C3aToC2aShareEncryptionLink),
        Box::new(c2_to_c4::C2aToC4aShareCommitmentLink {
            l,
            source_prefix_fields: 2,
        }),
        Box::new(c6_to_c7::C6ToC7DCommitmentLink),
        Box::new(c4a_to_c6::C4aToC6SkCommitmentLink),
    ]
}
