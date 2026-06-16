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
pub fn default_links(preset: BfvPreset) -> Vec<Box<dyn CommitmentLink>> {
    let l = preset.metadata().num_moduli;
    vec![
        Box::new(c0_to_c3::C3aToC0PkCommitmentLink),
        Box::new(c0_to_c3::C3bToC0PkCommitmentLink),
        Box::new(c1_to_c2::C1ToC2aSkCommitmentLink),
        Box::new(c1_to_c2::C1ToC2bESmCommitmentLink),
        Box::new(c1_to_c5::C1ToC5PkCommitmentLink),
        Box::new(c2_to_c3::C3aToC2aShareEncryptionLink),
        Box::new(c2_to_c3::C3bToC2bShareEncryptionLink),
        Box::new(c2_to_c4::C2aToC4aShareCommitmentLink { l }),
        Box::new(c2_to_c4::C2bToC4bShareCommitmentLink { l }),
        Box::new(c6_to_c7::C6ToC7DCommitmentLink),
        Box::new(c4a_to_c6::C4aToC6SkCommitmentLink),
        Box::new(c4b_to_c6::C4bToC6ESmCommitmentLink),
    ]
}
