// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Public-key and threshold-plaintext aggregation.
//!
//! Implementation is grouped by the `committee_finalization`,
//! `public_key_aggregation`, and `plaintext_aggregation` capabilities. The private
//! [`actors`], [`workflow`], and [`domain`] modules are compatibility views that
//! preserve established Rust paths; they do not define the filesystem layout.

mod actors;
mod domain;
pub mod ext;
mod repo;
#[cfg(test)]
mod test_support;
mod workflow;

pub(crate) use actors::*;
pub use actors::{
    Collecting, CommitteeFinalizer, CommitteeFinalizerRecoveryState, Complete, Computing,
    GeneratingC7Proof, PublicKeyAggregatorRecoveryState, PublicKeyAggregatorState,
    RecoveredCommitteeRequest, ThresholdPlaintextAggregatorRecoveryState,
    ThresholdPlaintextAggregatorState, VerifyingC6, COMMITTEE_FINALIZER_RECOVERY_SCHEMA_VERSION,
};
pub use repo::*;
