// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Public-key and threshold-plaintext aggregation.
//!
//! Implementation is grouped by the `public_key_aggregation` and
//! `plaintext_aggregation` capabilities. The private
//! [`actors`], [`workflow`], and [`domain`] modules are compatibility views that
//! preserve established Rust paths; they do not define the filesystem layout.

mod actors;
mod domain;
pub mod ext;
#[path = "public_key_aggregation/lbfv_aggregation_state.rs"]
pub mod lbfv_aggregation_state;
mod repo;
#[cfg(test)]
mod test_support;
mod workflow;

pub(crate) use actors::*;
pub use actors::{
    Collecting, Complete, Computing, GeneratingC7Proof, PublicKeyAggregatorRecoveryState,
    PublicKeyAggregatorState, ThresholdPlaintextAggregatorRecoveryState,
    ThresholdPlaintextAggregatorState, VerifyingC6,
};
pub use domain::lbfv_contribution_collection::*;
pub use lbfv_aggregation_state::*;
pub use repo::*;
