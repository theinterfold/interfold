// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Deterministic threshold-plaintext (decryption) aggregation workflow.
//!
//! This module holds the [`ThresholdPlaintextAggregatorState`] state machine plus the pure
//! transition/decision functions used by the `ThresholdPlaintextAggregator` actor. Nothing
//! here touches actix, `Persistable`, or the event bus: the actor feeds inputs in, gets a
//! next-state or a decision back, and performs the persistence/publish/dispatch side effects
//! itself.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Result};
use e3_events::CircuitName;
use e3_events::{
    DecryptionAggregationJobRequest, EventContext, PartyProofsToVerify, Proof, Seed, Sequenced,
    SignedProofPayload,
};
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::circuits::commitments::compute_threshold_decryption_share_commitment;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::MAX_MSG_NON_ZERO_COEFFS;
use e3_zk_helpers::threshold::share_decryption::{Bits as C6Bits, Bounds as C6Bounds};
use e3_zk_helpers::Computation;
use tracing::{info, warn};

#[path = "intents.rs"]
mod intents;
#[path = "state.rs"]
mod state;
#[path = "transitions.rs"]
mod transitions;

pub(crate) use intents::{build_decryption_aggregation_jobs, format_decrypted_plaintext};
pub use state::{
    Collecting, Complete, Computing, GeneratingC7Proof, ThresholdPlaintextAggregatorState,
    VerifyingC6,
};
pub(crate) use transitions::ThresholdPlaintextAggregation;

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
