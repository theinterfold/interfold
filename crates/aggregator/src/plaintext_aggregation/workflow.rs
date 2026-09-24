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
    DecryptionAggregationJobRequest, PartyProofsToVerify, Proof, Seed, SignedProofPayload,
};
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;

#[path = "intents.rs"]
mod intents;
#[path = "state.rs"]
mod state;
#[path = "transitions.rs"]
mod transitions;
#[path = "validation.rs"]
mod validation;

pub(crate) use intents::{build_decryption_aggregation_jobs, format_decrypted_plaintext};
pub use state::{
    Collecting, Complete, Computing, GeneratingC7Proof, QueuedDecryptionShare,
    ThresholdPlaintextAggregatorRecoveryState, ThresholdPlaintextAggregatorState, VerifyingC6,
    THRESHOLD_PLAINTEXT_RECOVERY_SCHEMA_VERSION,
};
pub(crate) use transitions::ThresholdPlaintextAggregation;
pub(crate) use validation::C6ShareVerifier;

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
