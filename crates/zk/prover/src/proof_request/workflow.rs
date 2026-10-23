// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Deterministic proof-request workflow dispatch and completion.
//!
//! The [`crate::actors::proof_request::ProofRequestActor`] is a thin transport
//! shell: it owns the event bus and signer and performs all publish/sign I/O.
//! This module owns the business logic — the per-E3 pending-proof state machines
//! (which proofs have arrived, when a set is complete) and the deterministic
//! dispatch *planning* (which proof requests to emit, in what order, with which
//! `seq` index). It has NO actix / `BusHandle` / signing concerns.

use std::collections::HashMap;
use std::sync::Arc;

use e3_events::{
    DkgShareDecryptionProofRequest, E3id, EncryptionKey, EventContext, PkAggregationProofRequest,
    PkGenerationProofRequest, Proof, Sequenced, ShareComputationProofRequest,
    ShareEncryptionProofRequest, ThresholdShare, ZkRequest,
};
use e3_utils::utility_types::ArcBytes;

#[path = "state.rs"]
mod state;
#[path = "transitions.rs"]
mod transitions;

pub(crate) use state::{
    DecryptionProofKind, NodeAggregationMeta, PendingAggregationProof, PendingDecryptionProofs,
    PendingPkAggregationProof, PendingProofRequest, PendingShareDecryptionProof,
    PendingThresholdProofs, ThresholdProofKind,
};
pub(crate) use transitions::{plan_decryption_dispatch, plan_threshold_dispatch};

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
