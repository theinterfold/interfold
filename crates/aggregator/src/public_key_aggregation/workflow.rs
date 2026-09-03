// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Deterministic public-key aggregation workflow.
//!
//! This module holds the [`PublicKeyAggregatorState`] state machine plus the pure
//! transition/decision functions used by the `PublicKeyAggregator` actor. Nothing here
//! touches actix, `Persistable`, or the event bus: the actor feeds inputs in, gets a
//! next-state or a [decision](C1Dispatch)/[`HonestSelection`] back, and performs the
//! persistence/publish/dispatch side effects itself.

use alloy::primitives::Address;
use anyhow::{anyhow, ensure, Context as _, Result};
use e3_events::{
    CircuitName, E3id, OrderedSet, PartyProofsToVerify, Proof, Seed, SignedDkgFoldAttestation,
    SignedProofPayload,
};
use e3_fhe::Fhe;
use e3_utils::ArcBytes;
use e3_zk_helpers::cap_honest_party_ids;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::extract_node_fold_agg_commits;
use std::collections::{BTreeSet, HashMap};
use tracing::{error, info, warn};

#[path = "state.rs"]
mod state;
#[path = "transitions.rs"]
mod transitions;
#[path = "validation.rs"]
mod validation;

pub use state::{
    PublicKeyAggregatorRecoveryState, PublicKeyAggregatorState,
    PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION,
};
pub(crate) use transitions::{C1Dispatch, HonestSelection, PublicKeyAggregation};
pub(crate) use validation::{
    check_c1_ckks_keyshare_commitments, check_c1_keyshare_commitments, committee_h_for,
    extract_pk_commitment, verify_dkg_fold_attestation,
};

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
