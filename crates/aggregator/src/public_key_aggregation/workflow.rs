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
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{
    CircuitName, E3id, PartyProofsToVerify, Proof, Seed, SignedDkgFoldAttestation,
    SignedProofPayload,
};
use e3_fhe::Fhe;
use e3_utils::{ArcBytes, OrderedSet};
use e3_zk_prover::extract_node_fold_agg_commits;
use std::collections::{BTreeSet, HashMap};
use tracing::{error, info, warn};

/// Keep the lowest distinct party IDs for the C5 circuit's `H` slots.
/// The caller supplies parties that have already passed C1 verification.
fn cap_honest_party_ids(
    committee_h: usize,
    party_ids: impl IntoIterator<Item = u64>,
) -> BTreeSet<u64> {
    let mut ids: Vec<u64> = party_ids.into_iter().collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() > committee_h {
        ids.truncate(committee_h);
    }
    ids.into_iter().collect()
}

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
    check_c1_keyshare_commitments, committee_h_for, extract_pk_commitment,
    verify_dkg_fold_attestation,
};

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
