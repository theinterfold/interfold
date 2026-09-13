// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Deterministic C1/C2/C3/C4/C6 share-proof verification workflow.
//!
//! The [`crate::actors::share_verification::ShareVerificationActor`] is a thin
//! transport shell: it owns the event bus and performs all publish/persist I/O.
//! This module owns the business logic — ECDSA validation, proof-commitment
//! hashing, consistency filtering, and ZK-result tallying — as pure functions on
//! the stateless [`ShareVerifier`] service, plus the per-E3 pending-state types.
//! It has NO actix / `BusHandle` / `Addr` concerns (tracing is allowed).

use std::collections::{BTreeSet, HashMap, HashSet};

use alloy::primitives::{keccak256, Address, Bytes, B256};
use alloy::sol_types::SolValue;
use e3_events::{
    E3id, EventContext, PartyProofData, PartyProofsToVerify, PartyShareDecryptionProofsToVerify,
    PartyVerificationResult, ProofIdentity, ProofType, Sequenced, SignedProofPayload,
    VerificationKind,
};
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::CiphernodesCommitteeSize;
use tracing::{info, warn};

#[path = "state.rs"]
mod state;
#[path = "transitions/mod.rs"]
mod transitions;

pub(crate) use state::*;
pub(crate) use transitions::filter_consistent;

#[cfg(test)]
#[path = "workflow_tests/mod.rs"]
mod tests;
