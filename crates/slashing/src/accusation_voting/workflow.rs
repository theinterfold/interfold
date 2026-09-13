// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Deterministic workflow for the off-chain accusation quorum
//! protocol.
//!
//! This module contains **all** the business logic that used to live inside
//! the `AccusationManager` actix actor:
//!
//! - EIP-712 digest computation (accusation + vote)
//! - ECDSA signature creation and verification
//! - deadline stamping / peer-deadline validation
//! - pending-accusation bookkeeping (votes, dedup, buffering)
//! - vote tallying, quorum threshold checks, and equivocation detection
//!
//! [`AccusationVoting`] owns the protocol state and exposes plain methods that
//! mutate that state and **return a list of [`VoteAction`]s** describing the
//! I/O the actor must perform (publish a gossip event, dispatch a ZK request,
//! start/cancel a vote timeout). The service itself performs **no** I/O: it
//! never touches the event bus, the actix context, or timers. This makes the
//! whole protocol deterministically unit-testable without spinning up an actor
//! system.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::SolValue;
use e3_events::{
    AccusationOutcome, AccusationQuorumReached, AccusationVote, CommitmentConsistencyViolation,
    ComputeRequest, ComputeRequestError, ComputeResponse, ComputeResponseKind, CorrelationId, E3id,
    EventContext, PartyProofsToVerify, ProofFailureAccusation, ProofIdentity, ProofType,
    ProofVerificationFailed, ProofVerificationPassed, Sequenced, SignedProofPayload, SlashExecuted,
    TypedEvent, VerifyShareProofsRequest, ZkRequest, ZkResponse, VOTE_DOMAIN_NAME,
    VOTE_DOMAIN_VERSION, VOTE_TYPEHASH_STR,
};
use e3_utils::ArcBytes;
use e3_zk_helpers::CiphernodesCommitteeSize;
use tracing::{error, info, warn};

#[path = "state.rs"]
mod state;
#[path = "transitions/mod.rs"]
mod transitions;

pub use state::Clock;
pub(crate) use state::*;

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
#[path = "workflow_tests/mod.rs"]
mod tests;
