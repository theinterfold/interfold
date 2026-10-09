// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Off-chain accusation quorum protocol for fault attribution.
//!
//! When a node detects a ZK proof failure from another committee member, it
//! broadcasts a [`ProofFailureAccusation`] over gossip. Other committee members
//! independently check the same proof and respond with [`AccusationVote`]s.
//! Once the on-chain quorum `H` votes is reached, the
//! actor emits [`AccusationQuorumReached`] for downstream consumers (aggregator
//! exclusion, on-chain slash submission).
//!
//! ## Architecture
//!
//! This file is a **thin actix shell**. All protocol logic lives in the plain,
//! synchronous [`AccusationVoting`] service ([`crate::accusation_voting`]). The
//! actor's only job is to translate inbound [`InterfoldEvent`]s into service
//! calls and to perform the I/O ([`VoteAction`]s) the service returns —
//! publishing gossip events, dispatching ZK requests, and managing vote
//! timeouts.
//!
//! ## Proof-type-specific behavior
//!
//! | Proof   | Attestation                | Notes                                      |
//! |---------|----------------------------|--------------------------------------------|
//! | C0      | All nodes independently    | Everyone receives via DHT                  |
//! | C1      | All nodes independently    | Bundled in ThresholdShareCreated            |
//! | C2a/C2b | All nodes independently    | Same proof bytes for all recipients         |
//! | C3a/C3b | Forwarding required        | Per-recipient; accuser forwards payload     |
//! | C4      | All nodes independently    | Broadcast via gossip                        |
//! | C5      | Committee attests          | Aggregator-generated; nodes verify off-chain|
//! | C6      | All nodes independently    | Broadcast via gossip                        |
//! | C7      | On-chain verification      | Not handled here (on-chain verifier)        |

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use actix::{Actor, Addr, AsyncContext, Context, Handler, SpawnHandle};
use alloy::primitives::{Address, Bytes};
use alloy::signers::local::PrivateKeySigner;
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{
    AccusationVote, BusHandle, CommitmentConsistencyViolation, ComputeRequestError,
    ComputeResponse, E3id, EventPublisher, EventSubscriber, EventType, InterfoldEvent,
    InterfoldEventData, ProofFailureAccusation, ProofType, ProofVerificationFailed,
    ProofVerificationPassed, TypedEvent,
};
use e3_utils::NotifySync;
use tracing::{error, warn};

pub use crate::workflow::accusation_voting::Clock;
use crate::workflow::accusation_voting::{AccusationVoting, VoteAction};

/// Production clock backed by `SystemTime::now()`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Thin actix shell around the [`AccusationVoting`] domain service.
///
/// **Lifecycle**: One instance per E3 computation. Created by
/// [`AccusationManagerExtension`] when [`CommitteeFinalized`] fires and
/// destroyed when the E3 completes or the node shuts down. All protocol state
/// lives inside the owned [`AccusationVoting`] service and is therefore
/// naturally scoped to a single E3.
///
/// **Ephemeral**: This actor does *not* persist state across restarts.
/// In-flight accusations are lost on node restart (accepted trade-off:
/// they would have timed out within the vote timeout anyway).
///
/// Subscribes to:
/// - [`ProofVerificationFailed`] — local proof failure detection
/// - [`ProofVerificationPassed`] — cache successful verification for voting
/// - [`ProofFailureAccusation`] — incoming accusations from other nodes via gossip
/// - [`AccusationVote`] — incoming votes from other nodes via gossip
/// - [`SlashExecuted`] — on-chain slash confirmation for committee updates
///
/// Publishes:
/// - [`ProofFailureAccusation`] — broadcast own accusations via gossip
/// - [`AccusationVote`] — broadcast own votes via gossip
/// - [`AccusationQuorumReached`] — quorum decision for downstream consumers
///
/// [`AccusationManagerExtension`]: crate::accusation_manager_ext::AccusationManagerExtension
/// [`CommitteeFinalized`]: e3_events::CommitteeFinalized
/// [`AccusationQuorumReached`]: e3_events::AccusationQuorumReached
/// [`SlashExecuted`]: e3_events::SlashExecuted
pub struct AccusationManager {
    bus: BusHandle,
    /// Plain, synchronous protocol core. Owns all accusation/vote state.
    voting: AccusationVoting,
    /// Active vote-collection timeouts keyed by accusation_id. Managed entirely
    /// by the actor — the service only signals start/cancel via [`VoteAction`].
    timeout_handles: HashMap<[u8; 32], SpawnHandle>,
}

#[path = "effects/mod.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "actor_tests.rs"]
mod tests;
