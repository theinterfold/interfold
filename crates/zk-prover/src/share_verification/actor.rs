// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Actor for C2/C3/C4 share proof verification.
//!
//! Follows the same pattern as [`ProofVerificationActor`] (for C0) — sits
//! between the raw proof data and the verified result, handling ECDSA validation
//! and ZK verification orchestration.
//!
//! ## Flow
//!
//! 1. Receives [`ShareVerificationDispatched`] from [`ThresholdKeyshare`].
//! 2. Performs ECDSA validation (signature recovery, signer consistency, e3_id,
//!    circuit name) — lightweight, no thread pool needed.
//! 3. Dispatches ZK-only verification to multithread via [`ComputeRequest`].
//! 4. Receives [`ComputeResponse`] from multithread with pure ZK results.
//! 5. Combines ECDSA + ZK results.
//! 6. Emits [`SignedProofFailed`] for any failing proofs.
//! 7. Publishes [`ShareVerificationComplete`] with dishonest party set.

use std::collections::{BTreeSet, HashMap, HashSet};

use actix::{Actor, Addr, Context, Handler};
use alloy::primitives::{keccak256, Address, Bytes, B256};
use alloy::sol_types::SolValue;
use e3_events::{
    BusHandle, CommitmentConsistencyCheckComplete, CommitmentConsistencyCheckRequested, Committee,
    ComputeRequest, ComputeRequestError, ComputeResponse, ComputeResponseKind, CorrelationId, E3id,
    EventContext, EventPublisher, EventSubscriber, EventType, InterfoldEvent, InterfoldEventData,
    PartyVerificationResult, ProofVerificationFailed, ProofVerificationPassed, Sequenced,
    ShareVerificationComplete, ShareVerificationDispatched, SignedProofFailed, SignedProofPayload,
    TypedEvent, VerificationKind, VerifyShareDecryptionProofsRequest, VerifyShareProofsRequest,
    ZkRequest, ZkResponse,
};
use e3_utils::utility_types::ArcBytes;
use e3_utils::NotifySync;
use tracing::{debug, error, info, warn};

use crate::workflow::share_verification::{
    filter_consistent, label_for, PendingConsistencyCheck, PendingVerification, ShareVerifier,
    VerifiableParty, ZkPartyEmission,
};

/// Actor that handles C1/C2/C3/C4/C6 share proof verification.
///
/// Three-stage pipeline:
/// 1. ECDSA validation (lightweight, done inline)
/// 2. Commitment consistency check (dispatched to per-E3 checker via event bus)
/// 3. ZK proof verification (heavyweight, delegated to multithread)
///
/// Emits [`SignedProofFailed`] for fault attribution and
/// [`ShareVerificationComplete`] with the final dishonest party set.
pub struct ShareVerificationActor {
    bus: BusHandle,
    /// Canonical finalized committees in party-id order. Every signed C1-C4/C6 proof must recover
    /// to the address that owns its outer `sender_party_id` slot.
    committees: HashMap<E3id, Vec<Address>>,
    /// Tracks pending ZK verifications by correlation ID.
    pending: HashMap<CorrelationId, PendingVerification>,
    /// Tracks pending consistency checks by correlation ID (between ECDSA and ZK).
    pending_consistency: HashMap<CorrelationId, PendingConsistencyCheck>,
}

impl ShareVerificationActor {
    pub fn new(bus: &BusHandle, persisted_committees: HashMap<E3id, Committee>) -> Self {
        let mut actor = Self {
            bus: bus.clone(),
            committees: HashMap::new(),
            pending: HashMap::new(),
            pending_consistency: HashMap::new(),
        };
        for (e3_id, committee) in persisted_committees {
            actor.store_committee(e3_id, committee.members());
        }
        actor
    }

    pub fn setup(bus: &BusHandle, persisted_committees: HashMap<E3id, Committee>) -> Addr<Self> {
        let addr = Self::new(bus, persisted_committees).start();
        bus.subscribe(EventType::CommitteeFinalized, addr.clone().into());
        bus.subscribe(EventType::ShareVerificationDispatched, addr.clone().into());
        bus.subscribe(EventType::ComputeResponse, addr.clone().into());
        bus.subscribe(EventType::ComputeRequestError, addr.clone().into());
        bus.subscribe(
            EventType::CommitmentConsistencyCheckComplete,
            addr.clone().into(),
        );
        bus.subscribe(EventType::E3RequestComplete, addr.clone().into());
        addr
    }

    fn store_committee(&mut self, e3_id: E3id, members: &[String]) {
        match members
            .iter()
            .map(|member| member.parse())
            .collect::<Result<Vec<Address>, _>>()
        {
            Ok(committee) => {
                self.committees.insert(e3_id, committee);
            }
            Err(error) => {
                error!(
                    %e3_id,
                    %error,
                    "Finalized committee contains an invalid address; share proofs will be rejected"
                );
            }
        }
    }
}

#[path = "effects/mod.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "actor_tests.rs"]
mod tests;
