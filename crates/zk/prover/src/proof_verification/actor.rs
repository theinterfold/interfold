// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies `EncryptionKeyReceived` events: recovers ECDSA address, delegates
//! ZK proof to `ZkActor`, and emits [`SignedProofFailed`] for a completed invalid check.
//! Local verifier errors retain the input for retry.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use actix::{Actor, Addr, AsyncContext, Context, Handler, Message, Recipient, SpawnHandle};
use alloy::primitives::{keccak256, Address, Bytes};
use alloy::sol_types::SolValue;
use anyhow::anyhow;
use e3_committee::{CiphernodesCommitteeSize, Committee};
use e3_events::{
    BusHandle, E3id, EType, EncryptionKey, EncryptionKeyCreated, EncryptionKeyReceived,
    ErrorDispatcher, EventContext, EventContextAccessors, EventPublisher, EventSubscriber,
    EventType, InterfoldEvent, InterfoldEventData, Proof, ProofType, ProofVerificationFailed,
    ProofVerificationPassed, Sequenced, SignedProofFailed, SignedProofPayload, TypedEvent,
};
use e3_fhe_params::BfvProfile;
use e3_request::E3Meta;
use e3_utils::NotifySync;
use tracing::{debug, error, info, warn};

use crate::domain::proof_verification::{dkg_has_ended, validate_received_key};

const VERIFICATION_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAX_VERIFICATION_RETRY_DELAY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Message)]
#[rtype(result = "()")]
pub struct ZkVerificationRequest {
    pub proof: Proof,
    pub e3_id: E3id,
    pub key: Arc<EncryptionKey>,
    pub sender: Recipient<TypedEvent<ZkVerificationResponse>>,
    pub artifacts_dir: String,
}

#[derive(Debug, Clone, Message)]
#[rtype(result = "()")]
pub struct ZkVerificationResponse {
    pub outcome: ZkVerificationOutcome,
    pub e3_id: E3id,
    pub key: Arc<EncryptionKey>,
}

#[derive(Debug, Clone)]
pub enum ZkVerificationOutcome {
    Valid,
    Invalid,
    InfrastructureError(String),
    /// The node's protocol task group ended; this outcome must not be retried or blamed on a peer.
    Cancelled,
}

#[derive(Clone, Debug)]
struct PendingVerification {
    signed_payload: SignedProofPayload,
    recovered_signer: Address,
    request: TypedEvent<ZkVerificationRequest>,
    retry: Option<SpawnHandle>,
    attempts: u32,
    retry_delay: Duration,
}

pub struct ProofVerificationActor {
    bus: BusHandle,
    verifier: Recipient<TypedEvent<ZkVerificationRequest>>,
    pending: HashMap<(E3id, u64), PendingVerification>,
    /// Request-time profile and committee select the C0 artifact namespace, including after restart.
    profiles: HashMap<E3id, (BfvProfile, CiphernodesCommitteeSize)>,
    /// Canonical finalized committee in party-id order. A C0 signer must own the party slot whose
    /// BFV key it advertises; recovering any valid ECDSA address is not sufficient.
    committees: HashMap<E3id, Vec<Address>>,
    recovered: Vec<TypedEvent<EncryptionKeyReceived>>,
    /// E3s whose DKG ended before startup. The replay can bring back their C0 inputs.
    dkg_ended: HashSet<E3id>,
    effects_enabled: bool,
}

impl ProofVerificationActor {
    pub fn new(
        bus: &BusHandle,
        verifier: Recipient<TypedEvent<ZkVerificationRequest>>,
        persisted_committees: HashMap<E3id, Committee>,
        persisted_e3_metadata: HashMap<E3id, E3Meta>,
    ) -> Self {
        let mut actor = Self {
            bus: bus.clone(),
            verifier,
            pending: HashMap::new(),
            profiles: HashMap::new(),
            committees: HashMap::new(),
            recovered: Vec::new(),
            dkg_ended: HashSet::new(),
            effects_enabled: false,
        };
        for (e3_id, meta) in persisted_e3_metadata {
            if let Err(error) = actor.store_profile(
                e3_id,
                meta.params_profile,
                meta.threshold_m,
                meta.threshold_n,
            ) {
                error!("{error}");
            }
        }
        for (e3_id, committee) in persisted_committees {
            actor.store_committee(e3_id, committee.members());
        }
        actor
    }

    pub fn setup(
        bus: &BusHandle,
        verifier: Recipient<TypedEvent<ZkVerificationRequest>>,
        persisted_committees: HashMap<E3id, Committee>,
        persisted_e3_metadata: HashMap<E3id, E3Meta>,
    ) -> Addr<Self> {
        Self::setup_with_recovery(
            bus,
            verifier,
            persisted_committees,
            persisted_e3_metadata,
            Vec::new(),
            HashSet::new(),
        )
    }

    pub(crate) fn setup_with_recovery(
        bus: &BusHandle,
        verifier: Recipient<TypedEvent<ZkVerificationRequest>>,
        persisted_committees: HashMap<E3id, Committee>,
        persisted_e3_metadata: HashMap<E3id, E3Meta>,
        recovered: Vec<TypedEvent<EncryptionKeyReceived>>,
        dkg_ended: HashSet<E3id>,
    ) -> Addr<Self> {
        let mut actor = Self::new(bus, verifier, persisted_committees, persisted_e3_metadata);
        actor.recovered = recovered;
        actor.dkg_ended = dkg_ended;
        let addr = actor.start();
        bus.subscribe(EventType::CiphernodeSelected, addr.clone().into());
        bus.subscribe(EventType::CommitteeFinalized, addr.clone().into());
        bus.subscribe(EventType::EncryptionKeyReceived, addr.clone().into());
        bus.subscribe(EventType::E3RequestComplete, addr.clone().into());
        bus.subscribe(EventType::E3StageChanged, addr.clone().into());
        bus.subscribe(EventType::EncryptionKeyCreated, addr.clone().into());
        bus.subscribe(EventType::ProofVerificationFailed, addr.clone().into());
        bus.subscribe(EventType::EffectsEnabled, addr.clone().into());
        addr
    }

    /// Keeps the profile that selects the E3's C0 artifacts. Without one, the actor abstains from
    /// the E3's C0 inputs: it publishes no verdict and blames no peer for its own configuration.
    fn store_profile(
        &mut self,
        e3_id: E3id,
        profile: BfvProfile,
        threshold_m: usize,
        threshold_n: usize,
    ) -> anyhow::Result<()> {
        let committee = profile
            .ensure_admission_enabled()
            .map_err(anyhow::Error::from)
            .and_then(|()| CiphernodesCommitteeSize::from_threshold(threshold_m, threshold_n))
            .map_err(|error| anyhow!("Skipping C0 verification for E3 {e3_id}: {error}"))?;
        self.profiles.insert(e3_id, (profile, committee));
        Ok(())
    }

    fn store_committee(&mut self, e3_id: E3id, members: &[String]) {
        match members
            .iter()
            .map(|node| node.parse())
            .collect::<Result<Vec<Address>, _>>()
        {
            Ok(committee) => {
                self.committees.insert(e3_id, committee);
            }
            Err(error) => {
                error!(
                    %e3_id,
                    %error,
                    "Finalized committee contains an invalid address; C0 keys will be rejected"
                );
            }
        }
    }
}

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[path = "recovery.rs"]
pub(crate) mod recovery;

#[cfg(test)]
#[path = "actor_tests.rs"]
mod tests;
