// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::committee::committee_addresses_in_party_order;
use crate::workflow::publickey_aggregation::{
    c5_proof_matches_keyshares, check_c1_keyshare_commitments, expected_node_fold_circuit,
    extract_lbfv_key_envelope_commitment, extract_pk_commitment, verify_dkg_fold_attestation,
    HonestSelection, PublicKeyAggregation,
};
use crate::{
    LbfvAggregationStateV1, LbfvContributionVerificationStateV1, LbfvPublicKeyPublicationStateV1,
};
use actix::prelude::*;
use anyhow::Result;
use e3_committee::CiphernodesCommitteeSize;
use e3_data::{Persistable, Repositories};
use e3_events::DkgFoldAttestationContext;
use e3_events::{
    prelude::*, AggregationInputsReady, AggregationPhase, AggregationResumed, AggregatorChanged,
    BusHandle, CommitmentRosterSelected, CommitteeMemberExcluded, CommitteeMemberExpelled,
    ComputeRequest, ComputeRequestError, ComputeResponse, ComputeResponseKind, CorrelationId,
    DKGRecursiveAggregationComplete, Die, DkgAggregationRequest, E3Failed, E3Stage, E3id,
    EventContext, EventId, FailureReason, InterfoldEvent, InterfoldEventData, KeyshareCreated,
    LbfvKeyShareDocumentFetchFailed, LbfvKeyShareDocumentReceived, LbfvKeyShareManifestPublished,
    LbfvPublicKeyAggregated, LbfvShareVerificationComplete, NodesFoldStepRequest,
    PkAggregationProofPending, PkAggregationProofRequest, PkAggregationProofSigned, Proof,
    ProofType, PublicKeyAggregated, Sequenced, ShareVerificationComplete,
    ShareVerificationDispatched, SignedProofFailed, SignedProofPayload, TypedEvent,
    VerificationKind, ZkRequest, ZkResponse,
};
use e3_events::{trap, EType};
use e3_fhe::{Fhe, GetAggregatePublicKey};
use e3_fhe_params::BfvProfile;
use e3_utils::NotifySync;
use e3_utils::{ArcBytes, OrderedSet, MAILBOX_LIMIT};
use e3_zk_prover::nodes_fold_step_len;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, warn};

/// When an l-BFV aggregation or fold-step request was published, and under which
/// event context, so a correlation whose response never arrives can be cleared
/// and the request published again. In-memory only: restart recovery clears
/// in-flight correlations and re-dispatches, so no dispatch age must survive a
/// restart.
pub(in crate::actors::publickey_aggregator) struct AggregationDispatch {
    pub(in crate::actors::publickey_aggregator) at: u64,
    pub(in crate::actors::publickey_aggregator) ec: EventContext<Sequenced>,
}

/// The accepted parties' key shares of a sealed l-BFV collection, in ascending party order. They
/// are read from the content-addressed documents and kept in memory only: the aggregation
/// sidecar does not store them, so its writes stay small.
pub(in crate::actors::publickey_aggregator) struct LbfvAcceptedShares {
    pub(in crate::actors::publickey_aggregator) public_key: Vec<ArcBytes>,
    pub(in crate::actors::publickey_aggregator) relinearization_key: Vec<ArcBytes>,
}

// Public-key aggregation state machine + pure transition logic now live in
// `crate::workflow::publickey_aggregation`; re-exported here to preserve the public path
// `e3_aggregator::publickey_aggregator::PublicKeyAggregatorState`.
pub use crate::workflow::publickey_aggregation::{
    PublicKeyAggregatorRecoveryState, PublicKeyAggregatorState,
    PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION,
};

trait LbfvRetryClock: Send + Sync {
    fn now_unix_secs(&self) -> u64;
}

struct SystemLbfvRetryClock;

impl LbfvRetryClock for SystemLbfvRetryClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

pub struct PublicKeyAggregator {
    synchronized: Option<effects::synchronized::SynchronizedPublication>,
    fhe: Arc<Fhe>,
    bus: BusHandle,
    e3_id: E3id,
    state: Persistable<PublicKeyAggregatorState>,
    recovery: Persistable<PublicKeyAggregatorRecoveryState>,
    params_profile: BfvProfile,
    lbfv_collection: Option<Persistable<crate::LbfvContributionCollectionStateV1>>,
    repositories: Repositories,
    committee_size: CiphernodesCommitteeSize,
    local_party_id: u32,
    dkg_fold_attestation_context: Option<DkgFoldAttestationContext>,
    is_aggregator: bool,
    /// This node started the in-flight aggregation as the active aggregator. A failover that
    /// demotes it does not discard that work: the chain accepts the first valid key publication.
    started_as_aggregator: bool,
    effects_enabled: bool,
    lbfv_retry_clock: Arc<dyn LbfvRetryClock>,
    lbfv_retry_timer: Option<SpawnHandle>,
    /// Canonical publication is independent of this node's local DKG phase.
    key_published: bool,
    /// C1 verdicts that arrive before effects resume or before replayed keyshares restore
    /// VerifyingC1, keyed by the ID of the verification request that each one answers.
    early_c1_verifications: HashMap<EventId, TypedEvent<ShareVerificationComplete>>,
    /// This node's C5 proof replayed during restart, kept until effects resume the C5 phase.
    replayed_c5_proof: Option<TypedEvent<PkAggregationProofSigned>>,
    /// DKG recursive aggregation events received before entering GeneratingC5Proof.
    early_dkg_proofs: Vec<TypedEvent<DKGRecursiveAggregationComplete>>,
    /// l-BFV row aggregation sidecar. The repository is the recovery source.
    lbfv_aggregation: Option<Persistable<LbfvAggregationStateV1>>,
    /// l-BFV publication intent. The separate repository keeps the trBFV recovery schema.
    lbfv_publication: Option<Persistable<LbfvPublicKeyPublicationStateV1>>,
    /// Dispatch bookkeeping for l-BFV aggregation and fold-step requests.
    lbfv_aggregation_dispatch_at: HashMap<CorrelationId, AggregationDispatch>,
    /// Periodic redrive of l-BFV aggregation requests whose response was lost.
    lbfv_aggregation_redrive_timer: Option<SpawnHandle>,
    /// The l-BFV generation verdict that this node cannot apply yet: effects are fenced, the
    /// roster has not restored `VerifyingC1`, or an earlier attempt to apply it failed. It stays
    /// until the sealed set is durable, because the bus drops a repeated request and nothing
    /// would produce the verdict again.
    held_lbfv_verification: Option<LbfvShareVerificationComplete>,
    /// The accepted parties' key shares, loaded when the collection is sealed or after a restart.
    lbfv_shares: Option<Arc<LbfvAcceptedShares>>,
}

/// States that only an active aggregator reaches: C1 verification completed and this node
/// computed the aggregate key.
pub(crate) fn aggregation_started(state: &PublicKeyAggregatorState) -> bool {
    matches!(
        state,
        PublicKeyAggregatorState::GeneratingC5Proof { .. }
            | PublicKeyAggregatorState::Complete { .. }
    )
}

pub struct PublicKeyAggregatorParams {
    pub fhe: Arc<Fhe>,
    pub bus: BusHandle,
    pub e3_id: E3id,
    pub params_profile: BfvProfile,
    pub committee_size: CiphernodesCommitteeSize,
    pub dkg_fold_attestation_context: Option<DkgFoldAttestationContext>,
    pub recovery: Persistable<PublicKeyAggregatorRecoveryState>,
    pub lbfv_collection: Option<Persistable<crate::LbfvContributionCollectionStateV1>>,
    pub repositories: Repositories,
    pub local_party_id: u32,
    pub lbfv_aggregation: Option<Persistable<LbfvAggregationStateV1>>,
    pub lbfv_publication: Option<Persistable<LbfvPublicKeyPublicationStateV1>>,
    pub initial_is_aggregator: bool,
    pub initial_stage: E3Stage,
    pub effects_enabled: bool,
}

/// Aggregate PublicKey for a committee of nodes. This actor listens for KeyshareCreated events
/// around a particular e3_id, verifies C1 proofs, aggregates the public key, generates a C5
/// proof of correct aggregation, and broadcasts a PublicKeyAggregated event on the event bus.
impl PublicKeyAggregator {
    pub fn new(
        params: PublicKeyAggregatorParams,
        state: Persistable<PublicKeyAggregatorState>,
    ) -> Self {
        Self::new_with_lbfv_retry_clock(params, state, Arc::new(SystemLbfvRetryClock))
    }

    fn new_with_lbfv_retry_clock(
        params: PublicKeyAggregatorParams,
        state: Persistable<PublicKeyAggregatorState>,
        lbfv_retry_clock: Arc<dyn LbfvRetryClock>,
    ) -> Self {
        let mut lbfv_collection = params.lbfv_collection;
        if let Some(collection) = &mut lbfv_collection {
            // Sidecar writes use acknowledged repository operations. Keep this connector as the
            // actor's serialized in-memory view without issuing duplicate asynchronous writes.
            collection.stage();
        }
        let started_as_aggregator = state.get().as_ref().is_some_and(aggregation_started)
            || params
                .recovery
                .get()
                .is_some_and(|recovery| recovery.started_as_aggregator);
        let mut actor = PublicKeyAggregator {
            synchronized: None,
            fhe: params.fhe,
            bus: params.bus,
            e3_id: params.e3_id,
            state,
            recovery: params.recovery,
            params_profile: params.params_profile,
            lbfv_collection,
            repositories: params.repositories,
            committee_size: params.committee_size,
            dkg_fold_attestation_context: params.dkg_fold_attestation_context,
            is_aggregator: params.initial_is_aggregator,
            started_as_aggregator,
            effects_enabled: params.effects_enabled,
            lbfv_retry_clock,
            lbfv_retry_timer: None,
            key_published: false,
            early_c1_verifications: HashMap::new(),
            replayed_c5_proof: None,
            early_dkg_proofs: Vec::new(),
            lbfv_aggregation: params.lbfv_aggregation,
            lbfv_publication: params.lbfv_publication,
            lbfv_aggregation_dispatch_at: HashMap::new(),
            lbfv_aggregation_redrive_timer: None,
            held_lbfv_verification: None,
            lbfv_shares: None,
            local_party_id: params.local_party_id,
        };
        actor.observe_stage(&params.initial_stage);
        actor
    }

    fn observe_stage(&mut self, stage: &E3Stage) {
        self.key_published |= matches!(
            stage,
            E3Stage::KeyPublished | E3Stage::CiphertextReady | E3Stage::Complete
        );
    }

    fn aggregation_inputs_ready(&self) -> bool {
        match self.state.get() {
            Some(PublicKeyAggregatorState::VerifyingC1 { .. }) if self.is_lbfv() => self
                .lbfv_collection_state()
                .and_then(|state| match state.verification {
                    LbfvContributionVerificationStateV1::Ready { .. }
                    | LbfvContributionVerificationStateV1::Dispatched { .. }
                    | LbfvContributionVerificationStateV1::Sealed { .. } => Ok(true),
                    LbfvContributionVerificationStateV1::Collecting
                    | LbfvContributionVerificationStateV1::Failed { .. } => Ok(false),
                })
                .unwrap_or(false),
            Some(
                PublicKeyAggregatorState::VerifyingC1 { .. }
                | PublicKeyAggregatorState::GeneratingC5Proof { .. }
                | PublicKeyAggregatorState::Complete { .. },
            ) => true,
            _ => false,
        }
    }

    /// Whether this node may start aggregation work: only the active aggregator does.
    fn can_run_aggregation_effects(&self) -> bool {
        self.effects_enabled && self.is_aggregator
    }

    /// Whether this node may continue aggregation work that is already in flight. A node that
    /// started the work as the active aggregator continues it after a failover demotes it, until a
    /// key is published on chain.
    fn can_continue_aggregation_effects(&self) -> bool {
        self.effects_enabled
            && (self.is_aggregator || (self.started_as_aggregator && !self.key_published))
    }

    /// Record that this node, as the active aggregator, starts aggregation work. The record is
    /// persisted, so that a restart after a failover still resumes the C1 verification.
    fn mark_started_as_aggregator(&mut self, ec: &EventContext<Sequenced>) -> Result<()> {
        if !self.can_run_aggregation_effects() {
            return Ok(());
        }
        self.record_started_as_aggregator(ec)
    }

    fn record_started_as_aggregator(&mut self, ec: &EventContext<Sequenced>) -> Result<()> {
        if self.started_as_aggregator {
            return Ok(());
        }
        self.started_as_aggregator = true;
        self.recovery.try_mutate(ec, |mut recovery| {
            recovery.started_as_aggregator = true;
            Ok(recovery)
        })
    }

    fn publish_inputs_ready(&self, ec: EventContext<Sequenced>) -> Result<()> {
        if !self.effects_enabled || !self.aggregation_inputs_ready() {
            return Ok(());
        }
        self.bus.publish(
            AggregationInputsReady {
                e3_id: self.e3_id.clone(),
                phase: AggregationPhase::PublicKey,
            },
            ec,
        )?;
        Ok(())
    }

    pub(in crate::actors::publickey_aggregator) fn replace_lbfv_aggregation(
        &mut self,
        state: Persistable<LbfvAggregationStateV1>,
    ) {
        self.lbfv_aggregation = Some(state);
    }

    pub(in crate::actors::publickey_aggregator) fn lbfv_aggregation_state(
        &self,
    ) -> Result<Option<LbfvAggregationStateV1>> {
        self.lbfv_aggregation
            .as_ref()
            .map(Persistable::try_get)
            .transpose()
    }

    pub(in crate::actors::publickey_aggregator) fn set_lbfv_aggregation(
        &mut self,
        state: LbfvAggregationStateV1,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let sidecar = self
            .lbfv_aggregation
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("l-BFV aggregator has no aggregation sidecar"))?;
        sidecar.try_mutate(ec, |_| Ok(state))
    }

    pub(in crate::actors::publickey_aggregator) fn lbfv_publication_state(
        &self,
    ) -> Result<Option<LbfvPublicKeyPublicationStateV1>> {
        let state = self
            .lbfv_publication
            .as_ref()
            .map(Persistable::try_get)
            .transpose()?;
        if let Some(state) = &state {
            state.validate_loaded()?;
        }
        Ok(state)
    }

    pub(in crate::actors::publickey_aggregator) fn set_lbfv_publication(
        &mut self,
        event: LbfvPublicKeyAggregated,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let publication = self
            .lbfv_publication
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("l-BFV aggregator has no publication sidecar"))?;
        publication.try_mutate(ec, |mut state| {
            state.validate_loaded()?;
            if let Some(existing) = &state.pending {
                anyhow::ensure!(existing == &event, "conflicting l-BFV publication intent");
            } else {
                state.pending = Some(event);
            }
            state.validate_loaded()?;
            Ok(state)
        })
    }
}

#[path = "effects/mod.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
