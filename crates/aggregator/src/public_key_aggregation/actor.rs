// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::committee::committee_addresses_in_party_order;
use crate::workflow::publickey_aggregation::{
    check_c1_keyshare_commitments, extract_pk_commitment, verify_dkg_fold_attestation, C1Dispatch,
    HonestSelection, PublicKeyAggregation,
};
use crate::{
    LbfvAggregationStateV1, LbfvContributionVerificationStateV1, LbfvPublicKeyPublicationStateV1,
};
use actix::prelude::*;
use anyhow::Result;
use e3_data::{Persistable, Repositories};
use e3_events::DkgFoldAttestationContext;
use e3_events::{
    prelude::*, AggregationInputsReady, AggregationPhase, AggregatorChanged, BusHandle,
    ComputeRequest, ComputeRequestError, ComputeResponse, ComputeResponseKind, CorrelationId,
    DKGRecursiveAggregationComplete, Die, DkgAggregationRequest, E3Failed, E3Stage, E3id,
    EventContext, FailureReason, InterfoldEvent, InterfoldEventData, KeyshareCreated,
    LbfvKeyShareDocumentFetchFailed, LbfvKeyShareDocumentReceived, LbfvKeyShareManifestPublished,
    LbfvPublicKeyAggregated, NodesFoldStepRequest, OrderedSet, PkAggregationProofPending,
    PkAggregationProofRequest, PkAggregationProofSigned, Proof, ProofType, PublicKeyAggregated,
    Sequenced, ShareVerificationComplete, ShareVerificationDispatched, SignedProofFailed,
    SignedProofPayload, TypedEvent, VerificationKind, ZkRequest, ZkResponse,
};
use e3_events::{trap, EType};
use e3_fhe::{Fhe, GetAggregatePublicKey};
use e3_fhe_params::BfvPreset;
use e3_utils::NotifySync;
use e3_utils::{ArcBytes, MAILBOX_LIMIT};
use e3_zk_helpers::CiphernodesCommitteeSize;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, warn};

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
    fhe: Arc<Fhe>,
    bus: BusHandle,
    e3_id: E3id,
    state: Persistable<PublicKeyAggregatorState>,
    recovery: Persistable<PublicKeyAggregatorRecoveryState>,
    lbfv_collection: Option<Persistable<crate::LbfvContributionCollectionStateV1>>,
    repositories: Repositories,
    params_preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
    local_party_id: u32,
    dkg_fold_attestation_context: Option<DkgFoldAttestationContext>,
    is_aggregator: bool,
    effects_enabled: bool,
    lbfv_retry_clock: Arc<dyn LbfvRetryClock>,
    lbfv_retry_timer: Option<SpawnHandle>,
    /// DKG recursive aggregation events received before entering GeneratingC5Proof.
    early_dkg_proofs: Vec<TypedEvent<DKGRecursiveAggregationComplete>>,
    /// Secure-16384 row aggregation sidecar. The repository is the recovery source.
    lbfv_aggregation: Option<Persistable<LbfvAggregationStateV1>>,
    /// Secure-16384 publication intent. The separate repository preserves the legacy recovery schema.
    lbfv_publication: Option<Persistable<LbfvPublicKeyPublicationStateV1>>,
}

pub struct PublicKeyAggregatorParams {
    pub fhe: Arc<Fhe>,
    pub bus: BusHandle,
    pub e3_id: E3id,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
    pub dkg_fold_attestation_context: Option<DkgFoldAttestationContext>,
    pub recovery: Persistable<PublicKeyAggregatorRecoveryState>,
    pub lbfv_collection: Option<Persistable<crate::LbfvContributionCollectionStateV1>>,
    pub repositories: Repositories,
    pub local_party_id: u32,
    pub lbfv_aggregation: Option<Persistable<LbfvAggregationStateV1>>,
    pub lbfv_publication: Option<Persistable<LbfvPublicKeyPublicationStateV1>>,
    pub initial_is_aggregator: bool,
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
        PublicKeyAggregator {
            fhe: params.fhe,
            bus: params.bus,
            e3_id: params.e3_id,
            state,
            recovery: params.recovery,
            lbfv_collection,
            repositories: params.repositories,
            params_preset: params.params_preset,
            committee_size: params.committee_size,
            dkg_fold_attestation_context: params.dkg_fold_attestation_context,
            is_aggregator: params.initial_is_aggregator,
            effects_enabled: params.effects_enabled,
            lbfv_retry_clock,
            lbfv_retry_timer: None,
            early_dkg_proofs: Vec::new(),
            lbfv_aggregation: params.lbfv_aggregation,
            lbfv_publication: params.lbfv_publication,
            local_party_id: params.local_party_id,
        }
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

    fn can_run_aggregation_effects(&self) -> bool {
        self.effects_enabled && self.is_aggregator
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
            .ok_or_else(|| anyhow::anyhow!("secure-16384 aggregator has no l-BFV sidecar"))?;
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
            .ok_or_else(|| anyhow::anyhow!("secure-16384 aggregator has no publication sidecar"))?;
        publication.try_mutate(ec, |mut state| {
            state.validate_loaded()?;
            if let Some(existing) = &state.pending {
                anyhow::ensure!(
                    existing == &event,
                    "conflicting secure-16384 publication intent"
                );
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
