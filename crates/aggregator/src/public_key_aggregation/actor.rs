// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::committee::committee_addresses_in_party_order;
use crate::workflow::publickey_aggregation::{
    check_c1_ckks_keyshare_commitments, check_c1_keyshare_commitments, extract_pk_commitment,
    verify_dkg_fold_attestation, C1Dispatch, HonestSelection, PublicKeyAggregation,
};
use actix::prelude::*;
use anyhow::Result;
use e3_data::Persistable;
use e3_events::DkgFoldAttestationContext;
use e3_events::{
    prelude::*, AggregationInputsReady, AggregationPhase, AggregatorChanged, BusHandle,
    ComputeRequest, ComputeRequestError, ComputeResponse, ComputeResponseKind, CorrelationId,
    DKGRecursiveAggregationComplete, Die, DkgAggregationRequest, E3Failed, E3Stage, E3id,
    EventContext, FailureReason, InterfoldEvent, InterfoldEventData, KeyshareCreated,
    NodesFoldStepRequest, OrderedSet, PkAggregationProofPending, PkAggregationProofRequest,
    PkAggregationProofSigned, Proof, ProofType, PublicKeyAggregated, Sequenced,
    ShareVerificationComplete, ShareVerificationDispatched, SignedProofFailed, SignedProofPayload,
    TypedEvent, VerificationKind, ZkRequest, ZkResponse,
};
use e3_events::{trap, EType};
use e3_fhe::{Fhe, GetAggregatePublicKey};
use e3_fhe_params::BfvPreset;
use e3_utils::NotifySync;
use e3_utils::{ArcBytes, MAILBOX_LIMIT};
use e3_zk_helpers::CiphernodesCommitteeSize;
use std::sync::Arc;
use tracing::{error, info, warn};

// Public-key aggregation state machine + pure transition logic now live in
// `crate::workflow::publickey_aggregation`; re-exported here to preserve the public path
// `e3_aggregator::publickey_aggregator::PublicKeyAggregatorState`.
pub use crate::workflow::publickey_aggregation::{
    PublicKeyAggregatorRecoveryState, PublicKeyAggregatorState,
    PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION,
};

pub struct PublicKeyAggregator {
    /// BFV runtime — `None` on CKKS E3s (never constructed for them);
    /// both use sites are on the BFV-only path behind the CKKS branch.
    fhe: Option<Arc<Fhe>>,
    /// CKKS runtime — `Some` only on CKKS E3s (program-bound scheme).
    /// When set, aggregation skips C1/C5 and runs the CKKS branch.
    ckks: Option<Arc<e3_fhe::ckks_runtime::CkksFhe>>,
    bus: BusHandle,
    e3_id: E3id,
    state: Persistable<PublicKeyAggregatorState>,
    recovery: Persistable<PublicKeyAggregatorRecoveryState>,
    params_preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
    dkg_fold_attestation_context: Option<DkgFoldAttestationContext>,
    is_aggregator: bool,
    effects_enabled: bool,
    /// DKG recursive aggregation events received before entering GeneratingC5Proof.
    early_dkg_proofs: Vec<TypedEvent<DKGRecursiveAggregationComplete>>,
}

pub struct PublicKeyAggregatorParams {
    pub fhe: Option<Arc<Fhe>>,
    /// CKKS runtime for CKKS E3s (None on BFV E3s).
    pub ckks: Option<Arc<e3_fhe::ckks_runtime::CkksFhe>>,
    pub bus: BusHandle,
    pub e3_id: E3id,
    pub params_preset: BfvPreset,
    pub committee_size: CiphernodesCommitteeSize,
    pub dkg_fold_attestation_context: Option<DkgFoldAttestationContext>,
    pub recovery: Persistable<PublicKeyAggregatorRecoveryState>,
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
        PublicKeyAggregator {
            fhe: params.fhe,
            ckks: params.ckks,
            bus: params.bus,
            e3_id: params.e3_id,
            state,
            recovery: params.recovery,
            params_preset: params.params_preset,
            committee_size: params.committee_size,
            dkg_fold_attestation_context: params.dkg_fold_attestation_context,
            is_aggregator: params.initial_is_aggregator,
            effects_enabled: params.effects_enabled,
            early_dkg_proofs: Vec::new(),
        }
    }

    fn aggregation_inputs_ready(&self) -> bool {
        matches!(
            self.state.get(),
            Some(
                PublicKeyAggregatorState::VerifyingC1 { .. }
                    | PublicKeyAggregatorState::GeneratingC5Proof { .. }
                    | PublicKeyAggregatorState::Complete { .. }
            )
        )
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
}

#[path = "effects/mod.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
