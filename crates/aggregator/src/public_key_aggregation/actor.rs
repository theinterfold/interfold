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
use std::time::Duration;
use tracing::{debug, error, info, warn};

// Public-key aggregation state machine + pure transition logic now live in
// `crate::workflow::publickey_aggregation`; re-exported here to preserve the public path
// `e3_aggregator::publickey_aggregator::PublicKeyAggregatorState`.
pub use crate::workflow::publickey_aggregation::{
    PublicKeyAggregatorRecoveryState, PublicKeyAggregatorState,
    PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION,
};

pub struct PublicKeyAggregator {
    fhe: Arc<Fhe>,
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
    /// Bounded wait for honest-party NodeDkgFold proofs. See [`node_proof_timeout`].
    node_proof_deadline: Option<SpawnHandle>,
}

pub struct PublicKeyAggregatorParams {
    pub fhe: Arc<Fhe>,
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
            node_proof_deadline: None,
        }
    }

    /// Arm the bounded wait for honest-party NodeDkgFold proofs.
    ///
    /// Idempotent: re-arming while a timer is live is a no-op, so repeated entries into
    /// `GeneratingC5Proof` (each buffered proof re-runs the dispatch path) do not extend the
    /// budget. Only the active aggregator arms it — a standby that is later promoted arms its
    /// own on promotion, which is the point at which its wait actually begins.
    ///
    /// Records an absolute deadline in the persisted state as well as arming the in-process
    /// timer. The handle is a [`SpawnHandle`] that dies with the process, and none of the three
    /// events that arm it are replayed on recovery, so without the persisted instant a restart
    /// would silently drop the bound and restore the unbounded stall this exists to prevent.
    pub(in crate::actors::publickey_aggregator) fn arm_node_proof_deadline(
        &mut self,
        ctx: &mut Context<Self>,
        ec: &EventContext<Sequenced>,
    ) {
        if self.node_proof_deadline.is_some() || !self.can_run_aggregation_effects() {
            return;
        }
        let budget = node_proof_timeout::dkg_node_proof_timeout();
        let deadline_at = Self::unix_now_secs().saturating_add(budget.as_secs());
        if let Err(err) = self.persist_node_proof_deadline(ec, Some(deadline_at)) {
            error!(
                e3_id = %self.e3_id,
                error = %err,
                "Failed to persist the node-proof deadline; a restart would drop the bound"
            );
        }
        self.spawn_node_proof_deadline(ctx, ec, budget);
    }

    /// Re-arm the bound after a restart from the persisted absolute deadline.
    ///
    /// Arms for the time that is actually left rather than a fresh full budget. An already
    /// expired deadline fires on the next tick instead of being skipped.
    pub(in crate::actors::publickey_aggregator) fn rearm_node_proof_deadline(
        &mut self,
        ctx: &mut Context<Self>,
        ec: &EventContext<Sequenced>,
    ) {
        if self.node_proof_deadline.is_some() || !self.can_run_aggregation_effects() {
            return;
        }
        if self.missing_node_proof_parties().is_empty() {
            return;
        }

        let Some(PublicKeyAggregatorState::GeneratingC5Proof {
            node_proof_deadline_at,
            ..
        }) = self.state.get()
        else {
            return;
        };

        // A checkpoint written before the deadline was persisted carries no instant. Start a
        // full budget now: a bound that is too generous still terminates, whereas none does not.
        let deadline_at = match node_proof_deadline_at {
            Some(at) => at,
            None => {
                let at = Self::unix_now_secs()
                    .saturating_add(node_proof_timeout::dkg_node_proof_timeout().as_secs());
                if let Err(err) = self.persist_node_proof_deadline(ec, Some(at)) {
                    error!(
                        e3_id = %self.e3_id,
                        error = %err,
                        "Failed to persist a node-proof deadline during recovery"
                    );
                }
                at
            }
        };

        let remaining = Duration::from_secs(deadline_at.saturating_sub(Self::unix_now_secs()));
        info!(
            e3_id = %self.e3_id,
            remaining_secs = remaining.as_secs(),
            missing_party_ids = ?self.missing_node_proof_parties(),
            "Re-armed the DKG node-proof deadline after recovery"
        );
        self.spawn_node_proof_deadline(ctx, ec, remaining);
    }

    fn spawn_node_proof_deadline(
        &mut self,
        ctx: &mut Context<Self>,
        ec: &EventContext<Sequenced>,
        delay: Duration,
    ) {
        let budget = node_proof_timeout::dkg_node_proof_timeout();
        let ec = ec.clone();
        let handle = ctx.run_later(delay, move |actor, _ctx| {
            actor.node_proof_deadline = None;
            // Clear the persisted instant so a restart after the failure does not re-arm a
            // deadline for an E3 that has already been failed.
            let _ = actor.persist_node_proof_deadline(&ec, None);
            actor.fail_on_missing_node_proofs(&ec, budget);
        });
        self.node_proof_deadline = Some(handle);
    }

    fn persist_node_proof_deadline(
        &mut self,
        ec: &EventContext<Sequenced>,
        deadline_at: Option<u64>,
    ) -> Result<()> {
        self.state.try_mutate(ec, |mut state| {
            if let PublicKeyAggregatorState::GeneratingC5Proof {
                node_proof_deadline_at,
                ..
            } = &mut state
            {
                *node_proof_deadline_at = deadline_at;
            }
            Ok(state)
        })
    }

    pub(in crate::actors::publickey_aggregator) fn unix_now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Cancel the bounded wait once every honest proof is in (or the E3 is finished).
    ///
    /// Also clears the persisted instant when a context is available. A demoted aggregator no
    /// longer owns the bound — the promoted standby arms its own — so leaving the old deadline
    /// in durable state would describe a wait this node is not performing. Re-promotion is
    /// unaffected either way because `arm_node_proof_deadline` always writes a fresh instant.
    pub(in crate::actors::publickey_aggregator) fn cancel_node_proof_deadline(
        &mut self,
        ctx: &mut Context<Self>,
    ) {
        if let Some(handle) = self.node_proof_deadline.take() {
            ctx.cancel_future(handle);
        }
    }

    /// Cancel the bounded wait and clear the persisted instant that described it.
    pub(in crate::actors::publickey_aggregator) fn cancel_node_proof_deadline_with_context(
        &mut self,
        ctx: &mut Context<Self>,
        ec: &EventContext<Sequenced>,
    ) {
        self.cancel_node_proof_deadline(ctx);
        if let Err(err) = self.persist_node_proof_deadline(ec, None) {
            error!(
                e3_id = %self.e3_id,
                error = %err,
                "Failed to clear the node-proof deadline after demotion"
            );
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
#[path = "node_proof_timeout.rs"]
mod node_proof_timeout;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
