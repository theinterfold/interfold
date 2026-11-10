// SPDX-License-Identifier: LGPL-3.0-only

//! Restart recovery for persisted public-key aggregation phases.

use super::super::*;
use crate::history::visit_e3_history;
use crate::PublicKeyRepositoryFactory;
use anyhow::ensure;
use e3_data::{AutoPersist, Repositories};
use e3_events::{EventSource, EventStoreQueryBy, SeqAgg};
use std::collections::BTreeSet;

impl PublicKeyAggregator {
    /// Restore DKG folds that a restart loses. A party sends its fold once, but folds received
    /// before GeneratingC5Proof are buffered only in memory, and folds drained into that phase keep
    /// contexts older than its snapshot cursor, so the store drops their writes.
    pub(crate) async fn recover_dkg_folds(
        &mut self,
        store: &Recipient<EventStoreQueryBy<SeqAgg>>,
        repositories: &Repositories,
    ) -> Result<()> {
        let (held, generating) = match self.state.get() {
            Some(
                PublicKeyAggregatorState::Collecting { .. }
                | PublicKeyAggregatorState::VerifyingC1 { .. },
            ) => (BTreeSet::new(), false),
            Some(PublicKeyAggregatorState::GeneratingC5Proof {
                dkg_node_proofs,
                honest_party_ids,
                ..
            }) if honest_party_ids
                .iter()
                .any(|party| !dkg_node_proofs.contains_key(party)) =>
            {
                (dkg_node_proofs.into_keys().collect::<BTreeSet<_>>(), true)
            }
            _ => return Ok(()),
        };
        if generating {
            self.state.stage();
        }
        let e3_id = self.e3_id.clone();
        visit_e3_history(store, &e3_id, |event| {
            let InterfoldEventData::DKGRecursiveAggregationComplete(fold) = event.get_data() else {
                return Ok(());
            };
            if held.contains(&fold.party_id) {
                return Ok(());
            }
            self.handle_dkg_recursive_aggregation_complete(TypedEvent::new(
                fold.clone(),
                event.get_ctx().clone(),
            ))
        })
        .await?;
        if generating {
            // Save the folds without their historical contexts before replay resumes.
            let repository = repositories.publickey(&self.e3_id);
            repository.write_sync(&self.state.try_get()?).await?;
            self.state = repository.load().await?;
        }
        Ok(())
    }

    /// Every node assembled the whole key from the chain's chunks, so a restart has no key
    /// publication left to send again.
    pub(in crate::actors::publickey_aggregator) fn forget_saved_publication(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if self
            .recovery
            .get()
            .is_none_or(|recovery| recovery.pending_publication.is_none())
        {
            return Ok(());
        }
        self.recovery.try_mutate(ec, |mut recovery| {
            recovery.pending_publication = None;
            Ok(recovery)
        })
    }

    pub(in crate::actors::publickey_aggregator) fn resume_in_flight_work(
        &mut self,
        effects_context: EventContext<Sequenced>,
    ) -> Result<()> {
        let recovery = self.recovery.try_get()?;
        ensure!(
            recovery.schema_version == PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION,
            "unsupported public-key recovery schema version {} for E3 {}",
            recovery.schema_version,
            self.e3_id
        );
        let Some(mut state) = self.state.get() else {
            return Ok(());
        };

        if matches!(state, PublicKeyAggregatorState::Collecting { .. }) {
            if let Some(selected) = recovery.selected_roster.as_ref() {
                self.state.try_mutate(&effects_context, |state| {
                    PublicKeyAggregation::begin_selected_c1(state, Some(selected))
                })?;
                state = self
                    .state
                    .get()
                    .ok_or_else(|| anyhow::anyhow!("public-key aggregation state disappeared"))?;
                self.publish_inputs_ready(effects_context.clone())?;
            }
        }

        // A saved key publication is this node's finished result, whatever its role now: send it
        // again until the whole key is on chain, so that the registry writer publishes it. The
        // writer skips a commitment that is already on chain and sends every chunk again.
        // `CommitteePublished` clears the saved publication.
        if matches!(state, PublicKeyAggregatorState::Complete { .. }) {
            if let Some(publication) = recovery.pending_publication {
                self.bus
                    .publish(publication, recovery.last_ec.unwrap_or(effects_context))?;
            }
            return Ok(());
        }

        // The active aggregator resumes any phase. A demoted node resumes only the work that it
        // started: every phase after C1 verification, and a C1 verification that it dispatched.
        if !(self.can_run_aggregation_effects()
            || ((aggregation_started(&state) || self.started_as_aggregator)
                && self.can_continue_aggregation_effects()))
        {
            return Ok(());
        }
        self.mark_started_as_aggregator(&effects_context)?;

        match state {
            PublicKeyAggregatorState::VerifyingC1 { .. } => {
                self.start_c1_verification(effects_context)
            }
            PublicKeyAggregatorState::GeneratingC5Proof {
                public_key,
                keyshare_bytes,
                nodes,
                circuit_committee_n,
                circuit_committee_h,
                c5_proof_pending,
                last_ec,
                ..
            } => {
                let causal_context = last_ec.unwrap_or_else(|| effects_context.clone());

                // Correlations identify process-local workers. A hydrated actor must create new
                // jobs instead of waiting for responses from workers that no longer exist.
                self.state.try_mutate(&effects_context, |mut state| {
                    if let PublicKeyAggregatorState::GeneratingC5Proof {
                        dkg_aggregation_correlation,
                        nodes_fold_step_correlation,
                        ..
                    } = &mut state
                    {
                        *dkg_aggregation_correlation = None;
                        *nodes_fold_step_correlation = None;
                    }
                    Ok(state)
                })?;

                let replayed_c5_proof = self.take_replayed_c5_proof(&keyshare_bytes);
                if c5_proof_pending.is_none() {
                    if let Some(c5_proof) = replayed_c5_proof {
                        self.replayed_c5_proof = Some(c5_proof);
                        self.publish_aggregation_resumed(effects_context)?;
                    } else {
                        self.bus.publish(
                            PkAggregationProofPending {
                                e3_id: self.e3_id.clone(),
                                proof_request: PkAggregationProofRequest {
                                    keyshare_bytes,
                                    aggregated_pk_bytes: public_key.clone(),
                                    params_preset: self.params_profile.threshold_preset(),
                                    committee_n: circuit_committee_n,
                                    committee_h: circuit_committee_h,
                                    committee_threshold: self.committee_size.values().threshold,
                                },
                                public_key,
                                nodes,
                            },
                            causal_context.clone(),
                        )?;
                    }
                }

                self.try_dispatch_nodes_fold_step(&causal_context)?;
                self.try_publish_complete()
            }
            PublicKeyAggregatorState::Complete { .. }
            | PublicKeyAggregatorState::Collecting { .. } => Ok(()),
        }
    }

    /// Start C1 verification of the collected keyshares, or apply the verdict held for them.
    pub(in crate::actors::publickey_aggregator) fn start_c1_verification(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if self.holds_c1_verification() {
            return self.publish_aggregation_resumed(ec);
        }
        self.continue_c1_verification(ec)
    }

    /// A restart can hold a C1 verdict or a C5 proof of this node, and replay can commit a
    /// snapshot past the result's own event. `EffectsEnabled` belongs to aggregate zero, and the
    /// committee filter releases replayed keyshares with their logged contexts, so a fresh event
    /// of this E3's chain carries the writes that apply the result.
    fn publish_aggregation_resumed(&self, cause: EventContext<Sequenced>) -> Result<()> {
        self.bus.publish(
            AggregationResumed {
                e3_id: self.e3_id.clone(),
                phase: AggregationPhase::PublicKey,
                correlation_id: CorrelationId::new(),
            },
            cause,
        )
    }

    /// Apply the held result under the resume event's revision.
    pub(in crate::actors::publickey_aggregator) fn handle_aggregation_resume(
        &mut self,
        msg: TypedEvent<AggregationResumed>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        if msg.e3_id != self.e3_id
            || msg.phase != AggregationPhase::PublicKey
            || ec.source() != EventSource::Local
            || !self.can_continue_aggregation_effects()
        {
            return Ok(());
        }
        match self.state.get() {
            Some(PublicKeyAggregatorState::VerifyingC1 { .. }) if self.holds_c1_verification() => {
                self.continue_c1_verification(ec)
            }
            Some(PublicKeyAggregatorState::GeneratingC5Proof { keyshare_bytes, .. }) => {
                let Some(c5_proof) = self.take_replayed_c5_proof(&keyshare_bytes) else {
                    return Ok(());
                };
                let (c5_proof, _) = c5_proof.into_components();
                self.handle_pk_aggregation_proof_signed(TypedEvent::new(c5_proof, ec))
            }
            _ => Ok(()),
        }
    }
}
