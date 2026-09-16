// SPDX-License-Identifier: LGPL-3.0-only

//! Restart recovery for persisted public-key aggregation phases.

use super::super::*;
use anyhow::ensure;

impl PublicKeyAggregator {
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

        if !self.can_run_aggregation_effects() {
            return Ok(());
        }

        match state {
            PublicKeyAggregatorState::VerifyingC1 { .. } => {
                self.continue_c1_verification(effects_context)
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

                if c5_proof_pending.is_none() {
                    self.bus.publish(
                        PkAggregationProofPending {
                            e3_id: self.e3_id.clone(),
                            proof_request: PkAggregationProofRequest {
                                keyshare_bytes,
                                aggregated_pk_bytes: public_key.clone(),
                                params_preset: self.params_preset,
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

                self.try_dispatch_nodes_fold_step(&causal_context)?;
                self.try_publish_complete()
            }
            PublicKeyAggregatorState::Complete { .. } => {
                if let Some(publication) = recovery.pending_publication {
                    self.bus
                        .publish(publication, recovery.last_ec.unwrap_or(effects_context))?;
                }
                Ok(())
            }
            PublicKeyAggregatorState::Collecting { .. } => Ok(()),
        }
    }
}
