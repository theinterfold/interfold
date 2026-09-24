// SPDX-License-Identifier: LGPL-3.0-only

//! Restart recovery for persisted plaintext aggregation phases.

use super::*;

impl ThresholdPlaintextAggregator {
    pub(in crate::actors::threshold_plaintext_aggregator) fn resume_in_flight_work(
        &mut self,
        effects_context: EventContext<Sequenced>,
    ) -> Result<()> {
        if !self.can_run_aggregation_effects() {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        ensure!(
            recovery.schema_version == THRESHOLD_PLAINTEXT_RECOVERY_SCHEMA_VERSION,
            "unsupported plaintext recovery schema version {} for E3 {}",
            recovery.schema_version,
            self.e3_id
        );
        let causal_context = recovery.last_ec.unwrap_or(effects_context.clone());
        self.pending.last_ec = Some(causal_context.clone());

        let Some(state) = self.state.get() else {
            return Ok(());
        };
        match state {
            ThresholdPlaintextAggregatorState::Collecting(_) => Ok(()),
            ThresholdPlaintextAggregatorState::VerifyingC6(state) => {
                self.dispatch_c6_verification(state.c6_proofs, effects_context)
            }
            ThresholdPlaintextAggregatorState::Computing(state) => {
                ensure!(
                    !self.proof_aggregation_enabled
                        || self.pending.honest_c6_proofs_for_agg.is_some(),
                    "plaintext aggregation for E3 {} cannot resume threshold decryption without verified C6 proofs",
                    self.e3_id
                );
                let correlation_id = CorrelationId::new();
                let request = ComputeRequest::trbfv(
                    TrBFVRequest::CalculateThresholdDecryption(
                        CalculateThresholdDecryptionRequest {
                            ciphertexts: state.ciphertext_output,
                            trbfv_config: TrBFVConfig::new(
                                state.params,
                                state.threshold_n,
                                state.threshold_m,
                            ),
                            d_share_polys: state.shares,
                        },
                    ),
                    correlation_id,
                    self.e3_id.clone(),
                );
                self.bus.publish(request, causal_context)?;
                self.pending.threshold_decryption_correlation = Some(correlation_id);
                Ok(())
            }
            ThresholdPlaintextAggregatorState::GeneratingC7Proof(state) => {
                self.pending.decryption_aggregation_correlation = None;
                if self.pending.c7_proofs_pending.is_none() {
                    self.dispatch_c7_proof_request(
                        state.shares,
                        state.plaintext,
                        state.threshold_m,
                        state.threshold_n,
                        causal_context.clone(),
                    )?;
                }
                self.maybe_start_decryption_aggregation(&causal_context)?;
                self.try_publish_complete()
            }
            ThresholdPlaintextAggregatorState::Complete(state) => {
                let proofs = self
                    .pending
                    .decryption_aggregator_proofs
                    .clone()
                    .ok_or_else(|| {
                        anyhow!(
                            "plaintext aggregation for E3 {} completed without a recovery publication record",
                            self.e3_id
                        )
                    })?;
                self.bus.publish(
                    PlaintextAggregated {
                        e3_id: self.e3_id.clone(),
                        decrypted_output: format_decrypted_plaintext(&state.decrypted),
                        decryption_aggregator_proofs: proofs,
                    },
                    causal_context,
                )
            }
        }
    }
}
