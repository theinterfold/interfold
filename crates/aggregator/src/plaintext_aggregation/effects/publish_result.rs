// SPDX-License-Identifier: LGPL-3.0-only

//! Terminal failure mapping and plaintext publication.

use super::*;

impl ThresholdPlaintextAggregator {
    pub(in crate::actors::threshold_plaintext_aggregator) fn fail_decryption_round(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        self.bus.publish(
            E3Failed {
                e3_id: self.e3_id.clone(),
                failed_at_stage: E3Stage::CiphertextReady,
                reason: FailureReason::DecryptionInvalidShares,
            },
            ec,
        )?;

        self.pending.honest_c6_proofs_for_agg = None;
        self.pending.threshold_decryption_correlation = None;
        self.pending.decryption_aggregation_correlation = None;
        self.pending.c7_proofs_pending = None;
        self.pending.decryption_aggregator_proofs = None;

        Ok(())
    }

    pub(in crate::actors::threshold_plaintext_aggregator) fn handle_compute_request_error(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        if msg.request().e3_id != self.e3_id {
            return Ok(());
        }

        let threshold_decryption_failed =
            self.pending.threshold_decryption_correlation.as_ref() == Some(msg.correlation_id());
        let decryption_aggregation_failed =
            self.pending.decryption_aggregation_correlation.as_ref() == Some(msg.correlation_id());

        if !threshold_decryption_failed && !decryption_aggregation_failed {
            return Ok(());
        }

        // Surface the structured threshold-BFV failure when present so the implicated party and
        // failure mode are visible in logs. Slashing/accusation stays driven by the C6 proof
        // verification path; this is diagnostics only.
        if let ComputeRequestErrorKind::TrBFV(trbfv_err) = msg.get_err() {
            let failure = trbfv_err.failure();
            match &failure.threshold {
                Some(threshold) => warn!(
                    e3_id = %self.e3_id,
                    kind = ?threshold.kind,
                    party_id = ?threshold.party_id,
                    "threshold decryption failed with structured error: {}",
                    threshold.message,
                ),
                None => warn!(
                    e3_id = %self.e3_id,
                    "threshold decryption failed: {}",
                    failure.message,
                ),
            }
        }

        self.fail_decryption_round(ec)
    }

    /// Publish the local `PlaintextAggregated` intent when C7 and decryption aggregation complete.
    pub(in crate::actors::threshold_plaintext_aggregator) fn try_publish_complete(
        &mut self,
    ) -> Result<()> {
        let Some(c7_proofs) = self.pending.c7_proofs_pending.clone() else {
            return Ok(());
        };
        let dec_ready = self.pending.decryption_aggregator_proofs.is_some()
            && self.pending.decryption_aggregation_correlation.is_none();
        if !dec_ready {
            return Ok(());
        }

        let state: GeneratingC7Proof = self
            .state
            .get()
            .ok_or_else(|| anyhow!("Expected GeneratingC7Proof state"))?
            .try_into()?;

        let ec = self
            .pending
            .last_ec
            .clone()
            .ok_or_else(|| anyhow!("No EventContext for publish"))?;

        info!("C7 + decryption_aggregator proofs ready — publishing PlaintextAggregated");

        // CKKS plaintexts are already the canonical fixed-point bytes; the
        // BFV formatter pads/truncates to MAX_MSG_NON_ZERO_COEFFS*8 which
        // would corrupt them (appended zero-words decode as extra values).
        let decrypted_output = if self.scheme == e3_events::E3Scheme::Ckks {
            state.plaintext.clone()
        } else {
            format_decrypted_plaintext(&state.plaintext)
        };

        let decryption_aggregator_proofs = self
            .pending
            .decryption_aggregator_proofs
            .clone()
            .unwrap_or_default();
        // Keep c7_proofs for invariant check; they are subsumed by the decryption_aggregator proof.
        let _ = c7_proofs;
        let event = PlaintextAggregated {
            decrypted_output,
            e3_id: self.e3_id.clone(),
            decryption_aggregator_proofs,
        };

        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.c7_proofs = Some(c7_proofs);
            recovery.decryption_aggregator_proofs =
                Some(event.decryption_aggregator_proofs.clone());
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;

        info!("Dispatching plaintext event {:?}", event);
        self.bus.publish(event, ec.clone())?;

        self.state.try_mutate(&ec, |_| {
            Ok(ThresholdPlaintextAggregatorState::Complete(Complete {
                decrypted: state.plaintext,
                shares: state.shares,
            }))
        })?;

        Ok(())
    }
}
