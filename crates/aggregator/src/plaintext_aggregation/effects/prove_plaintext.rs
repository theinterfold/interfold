// SPDX-License-Identifier: LGPL-3.0-only

//! Threshold decryption, C7 proving, and recursive decryption aggregation.

use super::*;

impl ThresholdPlaintextAggregator {
    /// Publish AggregationProofPending for C7 proof generation through ProofRequestActor.
    pub fn dispatch_c7_proof_request(
        &mut self,
        shares: Vec<(u64, Vec<ArcBytes>)>,
        plaintext: Vec<ArcBytes>,
        threshold_m: u64,
        threshold_n: u64,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        self.bus.publish(
            AggregationProofPending {
                e3_id: self.e3_id.clone(),
                proof_request: DecryptedSharesAggregationProofRequest {
                    d_share_polys: shares.clone(),
                    plaintext: plaintext.clone(),
                    params_preset: self.params_preset,
                    threshold_m,
                    threshold_n,
                    committee_size: self.committee_size,
                },
                plaintext,
                shares,
            },
            ec,
        )?;
        Ok(())
    }

    /// Handle AggregationProofSigned: store C7 proofs and wait for C6 fold before publishing.
    pub fn handle_aggregation_proof_signed(
        &mut self,
        msg: TypedEvent<AggregationProofSigned>,
        _ctx: &mut Context<Self>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();

        if msg.e3_id != self.e3_id {
            return Ok(());
        }

        let state: GeneratingC7Proof = self
            .state
            .get()
            .ok_or(anyhow!("Could not get state"))?
            .try_into()?;

        // Extract raw proofs from signed payloads for PlaintextAggregated
        let proofs: Vec<_> = msg
            .signed_proofs
            .iter()
            .map(|sp| sp.payload.proof.clone())
            .collect();

        if proofs.len() != state.plaintext.len() {
            warn!(
                e3_id = %self.e3_id,
                "C7 proof count mismatch: got {} proofs for {} ciphertext indices",
                proofs.len(),
                state.plaintext.len()
            );
            return self.fail_decryption_round(ec);
        }

        info!("C7 proof signed — awaiting DecryptionAggregation...");
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.c7_proofs = Some(proofs.clone());
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.pending.c7_proofs_pending = Some(proofs);
        self.pending.last_ec = Some(ec.clone());
        self.maybe_start_decryption_aggregation(&ec)?;
        self.try_publish_complete()
    }

    pub(in crate::actors::threshold_plaintext_aggregator) fn maybe_start_decryption_aggregation(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if self.pending.c7_proofs_pending.is_none() {
            return Ok(());
        }
        if self.pending.decryption_aggregator_proofs.is_some()
            || self.pending.decryption_aggregation_correlation.is_some()
        {
            return Ok(());
        }
        if !self.proof_aggregation_enabled {
            if self.pending.decryption_aggregator_proofs.is_none() {
                // Reuse the already-generated C7 proofs as non-empty test placeholders. Mock
                // decryption verifiers accept them; production verifiers reject them because
                // they are not DecryptionAggregator proofs.
                self.pending.decryption_aggregator_proofs = self.pending.c7_proofs_pending.clone();
                let proofs = self.pending.decryption_aggregator_proofs.clone();
                self.recovery.try_mutate(ec, |mut recovery| {
                    recovery.decryption_aggregator_proofs = proofs;
                    recovery.last_ec = Some(ec.clone());
                    Ok(recovery)
                })?;
            }
            return Ok(());
        }
        self.dispatch_decryption_aggregation(ec)
    }

    pub(in crate::actors::threshold_plaintext_aggregator) fn dispatch_decryption_aggregation(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if self.committee_addresses.is_empty() {
            warn!(
                e3_id = %self.e3_id,
                "DecryptionAggregation: committee addresses missing at aggregator construction"
            );
            return self.fail_decryption_round(ec.clone());
        }

        let Some(c7_proofs) = self.pending.c7_proofs_pending.as_ref() else {
            return Ok(());
        };
        if self.pending.decryption_aggregator_proofs.is_some() {
            return Ok(());
        }
        if self.pending.decryption_aggregation_correlation.is_some() {
            return Ok(());
        }
        if !self.proof_aggregation_enabled {
            self.pending.decryption_aggregator_proofs = self.pending.c7_proofs_pending.clone();
            return Ok(());
        }
        let Some(honest_c6) = self.pending.honest_c6_proofs_for_agg.as_ref() else {
            warn!(
                e3_id = %self.e3_id,
                "DecryptionAggregation deferred: honest C6 proofs not retained on aggregator"
            );
            return Ok(());
        };
        // With proof aggregation enabled we must have a complete C6 set; otherwise we'd publish
        // `decryption_aggregator_proofs = Vec::new()`, which downstream consumers interpret as
        // "aggregation disabled". Fail loudly instead so the missing shares are surfaced.
        if honest_c6.is_empty() || honest_c6.iter().any(|(_, w)| w.is_empty()) {
            warn!(
                e3_id = %self.e3_id,
                "DecryptionAggregation: honest C6 inner proofs missing while proof aggregation is enabled"
            );
            return self.fail_decryption_round(ec.clone());
        }
        let state: GeneratingC7Proof = self
            .state
            .get()
            .ok_or(anyhow!("Could not get state"))?
            .try_into()?;
        // C6Fold witness width is `T + 1` (same `T` as `threshold_m`). C7 is only proven for the
        // first `T + 1` parties after sorting by party id (`handle_decrypted_shares_aggregation_proof`
        // truncates); fold slot indices must stay in `0..T+1` and use that same party subset.
        let c6_total_slots = state.threshold_m as usize + 1;
        if honest_c6.len() < c6_total_slots {
            warn!(
                e3_id = %self.e3_id,
                "DecryptionAggregation needs at least {} honest C6 parties, have {}",
                c6_total_slots,
                honest_c6.len()
            );
            return self.fail_decryption_round(ec.clone());
        }
        let num_ct = c7_proofs.len();
        let Some(jobs) = build_decryption_aggregation_jobs(c7_proofs, honest_c6, c6_total_slots)
        else {
            return self.fail_decryption_round(ec.clone());
        };
        let corr = CorrelationId::new();
        info!(
            e3_id = %self.e3_id,
            num_jobs = num_ct,
            c6_slots = c6_total_slots,
            "DecryptionAggregation: publishing Zk compute request"
        );
        self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::DecryptionAggregation(DecryptionAggregationRequest {
                    c6_total_slots,
                    jobs,
                    committee_addresses: self.committee_addresses.clone(),
                    params_preset: self.params_preset,
                    committee_size: self.committee_size,
                }),
                corr,
                self.e3_id.clone(),
            ),
            ec.clone(),
        )?;
        self.pending.decryption_aggregation_correlation = Some(corr);
        Ok(())
    }

    pub fn handle_compute_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        ensure!(
            msg.e3_id == self.e3_id,
            "PlaintextAggregator should never receive incorrect e3_id msgs"
        );

        let correlation_id = msg.correlation_id;
        match msg.response {
            // TrBFV threshold decryption response -> transition to GeneratingC7Proof
            ComputeResponseKind::TrBFV(TrBFVResponse::CalculateThresholdDecryption(response)) => {
                if self.pending.threshold_decryption_correlation.as_ref() != Some(&correlation_id) {
                    return Ok(());
                }
                self.pending.threshold_decryption_correlation = None;
                info!("Received TrBFV threshold decryption response");
                let plaintext = response.plaintext;

                let state: Computing = self
                    .state
                    .get()
                    .ok_or(anyhow!("Could not get state"))?
                    .try_into()?;

                let shares = state.shares.clone();
                let threshold_m = state.threshold_m;
                let threshold_n = state.threshold_n;

                // Publish pending event before transitioning state so a publish
                // failure leaves us in Computing (retryable) rather than
                // GeneratingC7Proof (no retry path).
                self.dispatch_c7_proof_request(
                    shares.clone(),
                    plaintext.clone(),
                    threshold_m,
                    threshold_n,
                    ec.clone(),
                )?;

                // Transition to GeneratingC7Proof
                self.state.try_mutate(&ec, |_| {
                    Ok(ThresholdPlaintextAggregatorState::GeneratingC7Proof(
                        GeneratingC7Proof {
                            threshold_m,
                            threshold_n,
                            shares,
                            plaintext,
                        },
                    ))
                })?;
            }

            ComputeResponseKind::Zk(ZkResponse::DecryptionAggregation(resp)) => {
                if self.pending.decryption_aggregation_correlation.as_ref() == Some(&correlation_id)
                {
                    self.pending.decryption_aggregation_correlation = None;
                    // Worker must return one DecryptionAggregator proof per pending C7 ciphertext.
                    if let Some(c7_proofs) = self.pending.c7_proofs_pending.as_ref() {
                        if resp.proofs.len() != c7_proofs.len() {
                            warn!(
                                e3_id = %self.e3_id,
                                "DecryptionAggregation response proof count {} != expected {}",
                                resp.proofs.len(),
                                c7_proofs.len()
                            );
                            return self.fail_decryption_round(ec);
                        }
                    }
                    self.pending.decryption_aggregator_proofs = Some(resp.proofs);
                    let proofs = self.pending.decryption_aggregator_proofs.clone();
                    self.recovery.try_mutate(&ec, |mut recovery| {
                        recovery.decryption_aggregator_proofs = proofs;
                        recovery.last_ec = Some(ec.clone());
                        Ok(recovery)
                    })?;
                    self.try_publish_complete()?;
                }
            }

            _ => {
                // Not a response we handle — ignore
            }
        }
        let _ = ctx;
        Ok(())
    }
}
