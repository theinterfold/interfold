// SPDX-License-Identifier: LGPL-3.0-only

//! Ciphertext handling, C6 share calculation, and restart redrive.

use super::*;

impl ThresholdKeyshare {
    /// Handle the ciphertext output and begin local C6 decryption-share work.
    pub fn handle_ciphertext_output_published(
        &mut self,
        msg: TypedEvent<CiphertextOutputPublished>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let ciphertext_output = msg.ciphertext_output;

        // A replayed ciphertext can resume work that this process has not issued.
        {
            let state = self.state.try_get()?;
            match &state.state {
                KeyshareState::Decrypting(_) => {
                    info!(
                        e3_id = %state.e3_id,
                        "CiphertextOutputPublished received while already Decrypting — resuming pending decryption-share work"
                    );
                    return self.issue_decryption_share_request(ec);
                }
                KeyshareState::GeneratingDecryptionProof(_) | KeyshareState::Completed => {
                    info!(
                        e3_id = %state.e3_id,
                        state = %state.variant_name(),
                        "CiphertextOutputPublished received after decryption already in progress — ignoring"
                    );
                    return Ok(());
                }
                KeyshareState::ReadyForDecryption(_) => {
                    // Normal path — proceed with transition below.
                }
                other => {
                    warn!(
                        e3_id = %state.e3_id,
                        state = %other.variant_name(),
                        "CiphertextOutputPublished received in unexpected state — cannot process decryption"
                    );
                    return Ok(());
                }
            }
        }

        // Set state to decrypting, storing ciphertext for later C6 proof generation
        self.state.try_mutate(&ec, |s| {
            use KeyshareState as K;

            let current: ReadyForDecryption = s.clone().try_into()?;

            let next = K::Decrypting(Decrypting {
                pk_share: current.pk_share,
                sk_poly_sum: current.sk_poly_sum,
                es_poly_sum: current.es_poly_sum,
                ciphertext_output: ciphertext_output.clone(),
                signed_pk_generation_proof: current.signed_pk_generation_proof,
                signed_sk_share_computation_proof: current.signed_sk_share_computation_proof,
                signed_e_sm_share_computation_proof: current.signed_e_sm_share_computation_proof,
                signed_sk_share_encryption_proofs: current.signed_sk_share_encryption_proofs,
                signed_e_sm_share_encryption_proofs: current.signed_e_sm_share_encryption_proofs,
            });

            s.new_state(next)
        })?;

        self.issue_decryption_share_request(ec)
    }

    /// Issue one share calculation per process. The worker retries the same request, and the
    /// actor redelivers it when its result does not arrive.
    pub(in crate::actors::threshold_keyshare) fn issue_decryption_share_request(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if self.pending.decryption_share_request.is_some() {
            return Ok(());
        }
        if self.publish_decryption_share_request(ec.clone())? {
            self.pending.decryption_share_request = Some(IssuedDecryptionWork {
                ec,
                last_sent: std::time::Instant::now(),
                redeliveries: 0,
            });
        }
        Ok(())
    }

    /// Publish the share calculation for the saved ciphertext under a new correlation ID. Returns
    /// false when the chain public-key context is not recovered yet.
    fn publish_decryption_share_request(&mut self, ec: EventContext<Sequenced>) -> Result<bool> {
        let state = self.state.try_get()?;
        if !self.public_key_context_is_recovered(&state) {
            return Ok(false);
        }
        let e3_id = state.get_e3_id();
        let decrypting: Decrypting = state.clone().try_into()?;
        let trbfv_config = state.get_trbfv_config();
        let event = ComputeRequest::trbfv(
            TrBFVRequest::CalculateDecryptionShare(CalculateDecryptionShareRequest {
                name: format!("party_id({})", state.party_id),
                ciphertexts: decrypting.ciphertext_output,
                sk_poly_sum: decrypting.sk_poly_sum,
                es_poly_sum: decrypting.es_poly_sum,
                trbfv_config,
            }),
            CorrelationId::new(),
            e3_id.clone(),
        );
        self.bus.publish(event, ec)?;
        Ok(true)
    }

    pub(in crate::actors::threshold_keyshare) fn issue_decryption_proof_request(
        &mut self,
        mut pending: ShareDecryptionProofPending,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if self.pending.decryption_proof_request.is_some() {
            return Ok(());
        }
        let state = self.state.try_get()?;
        if self
            .canonical_keys
            .repair_request(&state.e3_id, &mut pending.proof_request)
            .is_err()
        {
            return Ok(());
        }
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.share_decryption_proof_pending =
                Some(TypedEvent::new(pending.clone(), ec.clone()));
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.bus.publish(pending, ec.clone())?;
        self.pending.decryption_proof_request = Some(IssuedDecryptionWork {
            ec,
            last_sent: std::time::Instant::now(),
            redeliveries: 0,
        });
        Ok(())
    }

    /// Send outstanding decryption work again when its result has not arrived for
    /// `DECRYPTION_REDELIVERY_DELAY`, at most `MAX_DECRYPTION_REDELIVERIES` times per phase. A lost
    /// request or result otherwise holds the node in its phase until a restart.
    pub(in crate::actors::threshold_keyshare) fn redeliver_decryption_work(
        &mut self,
        now: std::time::Instant,
    ) -> Result<()> {
        if !self.effects_enabled {
            return Ok(());
        }
        let due = |work: &IssuedDecryptionWork| {
            work.redeliveries < MAX_DECRYPTION_REDELIVERIES
                && now.saturating_duration_since(work.last_sent) >= DECRYPTION_REDELIVERY_DELAY
        };
        let state = self.state.try_get()?;
        match state.state {
            KeyshareState::Decrypting(_) => {
                let Some(work) = self.pending.decryption_share_request.clone().filter(due) else {
                    return Ok(());
                };
                if self.publish_decryption_share_request(work.ec.clone())? {
                    info!(
                        e3_id = %state.e3_id,
                        redelivery = work.redeliveries + 1,
                        "Redelivering a decryption-share request whose result has not arrived"
                    );
                    self.pending.decryption_share_request = Some(IssuedDecryptionWork {
                        last_sent: now,
                        redeliveries: work.redeliveries + 1,
                        ..work
                    });
                }
            }
            KeyshareState::GeneratingDecryptionProof(_) => {
                let Some(work) = self.pending.decryption_proof_request.clone().filter(due) else {
                    return Ok(());
                };
                let Some(pending) = self.recovery.try_get()?.share_decryption_proof_pending else {
                    return Ok(());
                };
                let mut pending = pending.into_inner();
                // A fresh value per redelivery, also after a restart: a counter would repeat the
                // values of replayed earlier requests.
                pending.redelivery = rand::random::<u64>().max(1);
                info!(
                    e3_id = %state.e3_id,
                    redelivery = pending.redelivery,
                    "Redelivering a C6 proof request whose result has not arrived"
                );
                self.bus.publish(pending, work.ec.clone())?;
                self.pending.decryption_proof_request = Some(IssuedDecryptionWork {
                    last_sent: now,
                    redeliveries: work.redeliveries + 1,
                    ..work
                });
            }
            _ => {}
        }
        Ok(())
    }

    /// CalculateDecryptionShareResponse — publish ShareDecryptionProofPending
    /// so ProofRequestActor generates and signs C6 proofs.
    pub fn handle_calculate_decryption_share_response(
        &mut self,
        res: TypedEvent<ComputeResponse>,
    ) -> Result<()> {
        let (res, ec) = res.into_components();
        let msg: CalculateDecryptionShareResponse = res.try_into()?;
        let state = self.state.try_get()?;
        let e3_id = state.e3_id.clone();
        if !matches!(state.state, KeyshareState::Decrypting(_)) {
            tracing::debug!(
                e3_id = %e3_id,
                state = %state.variant_name(),
                "Ignoring a decryption-share response after leaving Decrypting"
            );
            return Ok(());
        }
        let decrypting: Decrypting = state.clone().try_into()?;
        let d_share_poly = msg.d_share_poly;

        anyhow::ensure!(
            self.public_key_context_is_recovered(&state),
            "chain public-key context is unavailable for C6 proof"
        );
        let aggregated_pk_bytes = state
            .aggregated_pk
            .clone()
            .ok_or_else(|| anyhow!("Aggregated public key not available for C6 proof"))?;
        let decryption_domain = state
            .decryption_domain
            .ok_or_else(|| anyhow!("E3 decryption domain not available for C6 proof"))?;

        let threshold_preset = self
            .share_enc_preset
            .threshold_counterpart()
            .ok_or_else(|| {
                anyhow!(
                    "No threshold counterpart for preset {:?}",
                    self.share_enc_preset
                )
            })?;

        info!("Publishing ShareDecryptionProofPending for C6 proof generation...");

        let committee_size = state.committee_size()?;

        // Publish pending event before transitioning state so a publish
        // failure leaves us in Decrypting (retryable) rather than
        // GeneratingDecryptionProof (no retry path).
        let event = ShareDecryptionProofPending {
            e3_id: e3_id.clone(),
            party_id: state.party_id,
            node: state.address.clone(),
            decryption_share: d_share_poly.clone(),
            proof_request: ThresholdShareDecryptionProofRequest {
                ciphertext_bytes: decrypting.ciphertext_output,
                aggregated_pk_bytes,
                sk_poly_sum: decrypting.sk_poly_sum,
                es_poly_sum: decrypting.es_poly_sum,
                d_share_bytes: d_share_poly.clone(),
                decryption_domain,
                params_preset: threshold_preset,
                committee_size,
            },
            redelivery: 0,
        };
        self.issue_decryption_proof_request(event, ec.clone())?;

        // Transition to GeneratingDecryptionProof state
        self.state.try_mutate(&ec, |s| {
            use KeyshareState as K;
            s.new_state(K::GeneratingDecryptionProof(GeneratingDecryptionProof {
                pk_share: decrypting.pk_share.clone(),
                decryption_share: d_share_poly,
                signed_pk_generation_proof: decrypting.signed_pk_generation_proof.clone(),
                signed_sk_share_computation_proof: decrypting
                    .signed_sk_share_computation_proof
                    .clone(),
                signed_e_sm_share_computation_proof: decrypting
                    .signed_e_sm_share_computation_proof
                    .clone(),
                signed_sk_share_encryption_proofs: decrypting
                    .signed_sk_share_encryption_proofs
                    .clone(),
                signed_e_sm_share_encryption_proofs: decrypting
                    .signed_e_sm_share_encryption_proofs
                    .clone(),
            }))
        })?;
        Ok(())
    }

    pub fn handle_decryption_share_proof_signed(
        &mut self,
        msg: TypedEvent<DecryptionShareProofSigned>,
    ) -> Result<()> {
        let (_msg, ec) = msg.into_components();

        self.state.try_mutate(&ec, |s| {
            use KeyshareState as K;
            info!("Decryption share sending process is complete");
            s.new_state(K::Completed)
        })?;

        Ok(())
    }
}
