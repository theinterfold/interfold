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

    /// Issue one share calculation per process. The worker retries the same request.
    pub(in crate::actors::threshold_keyshare) fn issue_decryption_share_request(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if self.pending.decryption_share_requested {
            return Ok(());
        }
        let state = self.state.try_get()?;
        if !self.public_key_context_is_recovered(&state) {
            return Ok(());
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
        self.pending.decryption_share_requested = true;
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn issue_decryption_proof_request(
        &mut self,
        mut pending: ShareDecryptionProofPending,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if self.pending.decryption_proof_requested {
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
        self.bus.publish(pending, ec)?;
        self.pending.decryption_proof_requested = true;
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
