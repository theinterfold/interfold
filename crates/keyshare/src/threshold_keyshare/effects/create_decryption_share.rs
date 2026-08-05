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

        // If we are already in Decrypting (or beyond), this is a duplicate
        // event — e.g. replayed from the EventStore during crash recovery.
        // Re-issue the compute request idempotently (downstream aggregation
        // deduplicates by party_id) and skip the state transition.
        {
            let state = self.state.try_get()?;
            match &state.state {
                KeyshareState::Decrypting(_) => {
                    info!(
                        e3_id = %state.e3_id,
                        "CiphertextOutputPublished received while already Decrypting — re-issuing decryption-share request"
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

        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let decrypting: Decrypting = state.clone().try_into()?;
        let trbfv_config = state.get_trbfv_config();
        let event = ComputeRequest::trbfv(
            TrBFVRequest::CalculateDecryptionShare(CalculateDecryptionShareRequest {
                name: format!("party_id({})", state.party_id),
                ciphertexts: ciphertext_output,
                sk_poly_sum: decrypting.sk_poly_sum,
                es_poly_sum: decrypting.es_poly_sum,
                trbfv_config,
            }),
            CorrelationId::new(),
            e3_id.clone(),
        );
        self.bus.publish(event, ec)?; // CalculateDecryptionShareRequest
        Ok(())
    }

    /// (Re)issue the `CalculateDecryptionShare` compute request from the current
    /// `Decrypting` state. Factored out of `handle_ciphertext_output_published` so the
    /// boot-time resume path can re-drive the decryption-share computation idempotently
    /// (the resulting `DecryptionshareCreated` is deduped by `party_id` at the aggregator).
    pub(in crate::actors::threshold_keyshare) fn issue_decryption_share_request(
        &self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
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
        Ok(())
    }

    /// Re-drive this node's own in-flight DKG/decryption work after a crash or restart.
    ///
    /// Invoked when `EffectsEnabled` is broadcast at the end of boot sync, *after* this
    /// actor has been hydrated from its persisted state. The dangerous, value-bearing
    /// concern with re-driving is double-emission. Re-emission is safe here because:
    ///   * `KeyshareCreated` — `PublicKeyAggregation::add_keyshare` ignores a `party_id`
    ///     that already submitted (idempotent), and
    ///   * `DecryptionshareCreated` — threshold plaintext aggregation keys shares by
    ///     `party_id` (re-insert overwrites with the identical deterministic share), and
    ///   * `E3Failed` — the event bus deduplicates the identical payload by `EventId`.
    ///
    /// Only states where the local result is already determined are re-driven. Earlier
    /// phases depend on peer gossip that cannot be reconstructed locally and are surfaced
    /// (non-destructively) by `interfold node validate` instead of being force-re-driven.
    pub(in crate::actors::threshold_keyshare) fn resume_in_flight_work(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(state) = self.state.get() else {
            return Ok(());
        };
        match &state.state {
            // We have produced our public-key share but may have crashed before (or while)
            // publishing KeyshareCreated. Re-publishing is idempotent at the aggregator, but
            // ReadyForDecryption is entered *before* C4 honest-set verification authorizes the
            // publish, so only re-drive when a prior authorized publish was recorded. An
            // un-published ReadyForDecryption is a loose end surfaced by `interfold node validate`.
            KeyshareState::ReadyForDecryption(_) if state.keyshare_published => {
                info!(
                    e3_id = %state.e3_id,
                    "Resuming in-flight work: re-publishing KeyshareCreated"
                );
                self.publish_keyshare_created(ec)?;
            }
            // The ciphertext to decrypt has arrived. Re-publish our keyshare (in case the
            // crash happened before it propagated) and re-issue the decryption-share
            // computation so a DecryptionshareCreated is (re)produced.
            KeyshareState::Decrypting(_) => {
                info!(
                    e3_id = %state.e3_id,
                    "Resuming in-flight work: re-publishing KeyshareCreated and re-issuing decryption-share request"
                );
                self.publish_keyshare_created(ec.clone())?;
                self.issue_decryption_share_request(ec)?;
            }
            KeyshareState::Failed {
                failed_at_stage,
                reason,
            } => {
                info!(
                    e3_id = %state.e3_id,
                    "Resuming terminal keyshare failure"
                );
                self.bus.publish(
                    E3Failed {
                        e3_id: state.e3_id.clone(),
                        failed_at_stage: failed_at_stage.clone(),
                        reason: reason.clone(),
                    },
                    ec,
                )?;
            }
            other => {
                trace!(
                    e3_id = %state.e3_id,
                    state = %other.variant_name(),
                    "No locally re-drivable work on resume; loose ends are surfaced by `interfold node validate`"
                );
            }
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
        let decrypting: Decrypting = state.clone().try_into()?;
        let d_share_poly = msg.d_share_poly;

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

        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;

        // Publish pending event before transitioning state so a publish
        // failure leaves us in Decrypting (retryable) rather than
        // GeneratingDecryptionProof (no retry path).
        self.bus.publish(
            ShareDecryptionProofPending {
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
            },
            ec.clone(),
        )?;

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
