// SPDX-License-Identifier: LGPL-3.0-only

//! ESI generation and encrypted threshold-share publication.

use super::*;

impl ThresholdKeyshare {
    /// Dispatch ESI Shamir-share generation.
    pub fn handle_gen_esi_sss_requested(&self, msg: TypedEvent<GenEsiSss>) -> Result<()> {
        let (msg, ec) = msg.into_components();
        info!("GenEsiSss on ThresholdKeyshare");

        let e_sm_raw = msg.e_sm_raw;
        let CiphernodeSelected { e3_id, .. } = msg.ciphernode_selected;

        let state = self
            .state
            .get()
            .ok_or(anyhow!("State not found on ThrehsoldKeyshare"))?;

        let trbfv_config = state.get_trbfv_config();

        let event = ComputeRequest::trbfv(
            TrBFVRequest::GenEsiSss(GenEsiSssRequest {
                trbfv_config,
                e_sm_raw,
            }),
            CorrelationId::new(),
            e3_id,
        );

        self.bus.publish(event, ec)?;
        Ok(())
    }

    /// 3a. GenEsiSss result
    pub fn handle_gen_esi_sss_response(&mut self, res: TypedEvent<ComputeResponse>) -> Result<()> {
        let (res, ec) = res.into_components();
        let output: GenEsiSssResponse = res.try_into()?;

        let esi_sss = output.esi_sss;

        // First store esi_sss in GeneratingThresholdShareData
        self.state.try_mutate(&ec, |s| {
            info!("try_store_esi_sss");
            let current: GeneratingThresholdShareData = s.clone().try_into()?;
            s.new_state(KeyshareState::GeneratingThresholdShare(
                GeneratingThresholdShareData {
                    esi_sss: Some(esi_sss),
                    ..current
                },
            ))
        })?;

        info!("esi stored");

        // Check if all data is ready, if so call handle_shares_generated BEFORE transitioning
        let current: GeneratingThresholdShareData = self.state.try_get()?.try_into()?;
        let ready = current.pk_share.is_some()
            && current.sk_sss.is_some()
            && current.esi_sss.is_some()
            && current.e_sm_raw.is_some()
            && current.proof_request_data.is_some();

        if ready {
            // Call handle_shares_generated while still in GeneratingThresholdShare state
            self.handle_shares_generated(ec.clone())?;

            // Consume the own plaintext shares stashed transiently by handle_shares_generated.
            let (own_sk_share_raw, own_esi_shares_raw) =
                self.pending.own_dkg_shares.take().ok_or_else(|| {
                    anyhow!("pending_own_dkg_shares missing — handle_shares_generated did not run")
                })?;

            // Now transition to AggregatingDecryptionKey with minimal state
            self.state.try_mutate(&ec, |s| {
                let current: GeneratingThresholdShareData = s.clone().try_into()?;
                s.new_state(KeyshareState::AggregatingDecryptionKey(
                    AggregatingDecryptionKey {
                        pk_share: current.pk_share.expect("pk_share checked above"),
                        sk_bfv: current.sk_bfv,
                        own_sk_share_raw: own_sk_share_raw.clone(),
                        own_esi_shares_raw: own_esi_shares_raw.clone(),
                        signed_pk_generation_proof: None,
                        signed_sk_share_computation_proof: None,
                        signed_e_sm_share_computation_proof: None,
                        signed_sk_share_encryption_proofs: Vec::new(),
                        signed_e_sm_share_encryption_proofs: Vec::new(),
                    },
                ))
            })?;

            // Peers may have completed the collector while we were still generating.
            self.flush_early_all_shares_collected()?;
        }
        Ok(())
    }

    /// 4. SharesGenerated - Encrypt shares with BFV and publish
    pub fn handle_shares_generated(&mut self, ec: EventContext<Sequenced>) -> Result<()> {
        let Some(ThresholdKeyshareState {
            state:
                KeyshareState::GeneratingThresholdShare(GeneratingThresholdShareData {
                    pk_share: Some(pk_share),
                    sk_sss: Some(sk_sss),
                    esi_sss: Some(esi_sss),
                    e_sm_raw: Some(e_sm_raw),
                    proof_request_data: Some(proof_request_data),
                    collected_encryption_keys,
                    ..
                }),
            party_id,
            e3_id,
            threshold_m,
            threshold_n,
            ..
        }) = self.state.get()
        else {
            bail!("Invalid state - expected GeneratingThresholdShare with all data");
        };

        // Decrypt our shares from local storage
        let decrypted_sk_sss: SharedSecret = sk_sss.decrypt(&self.cipher)?;
        let decrypted_esi_sss: Vec<SharedSecret> = esi_sss
            .into_iter()
            .map(|s| s.decrypt(&self.cipher))
            .collect::<Result<_>>()?;

        let plan = build_shares_generated_plan(
            &self.cipher,
            self.share_enc_preset,
            party_id,
            threshold_m,
            threshold_n,
            pk_share,
            decrypted_sk_sss,
            decrypted_esi_sss,
            e_sm_raw,
            proof_request_data,
            &collected_encryption_keys,
        )?;

        // Cache own plaintext share rows for the AggregatingDecryptionKey transition.
        self.pending.own_dkg_shares = Some((plan.own_sk_share_raw, plan.own_esi_shares_raw));

        info!("Publishing ThresholdSharePending for E3 {}", e3_id);

        // Publish ThresholdSharePending - ProofRequestActor will generate proof, sign, and publish ThresholdShareCreated
        let event = ThresholdSharePending {
            e3_id,
            full_share: Arc::new(plan.full_share),
            proof_request: plan.proof_request,
            sk_share_computation_request: plan.sk_share_computation_request,
            e_sm_share_computation_request: plan.e_sm_share_computation_request,
            sk_share_encryption_requests: plan.sk_share_encryption_requests,
            e_sm_share_encryption_requests: plan.e_sm_share_encryption_requests,
            recipient_party_ids: plan.recipient_party_ids,
        };
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.threshold_share_pending = Some(TypedEvent::new(event.clone(), ec.clone()));
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.bus.publish(event, ec)?;

        Ok(())
    }
}
