// SPDX-License-Identifier: LGPL-3.0-only

//! Encrypted threshold-share publication.

use super::*;

impl ThresholdKeyshare {
    pub fn publish_generated_threshold_shares(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        self.handle_shares_generated(ec.clone())?;
        let own_sk_share_raw = self.pending.own_dkg_shares.take().ok_or_else(|| {
            anyhow!("pending_own_dkg_shares missing — handle_shares_generated did not run")
        })?;
        let outgoing_prf_keys = self.pending.outgoing_prf_keys.clone();
        self.state.try_mutate(&ec, |s| {
            let current: GeneratingThresholdShareData = s.clone().try_into()?;
            s.new_state(KeyshareState::AggregatingDecryptionKey(
                AggregatingDecryptionKey {
                    pk_share: current.pk_share.expect("pk_share checked above"),
                    sk_bfv: current.sk_bfv,
                    own_sk_share_raw: own_sk_share_raw.clone(),
                    signed_pk_generation_proof: None,
                    signed_sk_share_computation_proof: None,
                    signed_sk_share_encryption_proofs: Vec::new(),
                    outgoing_prf_keys,
                },
            ))
        })
    }

    /// 4. SharesGenerated - Encrypt shares with BFV and publish
    pub fn handle_shares_generated(&mut self, ec: EventContext<Sequenced>) -> Result<()> {
        let state = self.state.try_get()?;
        let committee_size = state.committee_size()?;
        let ThresholdKeyshareState {
            state:
                KeyshareState::GeneratingThresholdShare(GeneratingThresholdShareData {
                    pk_share: Some(pk_share),
                    sk_sss: Some(sk_sss),
                    proof_request_data: Some(proof_request_data),
                    collected_encryption_keys,
                    ..
                }),
            party_id,
            e3_id,
            ..
        } = state
        else {
            bail!("Invalid state - expected GeneratingThresholdShare with all data");
        };

        // Decrypt our shares from local storage
        let decrypted_sk_sss: SharedSecret = sk_sss.decrypt(&self.cipher)?;

        let plan = build_shares_generated_plan(
            &self.cipher,
            self.share_enc_preset,
            party_id,
            committee_size,
            pk_share,
            decrypted_sk_sss,
            proof_request_data,
            &collected_encryption_keys,
        )?;

        // Cache own plaintext share rows for the AggregatingDecryptionKey transition.
        self.pending.own_dkg_shares = Some(plan.own_sk_share_raw);
        self.pending.outgoing_prf_keys = plan.sk_share_computation_request.prf_keys.clone();

        info!("Publishing ThresholdSharePending for E3 {}", e3_id);

        // Publish ThresholdSharePending - ProofRequestActor will generate proof, sign, and publish ThresholdShareCreated
        let event = ThresholdSharePending {
            e3_id,
            full_share: Arc::new(plan.full_share),
            proof_request: plan.proof_request,
            sk_share_computation_request: plan.sk_share_computation_request,
            sk_share_encryption_requests: plan.sk_share_encryption_requests,
            recipient_party_ids: plan.recipient_party_ids,
        };
        let pending = TypedEvent::new(event.clone(), ec.clone());
        let payload_ref = self.recovery_payloads.write_pending(&pending, &ec)?;
        self.recovery.try_mutate(&ec, |mut recovery| {
            if let Some(existing) = recovery.threshold_share_pending_ref.as_ref() {
                anyhow::ensure!(
                    existing == &payload_ref,
                    "generated DKG work plan conflicts with its recovery payload"
                );
            }
            recovery.threshold_share_pending_ref = Some(payload_ref.clone());
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.recovery_payloads.remember_pending(pending);
        self.bus.publish(event, ec)?;

        Ok(())
    }
}
