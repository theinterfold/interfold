// SPDX-License-Identifier: LGPL-3.0-only

//! Decryption-key calculation and early C4 share handling.

use super::*;

impl ThresholdKeyshare {
    /// After verification, decrypt shares from honest parties and compute the decryption key.
    /// C4 proof generation is deferred to ProofRequestActor via DecryptionShareProofsPending.
    pub(in crate::actors::threshold_keyshare) fn proceed_with_decryption_key_calculation(
        &mut self,
        dishonest_parties: Option<HashSet<u64>>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let trbfv_config = state.get_trbfv_config();

        // Get our BFV secret key from state, pending shares from the actor
        let current: AggregatingDecryptionKey = state.clone().try_into()?;
        let shares = std::mem::take(&mut self.pending.shares);

        let plan = build_decryption_key_plan(
            &self.cipher,
            self.share_enc_preset,
            state.party_id,
            state.threshold_m,
            state.threshold_n,
            trbfv_config,
            &current,
            shares,
            dishonest_parties,
            e3_id,
        )?;

        match plan {
            DecryptionKeyPlan::Insufficient => {
                self.pending.shares.clear();
                self.bus.publish(
                    E3Failed {
                        e3_id: e3_id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::InsufficientCommitteeMembers,
                    },
                    ec,
                )?;
            }
            DecryptionKeyPlan::Proceed {
                calc_request,
                sk_request,
                esm_requests,
                honest_party_ids,
            } => {
                // Publish CalculateDecryptionKey request before persisting (ordering preserved).
                let event = ComputeRequest::trbfv(
                    TrBFVRequest::CalculateDecryptionKey(calc_request),
                    CorrelationId::new(),
                    e3_id.clone(),
                );
                self.bus.publish(event, ec.clone())?;

                // Store honest parties and C4 data on the actor (transient coordination)
                self.state.try_mutate(&ec, |mut s| {
                    s.honest_parties = Some(honest_party_ids.clone());
                    Ok(s)
                })?;
                self.pending.share_decryption_data = Some((sk_request, esm_requests));
            }
        }

        Ok(())
    }

    /// 5a. CalculateDecryptionKeyResponse — transition to ReadyForDecryption,
    /// then publish DecryptionShareProofsPending so ProofRequestActor can
    /// generate C4 proofs, sign them, and publish DecryptionKeyShared.
    pub fn handle_calculate_decryption_key_response(
        &mut self,
        res: TypedEvent<ComputeResponse>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let (res, ec) = res.into_components();

        // A restart inside the DKG window can drive this compute twice: once from the
        // event-store replay of the original `ComputeRequest` and once from the re-driven
        // `ShareVerificationComplete`. The gate cannot dedup them (different correlation
        // ids). The first response wins and moves us to `ReadyForDecryption`; the second is
        // a no-op, not an error — the node is healthy and the key is already derived.
        let state = self.state.try_get()?;
        if !matches!(state.state, KeyshareState::AggregatingDecryptionKey(_)) {
            debug!(
                "Ignoring CalculateDecryptionKey response in {:?}; key already derived",
                state.state.variant_name()
            );
            return Ok(());
        }

        let output: CalculateDecryptionKeyResponse = res
            .try_into()
            .context("Error extracting data from compute process")?;

        let (sk_poly_sum, es_poly_sum) = (output.sk_poly_sum, output.es_poly_sum);

        // Keep C4 inputs until the recovery record and phase transition succeed.
        let (sk_request, esm_requests) = self
            .pending
            .share_decryption_data
            .clone()
            .ok_or_else(|| anyhow!("No pending share decryption data — CalculateDecryptionKey responded before proof requests were built"))?;

        // Keep early shares until they are handed to the collector.
        let early_shares = self
            .pending
            .c4_verification_shares
            .clone()
            .unwrap_or_default();

        // Accept the C4 proof intent before advancing the primary phase. A crash cannot then
        // leave ReadyForDecryption without the input required to recreate its proof job.
        let e3_id = state.get_e3_id();
        let party_id = state.party_id;
        let node = state.address.clone();

        info!(
            "Publishing DecryptionShareProofsPending for E3 {} party {} (1 SK + {} ESM requests)",
            e3_id,
            party_id,
            esm_requests.len()
        );

        let event = DecryptionShareProofsPending {
            e3_id: e3_id.clone(),
            party_id,
            node,
            sk_request,
            esm_requests,
        };
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.decryption_share_proofs_pending =
                Some(TypedEvent::new(event.clone(), ec.clone()));
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;

        // Transition to ReadyForDecryption only after the recovery input is accepted.
        self.state.try_mutate(&ec, |s| {
            use KeyshareState as K;
            info!("Try store decryption key");

            let current: AggregatingDecryptionKey = s.clone().try_into()?;

            let next = K::ReadyForDecryption(ReadyForDecryption {
                pk_share: current.pk_share,
                sk_poly_sum: sk_poly_sum.clone(),
                es_poly_sum: es_poly_sum.clone(),
                signed_pk_generation_proof: current.signed_pk_generation_proof,
                signed_sk_share_computation_proof: current.signed_sk_share_computation_proof,
                signed_e_sm_share_computation_proof: current.signed_e_sm_share_computation_proof,
                signed_sk_share_encryption_proofs: current.signed_sk_share_encryption_proofs,
                signed_e_sm_share_encryption_proofs: current.signed_e_sm_share_encryption_proofs,
            });

            s.new_state(next)
        })?;

        // Publish DecryptionShareProofsPending to ProofRequestActor.
        self.bus.publish(event, ec.clone())?;

        // Create collector and replay any early-arriving DecryptionKeyShared events
        let state = self.state.try_get()?;
        let my_party_id = state.party_id;
        let honest = state.honest_parties.as_ref().cloned().unwrap_or_default();
        let expected: HashSet<u64> = honest
            .iter()
            .filter(|&&pid| pid != my_party_id)
            .copied()
            .collect();

        if !expected.is_empty() {
            let collector = self.ensure_decryption_key_shared_collector(self_addr)?;
            for (_pid, share) in early_shares {
                collector.do_send(TypedEvent::new(share, ec.clone()));
            }
        }

        self.pending.share_decryption_data = None;
        self.pending.c4_verification_shares = None;

        Ok(())
    }

    /// Handle an external DecryptionKeyShared event while in AggregatingDecryptionKey state.
    /// Store it for later processing when we transition to ReadyForDecryption.
    pub(in crate::actors::threshold_keyshare) fn handle_early_decryption_key_share(
        &mut self,
        data: DecryptionKeyShared,
        _ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let party_id = data.party_id;
        let state = self.state.try_get()?;
        if state.expelled_parties.contains(&party_id) {
            info!(
                "Dropping early DecryptionKeyShared from expelled party {}",
                party_id
            );
            return Ok(());
        }
        info!(
            "Storing early DecryptionKeyShared from party {} (state: AggregatingDecryptionKey)",
            party_id
        );
        self.pending
            .c4_verification_shares
            .get_or_insert_with(HashMap::new)
            .insert(party_id, data);
        Ok(())
    }
}
