// SPDX-License-Identifier: LGPL-3.0-only

//! Durable capture and restart redrive for threshold-keyshare work.

use super::*;
use anyhow::ensure;

impl ThresholdKeyshare {
    pub(in crate::actors::threshold_keyshare) fn public_key_context_is_recovered(
        state: &ThresholdKeyshareState,
    ) -> bool {
        state.aggregated_pk.is_some() && state.decryption_domain.is_some()
    }

    pub(in crate::actors::threshold_keyshare) fn needs_keyshare_republication(
        state: &ThresholdKeyshareState,
        recovery: &ThresholdKeyshareRecoveryState,
    ) -> bool {
        !Self::public_key_context_is_recovered(state)
            && (recovery.keyshare_publish_authorized || state.keyshare_published)
    }

    pub(in crate::actors::threshold_keyshare) fn record_encryption_key(
        &mut self,
        event: &TypedEvent<EncryptionKeyCreated>,
    ) -> Result<()> {
        let event = event.clone();
        let party_id = event.key.party_id;
        let ec = event.get_ctx().clone();
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.encryption_keys.insert(party_id, event);
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })
    }

    pub(in crate::actors::threshold_keyshare) fn record_threshold_share(
        &mut self,
        event: &TypedEvent<ThresholdShareCreated>,
    ) -> Result<()> {
        let event = event.clone();
        let party_id = event.share.party_id;
        let ec = event.get_ctx().clone();
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.threshold_shares.entry(party_id).or_insert(event);
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })
    }

    pub(in crate::actors::threshold_keyshare) fn record_collected_threshold_shares(
        &mut self,
        event: &TypedEvent<AllThresholdSharesCollected>,
    ) -> Result<()> {
        let ec = event.get_ctx().clone();
        let ids = event.shares.iter().map(|share| share.party_id).collect();
        self.recovery.try_mutate(&ec, |mut recovery| {
            if recovery.collected_threshold_share_ids.is_none() {
                recovery.collected_threshold_share_ids = Some(ids);
            }
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })
    }

    fn rebuild_collected_threshold_shares(
        recovery: &ThresholdKeyshareRecoveryState,
    ) -> Result<AllThresholdSharesCollected> {
        let ids = recovery
            .collected_threshold_share_ids
            .as_ref()
            .ok_or_else(|| anyhow!("missing durable DKG dealer snapshot"))?;
        let mut shares = HashMap::new();
        let mut proofs = HashMap::new();
        for &party_id in ids {
            let event = recovery
                .threshold_shares
                .get(&party_id)
                .ok_or_else(|| anyhow!("DKG dealer snapshot has no stored share"))?;
            shares.insert(party_id, event.share.clone());
            proofs.insert(
                party_id,
                ReceivedShareProofs {
                    signed_c2a_proof: event.signed_c2a_proof.clone(),
                    signed_c2b_proof: event.signed_c2b_proof.clone(),
                    signed_c3a_proofs: event.signed_c3a_proofs.clone(),
                    signed_c3b_proofs: event.signed_c3b_proofs.clone(),
                },
            );
        }
        Ok(AllThresholdSharesCollected::new(shares, proofs))
    }

    pub(in crate::actors::threshold_keyshare) fn record_decryption_key_share(
        &mut self,
        event: &TypedEvent<DecryptionKeyShared>,
    ) -> Result<()> {
        let event = event.clone();
        let party_id = event.party_id;
        let ec = event.get_ctx().clone();
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.decryption_key_shares.insert(party_id, event);
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })
    }

    pub(in crate::actors::threshold_keyshare) fn record_share_verification(
        &mut self,
        event: &TypedEvent<ShareVerificationComplete>,
    ) -> Result<()> {
        let event = event.clone();
        let ec = event.get_ctx().clone();
        let verified_dealer_ids = if event.kind == VerificationKind::ShareProofs {
            let recovery = self.recovery.try_get()?;
            let state = self.state.try_get()?;
            let collected = recovery
                .collected_threshold_share_ids
                .ok_or_else(|| anyhow!("missing durable DKG verification batch"))?;
            Some(
                collected
                    .into_iter()
                    .filter(|party_id| {
                        !event.dishonest_parties.contains(party_id)
                            && !state.expelled_parties.contains(party_id)
                    })
                    .collect::<BTreeSet<u64>>(),
            )
        } else {
            None
        };
        self.recovery.try_mutate(&ec, |mut recovery| {
            match event.kind {
                VerificationKind::ShareProofs => {
                    recovery.verified_dealer_ids = verified_dealer_ids;
                    recovery.share_verification_complete = Some(event);
                }
                VerificationKind::DecryptionProofs => {
                    recovery.decryption_verification_complete = Some(event)
                }
                _ => {}
            }
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })
    }

    fn replay_threshold_shares(
        &mut self,
        recovery: &ThresholdKeyshareRecoveryState,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        if recovery.threshold_shares.is_empty() {
            return Ok(());
        }
        let collector = self.ensure_collector(self_addr)?;
        for event in recovery.threshold_shares.values() {
            collector.try_send(event.clone())?;
        }
        Ok(())
    }

    fn replay_decryption_key_shares(
        &mut self,
        recovery: &ThresholdKeyshareRecoveryState,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        if recovery.decryption_key_shares.is_empty() {
            return Ok(());
        }
        let collector = self.ensure_decryption_key_shared_collector(self_addr)?;
        for event in recovery.decryption_key_shares.values() {
            collector.try_send(event.clone())?;
        }
        Ok(())
    }

    fn resume_generating_threshold_share(
        &mut self,
        data: GeneratingThresholdShareData,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if data.pk_share.is_none() || data.sk_sss.is_none() || data.e_sm_raw.is_none() {
            let selected = data.ciphernode_selected.ok_or_else(|| {
                anyhow!("missing CiphernodeSelected while resuming threshold share")
            })?;
            return self.handle_gen_pk_share_and_sk_sss_requested(TypedEvent::new(
                GenPkShareAndSkSss(selected),
                ec,
            ));
        }

        if data.esi_sss.is_none() {
            let selected = data.ciphernode_selected.ok_or_else(|| {
                anyhow!("missing CiphernodeSelected while resuming ESI generation")
            })?;
            let e_sm_raw = data
                .e_sm_raw
                .ok_or_else(|| anyhow!("missing e_sm_raw while resuming ESI generation"))?;
            return self.handle_gen_esi_sss_requested(TypedEvent::new(
                GenEsiSss {
                    ciphernode_selected: selected,
                    e_sm_raw,
                },
                ec,
            ));
        }

        ensure!(
            data.proof_request_data.is_some(),
            "missing proof request data while resuming generated threshold shares"
        );
        self.handle_shares_generated(ec.clone())?;
        let (own_sk_share_raw, own_esi_shares_raw) = self
            .pending
            .own_dkg_shares
            .take()
            .ok_or_else(|| anyhow!("generated shares did not retain local DKG rows"))?;
        self.state.try_mutate(&ec, |state| {
            let current: GeneratingThresholdShareData = state.clone().try_into()?;
            state.new_state(KeyshareState::AggregatingDecryptionKey(
                AggregatingDecryptionKey {
                    pk_share: current
                        .pk_share
                        .ok_or_else(|| anyhow!("missing generated public-key share"))?,
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
        })
    }

    /// Re-create interrupted collectors and process-local jobs from their persisted inputs.
    pub(in crate::actors::threshold_keyshare) fn resume_in_flight_work(
        &mut self,
        effects_context: EventContext<Sequenced>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let recovery = self.recovery.try_get()?;
        ensure!(
            recovery.schema_version == THRESHOLD_KEYSHARE_RECOVERY_SCHEMA_VERSION,
            "unsupported threshold-keyshare recovery schema version {}",
            recovery.schema_version
        );
        let ec = recovery.last_ec.clone().unwrap_or(effects_context);
        let state = self.state.try_get()?;

        match state.state {
            KeyshareState::Init => {
                let selected = recovery
                    .ciphernode_selected
                    .ok_or_else(|| anyhow!("missing CiphernodeSelected recovery input"))?;
                self_addr.try_send(selected)?;
                Ok(())
            }
            KeyshareState::CollectingEncryptionKeys(data) => {
                let collector = self.ensure_encryption_key_collector(self_addr)?;
                for event in recovery.encryption_keys.values() {
                    collector.try_send(event.clone())?;
                }
                let committee_size = CiphernodesCommitteeSize::from_threshold(
                    state.threshold_m as usize,
                    state.threshold_n as usize,
                )?;
                self.bus.publish(
                    EncryptionKeyPending {
                        e3_id: state.e3_id,
                        key: Arc::new(EncryptionKey::new(state.party_id, data.pk_bfv)),
                        params_preset: self.share_enc_preset,
                        committee_size,
                    },
                    ec,
                )
            }
            KeyshareState::GeneratingThresholdShare(data) => {
                self.replay_threshold_shares(&recovery, self_addr)?;
                self.resume_generating_threshold_share(data, ec)
            }
            KeyshareState::AggregatingDecryptionKey(_) => {
                if let Some(pending) = recovery.threshold_share_pending.clone() {
                    let (pending, pending_ec) = pending.into_components();
                    self.bus.publish(pending, pending_ec)?;
                }
                if let Some(roster) = recovery.dkg_roster.clone() {
                    self.accept_dkg_roster(roster, ec.clone())?;
                    if recovery.dkg_ready.is_some() {
                        return Ok(());
                    }
                    if let Some(verification) = recovery.share_verification_complete.clone() {
                        return self.handle_share_verification_complete(verification);
                    }
                    if recovery.collected_threshold_share_ids.is_some() {
                        let batch = Self::rebuild_collected_threshold_shares(&recovery)?;
                        return self
                            .handle_all_threshold_shares_collected(TypedEvent::new(batch, ec));
                    }
                    return self.replay_threshold_shares(&recovery, self_addr);
                }
                if let Some(verification) = recovery.share_verification_complete.clone() {
                    self.handle_share_verification_complete(verification)?;
                    if let Some(ready) = self.recovery.try_get()?.dkg_ready {
                        self.bus.publish(ready, ec.clone())?;
                    }
                    return self.propose_dkg_roster(ec);
                }
                if recovery.collected_threshold_share_ids.is_some() {
                    let batch = Self::rebuild_collected_threshold_shares(&recovery)?;
                    return self.handle_all_threshold_shares_collected(TypedEvent::new(batch, ec));
                }
                self.replay_threshold_shares(&recovery, self_addr)
            }
            KeyshareState::ReadyForDecryption(_) => {
                // PublicKeyAggregated is a newer durable fact than the retained C2/C3/C4
                // recovery inputs below. Replaying those superseded jobs would rebuild the
                // complete DKG proof pipeline before this node can decrypt.
                if Self::public_key_context_is_recovered(&state) {
                    return Ok(());
                }
                if let Some(pending) = recovery.threshold_share_pending.clone() {
                    let (pending, pending_ec) = pending.into_components();
                    self.bus.publish(pending, pending_ec)?;
                }
                if let Some(pending) = recovery.decryption_share_proofs_pending.clone() {
                    let (pending, pending_ec) = pending.into_components();
                    self.bus.publish(pending, pending_ec)?;
                }
                if let Some(verification) = recovery.decryption_verification_complete.clone() {
                    self.handle_share_verification_complete(verification)
                } else if Self::needs_keyshare_republication(&state, &recovery) {
                    self.publish_keyshare_created(ec)
                } else {
                    self.replay_decryption_key_shares(&recovery, self_addr)
                }
            }
            KeyshareState::Decrypting(_) => {
                if Self::needs_keyshare_republication(&state, &recovery) {
                    self.publish_keyshare_created(ec.clone())?;
                }
                self.issue_decryption_share_request(ec)
            }
            KeyshareState::GeneratingDecryptionProof(_) | KeyshareState::Completed => {
                let pending = recovery.share_decryption_proof_pending.ok_or_else(|| {
                    anyhow!(
                        "missing C6 proof request while resuming threshold-keyshare for E3 {}",
                        state.e3_id
                    )
                })?;
                let (pending, pending_ec) = pending.into_components();
                self.bus.publish(pending, pending_ec)
            }
            KeyshareState::Failed {
                failed_at_stage,
                reason,
            } => self.bus.publish(
                E3Failed {
                    e3_id: state.e3_id,
                    failed_at_stage,
                    reason,
                },
                ec,
            ),
        }
    }
}

#[cfg(test)]
mod dealer_snapshot_tests {
    use super::*;

    #[test]
    fn a_dealer_snapshot_cannot_replay_without_its_stored_share() {
        let mut recovery = ThresholdKeyshareRecoveryState::default();
        recovery.collected_threshold_share_ids = Some(BTreeSet::from([2]));
        assert!(ThresholdKeyshare::rebuild_collected_threshold_shares(&recovery).is_err());
    }
}
