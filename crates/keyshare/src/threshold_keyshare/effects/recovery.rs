// SPDX-License-Identifier: LGPL-3.0-only

//! Durable capture and restart redrive for threshold-keyshare work.

use super::*;
use anyhow::ensure;

impl ThresholdKeyshare {
    pub(in crate::actors::threshold_keyshare) fn clear_pending_recovery_payload(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        self.recovery.try_mutate(ec, |mut recovery| {
            recovery.threshold_share_pending_ref = None;
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        if let Err(error) = self.recovery_payloads.write_pending_tombstone(ec) {
            warn!(%error, "Could not retire completed DKG proof work");
        }
        self.recovery_payloads.forget_pending();
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn clear_large_recovery_payloads(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let party_count = self.state.try_get()?.threshold_n;
        self.recovery.try_mutate(ec, |mut recovery| {
            recovery.threshold_share_pending_ref = None;
            recovery.threshold_share_refs.clear();
            recovery.collected_threshold_share_ids = None;
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.recovery_payloads.write_pending_tombstone(ec)?;
        self.recovery_payloads
            .write_all_share_tombstones(party_count, ec)?;
        self.recovery_payloads.forget_pending();
        self.recovery_payloads.forget_shares();
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn public_key_context_is_recovered(
        &self,
        state: &ThresholdKeyshareState,
    ) -> bool {
        self.canonical_keys.get(&state.e3_id).is_some_and(|key| {
            state.decryption_domain == Some(key.domain(self.interfold_address))
                && state
                    .aggregated_pk
                    .as_ref()
                    .is_some_and(|pk| key.validate_key(pk).is_ok())
        })
    }

    pub(in crate::actors::threshold_keyshare) fn needs_keyshare_republication(
        &self,
        state: &ThresholdKeyshareState,
        recovery: &ThresholdKeyshareRecoveryState,
    ) -> bool {
        self.canonical_keys.get(&state.e3_id).is_none()
            && (recovery.keyshare_publish_authorized || state.keyshare_published)
    }

    /// Admit the key of a `PublicKeyAggregated` that matches the canonical key authority.
    pub(in crate::actors::threshold_keyshare) fn handle_public_key_aggregated(
        &mut self,
        data: e3_events::PublicKeyAggregated,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(key) = self.canonical_keys.get(&data.e3_id) else {
            return Ok(());
        };
        if !key.accepts(&data) {
            return Ok(());
        }
        self.admit_public_key(data.pubkey, ec)
    }

    /// Record the key publication stage of a chain `CommitteePublished`, and admit its key when it
    /// matches the canonical key authority. A peer copy establishes nothing.
    pub(in crate::actors::threshold_keyshare) fn handle_committee_published(
        &mut self,
        data: e3_events::CommitteePublished,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if ec.source() == e3_events::EventSource::Net {
            return Ok(());
        }
        self.observe_canonical_stage(&data.e3_id, &E3Stage::KeyPublished);
        let Some(key) = self.canonical_keys.get(&data.e3_id) else {
            return Ok(());
        };
        if !validation::committee_publication_matches(&key, &data) {
            return Ok(());
        }
        self.admit_public_key(data.public_key, ec)
    }

    pub(in crate::actors::threshold_keyshare) fn admit_public_key(
        &mut self,
        pk: ArcBytes,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if self.public_key_context_is_recovered(&state) {
            return Ok(());
        }
        let key = self
            .canonical_keys
            .get(&state.e3_id)
            .ok_or_else(|| anyhow!("chain public-key context is unavailable"))?;
        key.validate_key(&pk)?;
        let domain = key.domain(self.interfold_address);
        self.state.try_mutate(ec, |mut state| {
            state.aggregated_pk = Some(pk);
            state.decryption_domain = Some(domain);
            Ok(state)
        })?;
        self.resume_decryption_work(ec.clone())
    }

    pub(in crate::actors::threshold_keyshare) fn restore_public_key_context(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if self.public_key_context_is_recovered(&state) {
            return Ok(());
        }
        if let Some(key) = self.canonical_keys.get(&state.e3_id) {
            if let Some(pk) = self.canonical_keys.public_key(&state.e3_id).or_else(|| {
                state
                    .aggregated_pk
                    .clone()
                    .filter(|pk| key.validate_key(pk).is_ok())
            }) {
                return self.admit_public_key(pk, ec);
            }
        }
        if state.aggregated_pk.is_some() || state.decryption_domain.is_some() {
            self.state.try_mutate(ec, |mut state| {
                state.aggregated_pk = None;
                state.decryption_domain = None;
                Ok(state)
            })?;
        }
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn resume_decryption_work(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if !self.effects_enabled {
            return Ok(());
        }
        let state = self.state.try_get()?;
        match state.state {
            KeyshareState::Decrypting(_) => self.issue_decryption_share_request(ec),
            KeyshareState::GeneratingDecryptionProof(_) | KeyshareState::Completed => {
                let Some(pending) = self.recovery.try_get()?.share_decryption_proof_pending else {
                    return Ok(());
                };
                self.issue_decryption_proof_request(pending.into_inner(), ec)
            }
            _ => Ok(()),
        }
    }

    pub(in crate::actors::threshold_keyshare) fn record_encryption_key(
        &mut self,
        event: &TypedEvent<EncryptionKeyCreated>,
    ) -> Result<()> {
        let event = event.clone();
        let party_id = event.key.party_id;
        let ec = event.get_ctx().clone();
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.encryption_keys.entry(party_id).or_insert(event);
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })
    }

    pub(in crate::actors::threshold_keyshare) fn record_threshold_share(
        &mut self,
        event: &TypedEvent<ThresholdShareCreated>,
    ) -> Result<()> {
        if let Some(existing) = self.recovery_payloads.share(event.share.party_id) {
            ensure!(
                **existing == **event,
                "conflicting DKG share from the same party"
            );
            return Ok(());
        }
        let event = event.clone();
        let party_id = event.share.party_id;
        let ec = event.get_ctx().clone();
        let payload_ref = self.recovery_payloads.write_share(&event, &ec)?;
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery
                .threshold_share_refs
                .entry(party_id)
                .or_insert(payload_ref);
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.recovery_payloads.remember_share(event);
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn record_collected_threshold_shares(
        &mut self,
        event: &TypedEvent<AllThresholdSharesCollected>,
    ) -> Result<bool> {
        let ec = event.get_ctx().clone();
        let ids: BTreeSet<u64> = event.shares.iter().map(|share| share.party_id).collect();
        let state = self.state.try_get()?;
        // A collector can send its result before it stops; after the decryption-key calculation
        // retired the batch, that result must not restore it.
        if !state.state.share_collection_is_open() {
            return Ok(false);
        }
        let expelled = state.expelled_parties;
        let mut accepted = false;
        self.recovery.try_mutate(&ec, |mut recovery| {
            let verification_in_flight = recovery.collected_threshold_share_ids.is_some()
                && recovery.share_verification_complete.is_none();
            let extends_previous = recovery
                .collected_threshold_share_ids
                .as_ref()
                .is_none_or(|existing| batch_grows(existing, &ids, &expelled));
            if !verification_in_flight && extends_previous {
                recovery.collected_threshold_share_ids = Some(ids);
                recovery.share_verification_complete = None;
                recovery.share_dispatch_ids.clear();
                accepted = true;
            }
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        Ok(accepted)
    }

    fn rebuild_collected_threshold_shares(
        recovery: &ThresholdKeyshareRecoveryState,
        payloads: &ThresholdKeyshareRecoveryPayloads,
    ) -> Result<AllThresholdSharesCollected> {
        let ids = recovery
            .collected_threshold_share_ids
            .as_ref()
            .ok_or_else(|| anyhow!("missing durable DKG dealer snapshot"))?;
        let mut shares = HashMap::new();
        let mut proofs = HashMap::new();
        for &party_id in ids {
            recovery
                .threshold_share_refs
                .get(&party_id)
                .ok_or_else(|| anyhow!("DKG dealer snapshot has no stored share"))?;
            let event = payloads
                .share(party_id)
                .ok_or_else(|| anyhow!("DKG dealer recovery payload is not loaded"))?;
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

    /// Verify a recorded C2/C3 batch that has no verification result yet.
    pub(in crate::actors::threshold_keyshare) fn verify_recorded_threshold_shares(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let recovery = self.recovery.try_get()?;
        if recovery.collected_threshold_share_ids.is_none()
            || recovery.share_verification_complete.is_some()
        {
            return Ok(());
        }
        let batch = Self::rebuild_collected_threshold_shares(&recovery, &self.recovery_payloads)?;
        self.handle_all_threshold_shares_collected(TypedEvent::new(batch, ec))
    }

    pub(in crate::actors::threshold_keyshare) fn dispatch_expanded_threshold_share_batch(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if !matches!(state.state, KeyshareState::AggregatingDecryptionKey(_)) {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        if recovery.dkg_roster.is_some() || recovery.share_verification_complete.is_none() {
            return Ok(());
        }
        let current = recovery
            .collected_threshold_share_ids
            .clone()
            .unwrap_or_default();
        let available = recovery
            .threshold_share_refs
            .keys()
            .filter(|party_id| !state.expelled_parties.contains(*party_id))
            .copied()
            .collect::<BTreeSet<_>>();
        if !batch_grows(&current, &available, &state.expelled_parties) {
            return Ok(());
        }

        let mut expanded = recovery;
        expanded.collected_threshold_share_ids = Some(available);
        let batch = Self::rebuild_collected_threshold_shares(&expanded, &self.recovery_payloads)?;
        let event = TypedEvent::new(batch, ec);
        if self.record_collected_threshold_shares(&event)? {
            self.handle_all_threshold_shares_collected(event)?;
        }
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn record_decryption_key_share(
        &mut self,
        event: &TypedEvent<DecryptionKeyShared>,
    ) -> Result<()> {
        let event = event.clone();
        let party_id = event.party_id;
        let ec = event.get_ctx().clone();
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery
                .decryption_key_shares
                .entry(party_id)
                .or_insert(event);
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

    /// Send every recorded key to the encryption-key collector, then `EncryptionKeysReplayed`.
    ///
    /// A peer key that arrives while the keyshare is in `Init` is only recorded. The collector needs
    /// the frozen DKG timing, which this node reads when it handles its own selection. A collector
    /// that restart recovery creates after the cutoff applies the cutoff when the replay ends.
    ///
    /// Keys from expelled parties are sent too. The collector ignores the key of a party that it
    /// knows is expelled. After a later expulsion, the keyshare removes that party's key from the
    /// completed collection and fails the DKG if fewer than H keys remain.
    pub(in crate::actors::threshold_keyshare) fn replay_encryption_keys(
        &self,
        collector: &Addr<EncryptionKeyCollector>,
    ) -> Result<()> {
        for event in self.recovery.try_get()?.encryption_keys.values() {
            collector.try_send(event.clone())?;
        }
        collector.try_send(EncryptionKeysReplayed)?;
        Ok(())
    }

    fn replay_threshold_shares(
        &mut self,
        self_addr: Addr<Self>,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if self.recovery_payloads.shares().is_empty() {
            return Ok(());
        }
        self.rebuild_threshold_share_collector(self_addr, ec)
    }

    /// Restore the collector with its retained shares and the remaining canonical deadline.
    fn rebuild_threshold_share_collector(
        &mut self,
        self_addr: Addr<Self>,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        self.ensure_collector(
            self_addr,
            ec,
            crate::domain::timeout_policy::now_unix_secs(),
        )?;
        Ok(())
    }

    fn replay_decryption_key_shares(
        &mut self,
        recovery: &ThresholdKeyshareRecoveryState,
        self_addr: Addr<Self>,
    ) -> Result<()> {
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
        })?;
        self.verify_recorded_threshold_shares(ec)
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
        // The saved expulsions can already explain a held Ready update: the write that applies it
        // is separate from the expulsion's, and a refused write must not strand the update.
        self.apply_held_ready_updates(ec.clone())?;
        let recovery = self.recovery.try_get()?;
        self.restore_public_key_context(&ec)?;
        let state = self.state.try_get()?;
        info!(
            e3_id = %state.e3_id,
            ready_for_decryption = matches!(&state.state, KeyshareState::ReadyForDecryption(_)),
            c4_proof_intent = recovery.decryption_share_proofs_pending.is_some(),
            "resuming persisted threshold keyshare work"
        );
        // Derived before the match moves `state.state`; only the CollectingEncryptionKeys arm
        // needs it, so an error surfaces there and nowhere else.
        let committee_size = state.committee_size();

        match state.state {
            KeyshareState::Init => {
                let selected = recovery
                    .ciphernode_selected
                    .ok_or_else(|| anyhow!("missing CiphernodeSelected recovery input"))?;
                self_addr.try_send(selected)?;
                Ok(())
            }
            KeyshareState::CollectingEncryptionKeys(data) => {
                let collector = self.recover_encryption_key_collector(self_addr.clone(), &ec)?;
                self.replay_encryption_keys(&collector)?;
                // Selection creates the threshold-share collector too. A peer can send this node
                // its share while this node still collects encryption keys.
                self.rebuild_threshold_share_collector(self_addr, &ec)?;
                let committee_size = committee_size?;
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
                self.replay_threshold_shares(self_addr, &ec)?;
                self.resume_generating_threshold_share(data, ec)
            }
            KeyshareState::AggregatingDecryptionKey(_) => {
                if let Some(pending) = self.recovery_payloads.pending().cloned() {
                    let (pending, pending_ec) = pending.into_components();
                    self.bus.publish(pending, pending_ec)?;
                }
                if let Some(roster) = recovery.dkg_roster.clone() {
                    self.accept_dkg_roster(roster, ec.clone())?;
                    if recovery.dkg_ready.is_some() {
                        return Ok(());
                    }
                    if let Some(verification) = recovery.share_verification_complete.clone() {
                        self.handle_share_verification_complete(verification)?;
                        return self.dispatch_expanded_threshold_share_batch(ec);
                    }
                    if recovery.collected_threshold_share_ids.is_some() {
                        return self.verify_recorded_threshold_shares(ec);
                    }
                    return self.replay_threshold_shares(self_addr, &ec);
                }
                if let Some(verification) = recovery.share_verification_complete.clone() {
                    self.handle_share_verification_complete(verification)?;
                    self.dispatch_expanded_threshold_share_batch(ec.clone())?;
                    if let Some(ready) = self.recovery.try_get()?.dkg_ready {
                        self.bus.publish(ready, ec.clone())?;
                    }
                    return self.propose_dkg_roster(ec);
                }
                if recovery.collected_threshold_share_ids.is_some() {
                    return self.verify_recorded_threshold_shares(ec);
                }
                self.replay_threshold_shares(self_addr, &ec)
            }
            KeyshareState::ReadyForDecryption(_) => {
                // Chain key publication supersedes the retained DKG recovery work.
                if self.canonical_keys.get(&state.e3_id).is_some() {
                    return Ok(());
                }
                if recovery.decryption_verification_complete.is_none()
                    && !self.needs_keyshare_republication(&state, &recovery)
                {
                    self.replay_decryption_key_shares(&recovery, self_addr)?;
                }
                if let Some(pending) = self.recovery_payloads.pending().cloned() {
                    let (pending, pending_ec) = pending.into_components();
                    self.bus.publish(pending, pending_ec)?;
                }
                if let Some(pending) = recovery.decryption_share_proofs_pending.clone() {
                    let (pending, pending_ec) = pending.into_components();
                    self.bus.publish(pending, pending_ec)?;
                }
                if let Some(verification) = recovery.decryption_verification_complete.clone() {
                    self.handle_share_verification_complete(verification)
                } else if self.needs_keyshare_republication(&state, &recovery) {
                    self.publish_keyshare_created(ec)
                } else {
                    Ok(())
                }
            }
            KeyshareState::Decrypting(_) => {
                if self.needs_keyshare_republication(&state, &recovery) {
                    self.publish_keyshare_created(ec.clone())?;
                }
                self.issue_decryption_share_request(ec)
            }
            KeyshareState::GeneratingDecryptionProof(_) | KeyshareState::Completed => {
                self.resume_decryption_work(ec)
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
    use e3_data::{DataStore, InMemStore};

    #[actix::test]
    async fn a_dealer_snapshot_cannot_replay_without_its_stored_share() {
        let recovery = ThresholdKeyshareRecoveryState {
            collected_threshold_share_ids: Some(BTreeSet::from([2])),
            ..Default::default()
        };
        let store = InMemStore::new(false).start();
        let payloads = ThresholdKeyshareRecoveryPayloads::new(DataStore::from_in_mem(&store));
        assert!(
            ThresholdKeyshare::rebuild_collected_threshold_shares(&recovery, &payloads).is_err()
        );
    }
}
