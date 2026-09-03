// SPDX-License-Identifier: LGPL-3.0-only

//! Collector lifecycle, expulsion, and early artifact routing.

use super::*;

impl ThresholdKeyshare {
    pub fn ensure_collector(
        &mut self,
        self_addr: Addr<Self>,
    ) -> Result<Addr<ThresholdShareCollector>> {
        let Some(state) = self.state.get() else {
            bail!("State not found on threshold keyshare. This should not happen.");
        };

        info!(
            "Setting up key collector for addr: {} and {} nodes",
            state.address, state.threshold_n
        );
        let e3_id = state.e3_id.clone();
        let threshold_n = state.threshold_n;
        let own_party_id = state.party_id;
        let timeout = resolve_timeout(
            DkgTimeoutPhase::ThresholdShareCollection,
            state.dkg_started_at_unix_secs,
        );
        info!(
            e3_id = %e3_id,
            timeout = ?timeout.duration,
            "{}",
            timeout.description
        );
        let addr = self.decryption_key_collector.get_or_insert_with(|| {
            ThresholdShareCollector::setup(
                self_addr,
                threshold_n,
                own_party_id,
                e3_id,
                timeout.duration,
            )
        });
        Ok(addr.clone())
    }

    pub fn ensure_encryption_key_collector(
        &mut self,
        self_addr: Addr<Self>,
    ) -> Result<Addr<EncryptionKeyCollector>> {
        let Some(state) = self.state.get() else {
            bail!("State not found on threshold keyshare. This should not happen.");
        };

        info!(
            "Setting up encryption key collector for addr: {} and {} nodes",
            state.address, state.threshold_n
        );
        let e3_id = state.e3_id.clone();
        let threshold_n = state.threshold_n;
        let timeout = resolve_timeout(
            DkgTimeoutPhase::EncryptionKeyCollection,
            state.dkg_started_at_unix_secs,
        );
        info!(
            e3_id = %e3_id,
            timeout = ?timeout.duration,
            "{}",
            timeout.description
        );
        let addr = self.encryption_key_collector.get_or_insert_with(|| {
            EncryptionKeyCollector::setup(self_addr, threshold_n, e3_id, timeout.duration)
        });
        Ok(addr.clone())
    }

    /// Create or return the DecryptionKeySharedCollector.
    /// Uses honest_parties from persisted state.
    pub fn ensure_decryption_key_shared_collector(
        &mut self,
        self_addr: Addr<Self>,
    ) -> Result<Addr<DecryptionKeySharedCollector>> {
        let state = self.state.try_get()?;
        let my_party_id = state.party_id;

        let honest = state
            .honest_parties
            .as_ref()
            .ok_or_else(|| anyhow!("honest_parties not set when creating collector"))?;

        let expected: HashSet<u64> = honest
            .iter()
            .filter(|&&pid| pid != my_party_id)
            .copied()
            .collect();

        let e3_id = state.e3_id.clone();
        let timeout = resolve_timeout(
            DkgTimeoutPhase::DecryptionKeySharedCollection,
            state.dkg_started_at_unix_secs,
        );
        info!(
            e3_id = %e3_id,
            timeout = ?timeout.duration,
            "{}",
            timeout.description
        );
        let addr = self.decryption_key_shared_collector.get_or_insert_with(|| {
            DecryptionKeySharedCollector::setup(self_addr, expected, e3_id, timeout.duration)
        });
        Ok(addr.clone())
    }

    pub(in crate::actors::threshold_keyshare) fn handle_committee_member_expelled(
        &mut self,
        data: CommitteeMemberExpelled,
        ec: EventContext<Sequenced>,
    ) {
        // Only process enriched events (party_id resolved by Sortition).
        // Raw events from chain (party_id = None) are ignored here;
        // Sortition will re-publish them with party_id set.
        let Some(party_id) = data.party_id else {
            return;
        };

        let node_addr = data.node.to_string();
        info!(
            "CommitteeMemberExpelled received (enriched): node={}, party_id={}, e3_id={}, active_count_after={}",
            node_addr, party_id, data.e3_id, data.active_count_after
        );

        self.handle_party_excluded(party_id, ec);
    }

    pub(in crate::actors::threshold_keyshare) fn handle_committee_member_excluded(
        &mut self,
        data: CommitteeMemberExcluded,
        ec: EventContext<Sequenced>,
    ) {
        let Some(party_id) = data.party_id else {
            return;
        };

        info!(
            node = %data.node,
            party_id,
            e3_id = %data.e3_id,
            proof_type = %data.proof_type,
            "Stopping current E3 work with a quorum-confirmed faulty member"
        );

        self.handle_party_excluded(party_id, ec);
    }

    fn handle_party_excluded(&mut self, party_id: u64, ec: EventContext<Sequenced>) {
        // Record permanently so late-arriving data is rejected even if
        // collectors haven't been created or have already completed.
        // Also clean honest_parties set for the expelled party.
        let _ = self.state.try_mutate(&ec, |mut s| {
            s.expelled_parties.insert(party_id);
            if let Some(ref mut honest) = s.honest_parties {
                honest.remove(&party_id);
            }
            Ok(s)
        });

        // Clean transient coordination state for the expelled party
        self.pending.shares.retain(|s| s.party_id != party_id);

        if let Some(ref mut pending_c4) = self.pending.c4_verification_shares {
            pending_c4.remove(&party_id);
        }

        if let Some(ref collector) = self.encryption_key_collector {
            collector.do_send(ExpelPartyFromKeyCollection {
                party_id,
                ec: ec.clone(),
            });
        }

        if let Some(ref collector) = self.decryption_key_collector {
            collector.do_send(ExpelPartyFromShareCollection {
                party_id,
                ec: ec.clone(),
            });
        }

        if let Some(ref collector) = self.decryption_key_shared_collector {
            collector.do_send(ExpelPartyFromDecryptionKeySharedCollection { party_id, ec });
        }
    }

    pub fn handle_threshold_share_created(
        &mut self,
        msg: TypedEvent<ThresholdShareCreated>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        // CKKS branch: the machine consumes EVERY member's broadcast (the
        // dealt rows are per-recipient encrypted, so no target filter).
        if state.scheme == crate::E3Scheme::Ckks {
            // Record BEFORE processing: restart replay feeds these back.
            self.record_threshold_share(&msg)?;
            let (msg, ec) = msg.into_components();
            if state.expelled_parties.contains(&msg.share.party_id) {
                info!(
                    "Dropping CKKS ThresholdShareCreated from expelled party {}",
                    msg.share.party_id
                );
                return Ok(());
            }
            return self.ckks_handle_threshold_share(msg.share, ec);
        }
        if !matches!(
            state.state,
            KeyshareState::CollectingEncryptionKeys(_)
                | KeyshareState::GeneratingThresholdShare(_)
                | KeyshareState::AggregatingDecryptionKey(_)
        ) {
            trace!(
                e3_id = %state.e3_id,
                state = state.variant_name(),
                sender_party_id = msg.share.party_id,
                "Ignoring ThresholdShareCreated outside share collection"
            );
            return Ok(());
        }

        let my_party_id = state.party_id;

        // Filter: only process shares intended for this party
        if msg.target_party_id != my_party_id {
            return Ok(());
        }

        // Reject shares from expelled parties
        if state.expelled_parties.contains(&msg.share.party_id) {
            info!(
                "Dropping ThresholdShareCreated from expelled party {} for us (party {})",
                msg.share.party_id, my_party_id
            );
            return Ok(());
        }
        self.record_threshold_share(&msg)?;

        info!(
            "Received ThresholdShareCreated from party {} for us (party {}), forwarding to collector!",
            msg.share.party_id, my_party_id
        );
        let collector = self.ensure_collector(self_addr)?;
        info!("got collector address!");
        collector.do_send(msg);
        Ok(())
    }

    pub fn handle_encryption_key_created(
        &mut self,
        msg: TypedEvent<EncryptionKeyCreated>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        // CKKS branch: feed the machine directly (no collector actor —
        // the machine does its own counting and idempotency).
        if state.scheme == crate::E3Scheme::Ckks {
            // Record BEFORE processing: restart replay feeds these back.
            self.record_encryption_key(&msg)?;
            let (msg, ec) = msg.into_components();
            if state.expelled_parties.contains(&msg.key.party_id) {
                info!(
                    "Dropping CKKS EncryptionKeyCreated from expelled party {}",
                    msg.key.party_id
                );
                return Ok(());
            }
            return self.ckks_handle_encryption_key(&msg.key, ec);
        }
        if !matches!(
            state.state,
            KeyshareState::Init | KeyshareState::CollectingEncryptionKeys(_)
        ) {
            trace!(
                e3_id = %state.e3_id,
                state = state.variant_name(),
                sender_party_id = msg.key.party_id,
                "Ignoring EncryptionKeyCreated outside key collection"
            );
            return Ok(());
        }

        // Reject keys from expelled parties
        if state.expelled_parties.contains(&msg.key.party_id) {
            info!(
                "Dropping EncryptionKeyCreated from expelled party {}",
                msg.key.party_id
            );
            return Ok(());
        }
        self.record_encryption_key(&msg)?;
        info!("Received EncryptionKeyCreated forwarding to encryption key collector!");
        let collector = self.ensure_encryption_key_collector(self_addr)?;
        collector.do_send(msg);
        Ok(())
    }
}
