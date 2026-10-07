// SPDX-License-Identifier: LGPL-3.0-only

//! Collector lifecycle, expulsion, and early artifact routing.

use super::*;

impl ThresholdKeyshare {
    /// Resolve a dealer only from this E3's finalized committee.
    pub(super) fn dkg_dealer_address(
        &self,
        e3_id: &E3id,
        party_id: u64,
    ) -> Result<Option<alloy::primitives::Address>> {
        if *e3_id != self.state.try_get()?.e3_id {
            return Ok(None);
        }
        let recovery = self.recovery.try_get()?;
        Ok(recovery.ciphernode_selected.as_ref().and_then(|selected| {
            usize::try_from(party_id)
                .ok()
                .and_then(|party| selected.committee.get(party))
                .and_then(|member| member.parse().ok())
        }))
    }

    /// Create or return the threshold-share collector. Seed every new collector with recorded
    /// expulsions, then retained authenticated shares, so its deadline counts the complete set.
    pub fn ensure_collector(
        &mut self,
        self_addr: Addr<Self>,
        ec: &EventContext<Sequenced>,
        now_unix_secs: u64,
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
        let minimum_external = state.committee_h()?.saturating_sub(1);
        let schedule = resolve_threshold_share_schedule(
            state.dkg_deadline_unix_secs,
            state.dkg_window_secs,
            now_unix_secs,
        )?;
        info!(
            e3_id = %e3_id,
            cutoff_delay = ?schedule.cutoff_delay,
            deadline_delay = ?schedule.deadline_delay,
            cutoff_reached = schedule.cutoff_reached,
            "{}",
            schedule.description
        );
        if let Some(addr) = &self.decryption_key_collector {
            return Ok(addr.clone());
        }
        let addr = ThresholdShareCollector::setup(
            self_addr,
            threshold_n,
            own_party_id,
            minimum_external,
            e3_id,
            schedule,
        );
        // Keep the collector reachable before seeding it: a failed send must not leave a running
        // collector with live timers that nothing can address.
        self.decryption_key_collector = Some(addr.clone());
        for &party_id in &state.expelled_parties {
            addr.try_send(ExpelPartyFromShareCollection {
                party_id,
                ec: ec.clone(),
            })?;
        }
        for event in self.recovery_payloads.shares().values() {
            addr.try_send(event.clone())?;
        }
        Ok(addr)
    }

    pub(in crate::actors::threshold_keyshare) fn stop_threshold_share_collector(
        &mut self,
    ) -> Result<()> {
        if let Some(collector) = &self.decryption_key_collector {
            match collector.try_send(Die) {
                Ok(()) | Err(SendError::Closed(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.decryption_key_collector = None;
        Ok(())
    }

    pub fn ensure_encryption_key_collector(
        &mut self,
        self_addr: Addr<Self>,
        ec: &EventContext<Sequenced>,
        now_unix_secs: u64,
    ) -> Result<Addr<EncryptionKeyCollector>> {
        let Some(state) = self.state.get() else {
            bail!("State not found on threshold keyshare. This should not happen.");
        };
        let timeout = resolve_timeout(
            DkgTimeoutPhase::EncryptionKeyCollection,
            state.dkg_deadline_unix_secs,
            state.dkg_window_secs,
            now_unix_secs,
        )?;
        self.encryption_key_collector_with_timeout(self_addr, Some(timeout), ec)
    }

    /// Create or return the encryption-key collector during restart recovery.
    ///
    /// Unlike `ensure_encryption_key_collector`, this also creates the collector after the cutoff.
    /// That collector has no timer: it applies the cutoff when it receives `EncryptionKeysReplayed`
    /// after the recorded keys. A live key after the cutoff must not reach a collector, so only
    /// `resume_in_flight_work` calls this.
    pub(in crate::actors::threshold_keyshare) fn recover_encryption_key_collector(
        &mut self,
        self_addr: Addr<Self>,
        ec: &EventContext<Sequenced>,
    ) -> Result<Addr<EncryptionKeyCollector>> {
        let state = self.state.try_get()?;
        let timeout = resolve_encryption_key_timeout(
            state.dkg_deadline_unix_secs,
            state.dkg_window_secs,
            crate::domain::timeout_policy::now_unix_secs(),
        )?;
        self.encryption_key_collector_with_timeout(self_addr, timeout, ec)
    }

    /// Return the existing encryption-key collector, or create one with `timeout` (`None`: the
    /// cutoff has passed). A new collector learns every recorded expulsion before any key, so it
    /// does not wait for a party that will not send one.
    fn encryption_key_collector_with_timeout(
        &mut self,
        self_addr: Addr<Self>,
        timeout: Option<DerivedTimeout>,
        ec: &EventContext<Sequenced>,
    ) -> Result<Addr<EncryptionKeyCollector>> {
        let state = self.state.try_get()?;
        info!(
            "Setting up encryption key collector for addr: {} and {} nodes",
            state.address, state.threshold_n
        );
        let e3_id = state.e3_id.clone();
        let threshold_n = state.threshold_n;
        let minimum_keys = state.committee_h()?;
        let own_party_id = state.party_id;
        match &timeout {
            Some(timeout) => info!(
                e3_id = %e3_id,
                timeout = ?timeout.duration,
                "{}",
                timeout.description
            ),
            None => info!(
                e3_id = %e3_id,
                "Encryption-key collection cutoff has passed"
            ),
        }
        if let Some(addr) = &self.encryption_key_collector {
            return Ok(addr.clone());
        }
        let addr = EncryptionKeyCollector::setup(
            self_addr,
            threshold_n,
            minimum_keys,
            own_party_id,
            e3_id,
            timeout.map(|timeout| timeout.duration),
        );
        // Keep the collector reachable before seeding it: a failed send must not leave a running
        // collector with live timers that nothing can address.
        self.encryption_key_collector = Some(addr.clone());
        for &party_id in &state.expelled_parties {
            addr.try_send(ExpelPartyFromKeyCollection {
                party_id,
                ec: ec.clone(),
            })?;
        }
        Ok(addr)
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
            state.dkg_deadline_unix_secs,
            state.dkg_window_secs,
            crate::domain::timeout_policy::now_unix_secs(),
        )?;
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
    ) -> Result<()> {
        // Only process enriched events (party_id resolved by Sortition).
        // Raw events from chain (party_id = None) are ignored here;
        // Sortition will re-publish them with party_id set.
        let Some(party_id) = data.party_id else {
            return Ok(());
        };

        let node_addr = data.node.to_string();
        info!(
            "CommitteeMemberExpelled received (enriched): node={}, party_id={}, e3_id={}, active_count_after={}",
            node_addr, party_id, data.e3_id, data.active_count_after
        );

        self.handle_party_excluded(party_id, ec)
    }

    pub(in crate::actors::threshold_keyshare) fn handle_committee_member_excluded(
        &mut self,
        data: CommitteeMemberExcluded,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(party_id) = data.party_id else {
            return Ok(());
        };

        info!(
            node = %data.node,
            party_id,
            e3_id = %data.e3_id,
            proof_type = %data.proof_type,
            "Stopping current E3 work with a quorum-confirmed faulty member"
        );

        self.handle_party_excluded(party_id, ec)
    }

    /// Record the expulsion, then remove the party from the transient state and from every
    /// running collector. A failed write is returned after the collectors are told, so that they
    /// still stop waiting for the party. Then apply the held Ready updates that it explains.
    fn handle_party_excluded(&mut self, party_id: u64, ec: EventContext<Sequenced>) -> Result<()> {
        // Record permanently so late-arriving data is rejected even if
        // collectors haven't been created or have already completed.
        // Also clean honest_parties set for the expelled party.
        let recorded = self.state.try_mutate(&ec, |mut s| {
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
            collector.do_send(ExpelPartyFromDecryptionKeySharedCollection {
                party_id,
                ec: ec.clone(),
            });
        }
        recorded?;
        // The expulsion can explain a dealer that a held Ready update lacks.
        self.apply_held_ready_updates(ec)
    }

    pub fn handle_threshold_share_created(
        &mut self,
        msg: TypedEvent<ThresholdShareCreated>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
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
        let expected = self.dkg_dealer_address(&msg.e3_id, msg.share.party_id)?;
        if expected.is_none() || msg.recover_address().ok() != expected {
            warn!(
                party_id = msg.share.party_id,
                e3_id = %msg.e3_id,
                "Dropping threshold share without its dealer's signature"
            );
            return Ok(());
        }
        self.record_threshold_share(&msg)?;
        // One clock reading decides both whether the share is late and the collector's timing.
        let now = crate::domain::timeout_policy::now_unix_secs();
        // A share after the canonical DKG deadline stays recorded, but it reaches no collector.
        if past_dkg_deadline(state.dkg_deadline_unix_secs, now)? {
            debug!(
                e3_id = %state.e3_id,
                sender_party_id = msg.share.party_id,
                "Ignoring ThresholdShareCreated after the canonical DKG deadline"
            );
            return Ok(());
        }

        info!(
            "Received ThresholdShareCreated from party {} for us (party {}), forwarding to collector!",
            msg.share.party_id, my_party_id
        );
        let collector = self.ensure_collector(self_addr, msg.get_ctx(), now)?;
        info!("got collector address!");
        let ec = msg.get_ctx().clone();
        collector.do_send(msg);
        self.dispatch_expanded_threshold_share_batch(ec)
    }

    pub fn handle_encryption_key_created(
        &mut self,
        msg: TypedEvent<EncryptionKeyCreated>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
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
        // In `Init`, the collector can be missing: it needs the frozen DKG timing that this node
        // reads when it handles its own selection. `handle_ciphernode_selected` sends every
        // recorded key to the collector.
        if matches!(state.state, KeyshareState::Init) {
            info!(
                e3_id = %state.e3_id,
                sender_party_id = msg.key.party_id,
                "Recorded EncryptionKeyCreated before this node's selection"
            );
            return Ok(());
        }
        // One clock reading decides both whether the key is late and the collector's timing.
        let now = crate::domain::timeout_policy::now_unix_secs();
        // A live key after the cutoff stays recorded, but it reaches no collector, even if the
        // collector's relative timer has not fired yet.
        if past_phase_cutoff(
            DkgTimeoutPhase::EncryptionKeyCollection,
            state.dkg_deadline_unix_secs,
            state.dkg_window_secs,
            now,
        )? {
            debug!(
                e3_id = %state.e3_id,
                sender_party_id = msg.key.party_id,
                "Ignoring EncryptionKeyCreated after the encryption-key cutoff"
            );
            return Ok(());
        }
        info!("Received EncryptionKeyCreated forwarding to encryption key collector!");
        let collector = self.ensure_encryption_key_collector(self_addr, msg.get_ctx(), now)?;
        collector.do_send(msg);
        Ok(())
    }
}
