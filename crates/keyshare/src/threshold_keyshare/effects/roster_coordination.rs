// SPDX-License-Identifier: LGPL-3.0-only

//! DKG roster coordination: ready reports, epoch proposals, and C4 per roster.
//!
//! After C2/C3 verification this member publishes a signed `DkgReady` with the senders it
//! holds. The epoch leader collects reports and publishes a signed `DkgRosterProposed`
//! with exactly `H` mutually complete members. Members of the roster compute C4 over it.
//! A member outside the roster keeps its bundles and idles. When an epoch does not
//! complete, the next leader proposes the next epoch without the missing members.

use super::*;
use crate::actors::threshold_keyshare::handlers::{RosterEpochWatchdog, RosterProposalWatchdog};
use crate::domain::roster::{can_serve_roster, leader_for_epoch, record_ready, select_roster};
use e3_events::{DkgReady, DkgRosterProposed};
use std::time::Duration;

impl ThresholdKeyshare {
    fn mutate_state<F>(&mut self, ec: Option<&EventContext<Sequenced>>, f: F) -> Result<()>
    where
        F: FnOnce(ThresholdKeyshareState) -> Result<ThresholdKeyshareState>,
    {
        match ec {
            Some(ec) => self.state.try_mutate(ec, f),
            None => self.state.try_mutate_without_context(f),
        }
    }

    fn publish_event(
        &self,
        data: impl Into<InterfoldEventData>,
        ec: Option<&EventContext<Sequenced>>,
    ) -> Result<()> {
        match ec {
            Some(ec) => self.bus.publish(data, ec.clone()),
            None => self.bus.publish_without_context(data),
        }
    }

    /// True while a new roster epoch can still be served from the retained material.
    fn can_rotate_roster(state: &ThresholdKeyshareState) -> bool {
        match &state.state {
            KeyshareState::AggregatingDecryptionKey(_) => true,
            KeyshareState::ReadyForDecryption(_) => {
                state.aggregating.is_some() && state.aggregated_pk.is_none()
            }
            _ => false,
        }
    }

    /// Committee members that may lead or serve: every party id below `N` that is not
    /// expelled, ascending.
    fn eligible_parties(state: &ThresholdKeyshareState) -> Vec<u64> {
        (0..state.threshold_n)
            .filter(|id| !state.expelled_parties.contains(id))
            .collect()
    }

    /// Record the C2/C3-verified senders and publish this member's signed `DkgReady`.
    /// Then try to propose or serve.
    pub(in crate::actors::threshold_keyshare) fn publish_dkg_ready(
        &mut self,
        held: BTreeSet<u64>,
        ec: Option<EventContext<Sequenced>>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let e3_id = state.e3_id.clone();
        let party_id = state.party_id;

        let report = DkgReady::sign(e3_id.clone(), party_id, held.iter().copied(), &self.signer)?;
        self.mutate_state(ec.as_ref(), |mut s| {
            let roster = s.roster.get_or_insert_with(Default::default);
            roster.held = held.clone();
            record_ready(&mut roster.ready, &report);
            Ok(s)
        })?;

        info!(
            e3_id = %e3_id,
            party_id,
            held = ?held,
            "Publishing DkgReady after C2/C3 verification"
        );
        self.publish_event(report, ec.as_ref())?;
        self.try_advance_roster(ec)
    }

    /// Accept a peer's signed `DkgReady`.
    pub(in crate::actors::threshold_keyshare) fn handle_dkg_ready(
        &mut self,
        report: DkgReady,
        ec: Option<EventContext<Sequenced>>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if report.party_id >= state.threshold_n || report.party_id == state.party_id {
            return Ok(());
        }
        if state.expelled_parties.contains(&report.party_id) {
            return Ok(());
        }
        if !report.verify_signature() {
            warn!(
                e3_id = %report.e3_id,
                party_id = report.party_id,
                "Dropping DkgReady with an invalid signature"
            );
            return Ok(());
        }
        if !self.party_owns_address(&state, report.party_id, report.node) {
            warn!(
                e3_id = %report.e3_id,
                party_id = report.party_id,
                node = %report.node,
                "Dropping DkgReady: signer does not own the party slot"
            );
            return Ok(());
        }
        self.mutate_state(ec.as_ref(), |mut s| {
            let roster = s.roster.get_or_insert_with(Default::default);
            if roster.unresponsive.contains(&report.party_id) {
                return Ok(s);
            }
            record_ready(&mut roster.ready, &report);
            Ok(s)
        })?;
        self.try_advance_roster(ec)
    }

    /// Accept a signed `DkgRosterProposed` from the epoch leader.
    pub(in crate::actors::threshold_keyshare) fn handle_dkg_roster_proposed(
        &mut self,
        proposal: DkgRosterProposed,
        ec: Option<EventContext<Sequenced>>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let committee = state.committee()?;
        if !proposal.roster_is_well_formed(committee.n, committee.h) {
            warn!(e3_id = %proposal.e3_id, epoch = proposal.epoch, "Dropping malformed DkgRosterProposed");
            return Ok(());
        }
        if !proposal.verify_signature() {
            warn!(e3_id = %proposal.e3_id, epoch = proposal.epoch, "Dropping DkgRosterProposed with an invalid signature");
            return Ok(());
        }
        let eligible = Self::eligible_parties(&state);
        if leader_for_epoch(&eligible, proposal.epoch) != Some(proposal.proposer_party_id) {
            warn!(
                e3_id = %proposal.e3_id,
                epoch = proposal.epoch,
                proposer = proposal.proposer_party_id,
                "Dropping DkgRosterProposed from a party that does not lead this epoch"
            );
            return Ok(());
        }
        if !self.party_owns_address(&state, proposal.proposer_party_id, proposal.proposer) {
            warn!(e3_id = %proposal.e3_id, epoch = proposal.epoch, "Dropping DkgRosterProposed: signer does not own the leader slot");
            return Ok(());
        }
        if proposal
            .roster
            .iter()
            .any(|id| state.expelled_parties.contains(id))
        {
            warn!(e3_id = %proposal.e3_id, epoch = proposal.epoch, "Dropping DkgRosterProposed that includes an expelled party");
            return Ok(());
        }
        let current_epoch = state.roster.as_ref().and_then(|r| r.epoch);
        if current_epoch.is_some_and(|current| proposal.epoch <= current) {
            trace!(e3_id = %proposal.e3_id, epoch = proposal.epoch, "Ignoring DkgRosterProposed for a past epoch");
            return Ok(());
        }
        // A higher epoch from its rightful leader is accepted even while this member still
        // considers the current epoch live: the leader proposes only after it observed a
        // miss, and an idle member may not have observed it. Safety does not depend on
        // this (the fold fails closed on mixed rosters). A proposal for an epoch this
        // member already skipped is stale.
        if let Some(r) = state.roster.as_ref() {
            if r.skipped_epochs.contains(&proposal.epoch) {
                trace!(e3_id = %proposal.e3_id, epoch = proposal.epoch, "Ignoring DkgRosterProposed for a skipped epoch");
                return Ok(());
            }
            if let Some(dead) = proposal
                .roster
                .iter()
                .find(|id| r.unresponsive.contains(id))
            {
                // The leader has not yet learned this party is unresponsive. Serve anyway:
                // refusing would let the serving members mark THIS member unresponsive.
                // The epoch misses on the silent party and the next leader excludes it.
                warn!(
                    e3_id = %proposal.e3_id,
                    epoch = proposal.epoch,
                    party_id = dead,
                    "DkgRosterProposed includes a party this member saw go silent; serving anyway"
                );
            }
        }
        self.accept_roster(proposal.epoch, proposal.roster, ec, self_addr)
    }

    /// Propose the next epoch when this member leads it and a roster exists.
    fn try_advance_roster(&mut self, ec: Option<EventContext<Sequenced>>) -> Result<()> {
        let state = self.state.try_get()?;
        let Some(roster_state) = state.roster.clone() else {
            return Ok(());
        };
        // Rotation is possible while this member still holds the aggregating material:
        // before its first C4 (`AggregatingDecryptionKey`) and after a served epoch missed
        // (`ReadyForDecryption` with `aggregating` kept). Once the public key is published
        // the roster is final.
        if roster_state.serving || !Self::can_rotate_roster(&state) {
            return Ok(());
        }
        // One proposal per epoch, and only after the current epoch missed. A member that
        // becomes ready late must not replace a live epoch with its own roster.
        if !roster_state.awaiting_proposal() {
            return Ok(());
        }
        let eligible = Self::eligible_parties(&state);
        let epoch = roster_state.next_epoch();
        if leader_for_epoch(&eligible, epoch) != Some(state.party_id) {
            // Another member leads this epoch. Wait for its proposal, but only for the
            // proposal budget: a silent leader must not stall the round.
            self.arm_proposal_watchdog(epoch)?;
            return Ok(());
        }
        let mut excluded: BTreeSet<u64> = state.expelled_parties.iter().copied().collect();
        excluded.extend(roster_state.unresponsive.iter().copied());
        let h = state.committee()?.h;
        let Some(roster) = select_roster(&roster_state.ready, &excluded, h) else {
            trace!(
                e3_id = %state.e3_id,
                epoch,
                reports = roster_state.ready.len(),
                "Leading the next DKG roster epoch but no mutually complete roster exists yet"
            );
            return Ok(());
        };
        let proposal = DkgRosterProposed::sign(
            state.e3_id.clone(),
            epoch,
            roster.clone(),
            state.party_id,
            &self.signer,
        )?;
        info!(
            e3_id = %state.e3_id,
            epoch,
            roster = ?roster,
            "DkgRosterProposed"
        );
        self.publish_event(proposal, ec.as_ref())?;
        // The leader accepts its own proposal on the same path as a peer.
        let self_addr = self
            .self_addr
            .clone()
            .ok_or_else(|| anyhow!("keyshare actor address is not set"))?;
        self.accept_roster(epoch, roster, ec, self_addr)
    }

    /// Record the accepted epoch. Serve it when this member is in the roster and holds every
    /// other member's bundle; otherwise idle and wait for the next epoch.
    fn accept_roster(
        &mut self,
        epoch: u32,
        roster: Vec<u64>,
        ec: Option<EventContext<Sequenced>>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let party_id = state.party_id;
        let held = state
            .roster
            .as_ref()
            .map(|r| r.held.clone())
            .unwrap_or_default();
        let roster_hash = DkgRosterProposed::roster_hash(&roster);
        let serve = can_serve_roster(party_id, &held, &roster);

        self.mutate_state(ec.as_ref(), |mut s| {
            let r = s.roster.get_or_insert_with(Default::default);
            r.epoch = Some(epoch);
            r.roster = roster.clone();
            r.roster_hash = roster_hash;
            r.serving = serve;
            r.epoch_missed = false;
            // The roster is the honest set for every later phase of this epoch.
            s.honest_parties = Some(roster.iter().copied().collect());
            Ok(s)
        })?;

        // A previous epoch's collector expects the old roster; replace it.
        self.decryption_key_shared_collector = None;
        self.pending.c4_verification_shares = None;
        self.roster_watchdog_epoch = None;

        if !serve {
            if roster.contains(&party_id) {
                warn!(
                    e3_id = %state.e3_id,
                    epoch,
                    roster = ?roster,
                    held = ?held,
                    "In the DKG roster but missing a member's bundle; cannot serve this epoch"
                );
            } else {
                info!(
                    e3_id = %state.e3_id,
                    epoch,
                    roster = ?roster,
                    "Outside the DKG roster for this epoch; idling"
                );
            }
            // An idle member has no C4 collector to tell it the epoch missed. Watch the
            // epoch budget so it can lead or wait for the next epoch.
            self.arm_epoch_watchdog(epoch)?;
            return Ok(());
        }

        info!(
            e3_id = %state.e3_id,
            epoch,
            roster = ?roster,
            "Serving the DKG roster: computing the decryption key share over it"
        );
        let roster_set: BTreeSet<u64> = roster.iter().copied().collect();
        self.proceed_with_decryption_key_calculation(roster_set, roster_hash, ec, self_addr)
    }

    /// Deliver `msg` to this actor after `delay` with an acknowledged send. The actor
    /// being gone by then is the only failure, and then nothing is left to notify.
    fn fire_after<M>(self_addr: Addr<Self>, delay: Duration, msg: M)
    where
        M: actix::Message<Result = ()> + Send + 'static,
        Self: Handler<M>,
    {
        actix::spawn(async move {
            actix::clock::sleep(delay).await;
            if let Err(err) = self_addr.send(msg).await {
                warn!("roster watchdog could not reach the keyshare actor: {err}");
            }
        });
    }

    /// Arm the proposal watchdog for `epoch` unless it is already armed for it. When it
    /// fires and no proposal for `epoch` has been accepted, the epoch is skipped and the
    /// next leader is considered.
    fn arm_proposal_watchdog(&mut self, epoch: u32) -> Result<()> {
        if self.roster_watchdog_epoch == Some(epoch) {
            return Ok(());
        }
        let state = self.state.try_get()?;
        let budget = crate::domain::timeout_policy::resolve_roster_proposal_timeout(
            state.dkg_deadline_unix_secs,
            state.dkg_window_secs,
        )?;
        let self_addr = self
            .self_addr
            .clone()
            .ok_or_else(|| anyhow!("keyshare actor address is not set"))?;
        info!(
            e3_id = %state.e3_id,
            epoch,
            budget = ?budget,
            "Waiting for the DKG roster proposal of this epoch"
        );
        self.roster_watchdog_epoch = Some(epoch);
        Self::fire_after(self_addr, budget, RosterProposalWatchdog { epoch });
        Ok(())
    }

    /// Arm the epoch watchdog for an idle member: when the roster-epoch budget elapses and
    /// `epoch` is still the accepted, live epoch, mark it missed. The missing parties are
    /// unknown to an idle member, so no ready set is changed.
    fn arm_epoch_watchdog(&mut self, epoch: u32) -> Result<()> {
        let state = self.state.try_get()?;
        let budget = crate::domain::timeout_policy::resolve_roster_epoch_timeout(
            state.dkg_deadline_unix_secs,
            state.dkg_window_secs,
        )?;
        let self_addr = self
            .self_addr
            .clone()
            .ok_or_else(|| anyhow!("keyshare actor address is not set"))?;
        Self::fire_after(self_addr, budget, RosterEpochWatchdog { epoch });
        Ok(())
    }

    /// The roster-epoch budget for `epoch` elapsed on an idle member.
    pub(in crate::actors::threshold_keyshare) fn handle_roster_epoch_watchdog(
        &mut self,
        epoch: u32,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let Some(roster_state) = state.roster.clone() else {
            return Ok(());
        };
        if roster_state.epoch != Some(epoch) || roster_state.epoch_missed || roster_state.serving {
            return Ok(());
        }
        if !Self::can_rotate_roster(&state) {
            return Ok(());
        }
        // Roster members whose C4 share for this roster never reached this member are the
        // ones that missed. Their shares are gossiped, so an idle member sees them too.
        let seen: BTreeSet<u64> = self
            .pending
            .c4_verification_shares
            .as_ref()
            .map(|shares| {
                shares
                    .iter()
                    .filter(|(_, share)| share.roster_hash == roster_state.roster_hash)
                    .map(|(pid, _)| *pid)
                    .collect()
            })
            .unwrap_or_default();
        let missing: Vec<u64> = roster_state
            .roster
            .iter()
            .copied()
            .filter(|pid| *pid != state.party_id && !seen.contains(pid))
            .collect();
        warn!(
            e3_id = %state.e3_id,
            epoch,
            missing_parties = ?missing,
            "DKG roster epoch budget elapsed while idling; treating the epoch as missed"
        );
        let ec = self.recovery.get().and_then(|r| r.last_ec);
        self.handle_roster_epoch_timeout(&missing, ec)
    }

    /// The proposal budget for `epoch` elapsed. Skip the epoch when no proposal for it was
    /// accepted, then try to lead or wait for the next one.
    pub(in crate::actors::threshold_keyshare) fn handle_roster_proposal_watchdog(
        &mut self,
        epoch: u32,
    ) -> Result<()> {
        if self.roster_watchdog_epoch != Some(epoch) {
            return Ok(());
        }
        self.roster_watchdog_epoch = None;
        let state = self.state.try_get()?;
        let Some(roster_state) = state.roster.clone() else {
            return Ok(());
        };
        if !roster_state.awaiting_proposal() || roster_state.next_epoch() != epoch {
            // A proposal arrived in time.
            return Ok(());
        }
        if crate::domain::timeout_policy::now_unix_secs()
            >= state.dkg_deadline_unix_secs.unwrap_or(0)
        {
            // The deadline handling of the C4 collector or the E3 timeout owns failure.
            return Ok(());
        }
        warn!(
            e3_id = %state.e3_id,
            epoch,
            "No DKG roster proposal arrived for this epoch; skipping its leader"
        );
        let eligible = Self::eligible_parties(&state);
        let silent_leader = leader_for_epoch(&eligible, epoch);
        let ec = self.recovery.get().and_then(|r| r.last_ec);
        self.mutate_state(ec.as_ref(), |mut s| {
            if let Some(r) = s.roster.as_mut() {
                r.skipped_epochs.insert(epoch);
                // A leader that has reported ready but does not propose is unresponsive.
                if let Some(leader) = silent_leader {
                    if r.ready.contains_key(&leader) {
                        r.unresponsive.insert(leader);
                        r.ready.remove(&leader);
                        for set in r.ready.values_mut() {
                            set.remove(&leader);
                        }
                    }
                }
            }
            Ok(s)
        })?;
        self.try_advance_roster(ec)
    }

    /// After a restart in `ReadyForDecryption` whose epoch had already missed, continue the
    /// rotation: lead the next epoch or wait for its leader.
    pub(in crate::actors::threshold_keyshare) fn resume_roster_rotation(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        self.try_advance_roster(Some(ec))
    }

    /// After a restart in `AggregatingDecryptionKey`, serve the persisted epoch again. The
    /// roster and this member's held set are durable; the compute job is not.
    pub(in crate::actors::threshold_keyshare) fn resume_accepted_roster(
        &mut self,
        ec: EventContext<Sequenced>,
        self_addr: Addr<Self>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let Some(roster_state) = state.roster.clone() else {
            return Ok(());
        };
        let Some(epoch) = roster_state.epoch else {
            return Ok(());
        };
        if !matches!(state.state, KeyshareState::AggregatingDecryptionKey(_)) {
            return Ok(());
        }
        if roster_state.epoch_missed {
            // The persisted epoch already missed; look for the next one instead.
            return self.try_advance_roster(Some(ec));
        }
        info!(
            e3_id = %state.e3_id,
            epoch,
            roster = ?roster_state.roster,
            "Resuming the accepted DKG roster epoch after restart"
        );
        self.accept_roster(epoch, roster_state.roster, Some(ec), self_addr)
    }

    /// The C4 collector for the current epoch timed out. Propose the next epoch when this
    /// member leads it; otherwise wait for the next leader.
    pub(in crate::actors::threshold_keyshare) fn handle_roster_epoch_timeout(
        &mut self,
        missing_parties: &[u64],
        ec: Option<EventContext<Sequenced>>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let Some(roster_state) = state.roster.clone() else {
            return Ok(());
        };
        warn!(
            e3_id = %state.e3_id,
            epoch = ?roster_state.epoch,
            missing_parties = ?missing_parties,
            "DKG roster epoch did not complete"
        );
        // Members that did not deliver C4 for this epoch are removed from every ready set so
        // the next roster cannot include them.
        self.mutate_state(ec.as_ref(), |mut s| {
            if let Some(r) = s.roster.as_mut() {
                r.serving = false;
                r.epoch_missed = true;
                for missing in missing_parties {
                    r.unresponsive.insert(*missing);
                    r.ready.remove(missing);
                    for set in r.ready.values_mut() {
                        set.remove(missing);
                    }
                }
            }
            Ok(s)
        })?;
        self.try_advance_roster(ec)
    }

    /// True when `address` is the registered address of `party_id` in the finalized
    /// committee. The committee list is in party-id order.
    fn party_owns_address(
        &self,
        state: &ThresholdKeyshareState,
        party_id: u64,
        address: Address,
    ) -> bool {
        let Some(committee) = Self::committee_from_state(state) else {
            // Without the committee list the signature check is the only defense; accept.
            return true;
        };
        committee
            .get(party_id as usize)
            .and_then(|node| node.parse::<Address>().ok())
            .is_some_and(|expected| expected == address)
    }

    fn committee_from_state(state: &ThresholdKeyshareState) -> Option<Vec<String>> {
        match &state.state {
            KeyshareState::CollectingEncryptionKeys(d) => {
                Some(d.ciphernode_selected.committee.clone())
            }
            KeyshareState::GeneratingThresholdShare(d) => {
                d.ciphernode_selected.as_ref().map(|s| s.committee.clone())
            }
            _ => state.committee.clone(),
        }
    }
}
