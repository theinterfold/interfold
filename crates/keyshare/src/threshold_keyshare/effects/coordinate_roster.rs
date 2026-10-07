// SPDX-License-Identifier: LGPL-3.0-only

//! Authenticated readiness and active-aggregator DKG roster coordination.

use super::*;
use anyhow::ensure;
use std::{
    collections::{BTreeMap, HashSet},
    time::Instant,
};

impl ThresholdKeyshare {
    pub(in crate::actors::threshold_keyshare) fn maybe_publish_dkg_ready(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let KeyshareState::AggregatingDecryptionKey(current) = &state.state else {
            return Ok(());
        };
        let recovery = self.recovery.try_get()?;
        if recovery.share_verification_complete.is_none() {
            return Ok(());
        }
        let (Some(own_c2a), Some(own_c2b), Some(verified)) = (
            current.signed_sk_share_computation_proof.as_ref(),
            current.signed_e_sm_share_computation_proof.as_ref(),
            recovery.verified_dealer_ids.as_ref(),
        ) else {
            return Ok(());
        };

        let selected = recovery
            .ciphernode_selected
            .as_ref()
            .ok_or_else(|| anyhow!("missing finalized committee for DKG readiness"))?;
        let own_address: Address = selected
            .committee
            .get(state.party_id as usize)
            .ok_or_else(|| anyhow!("own DKG party is outside the finalized committee"))?
            .parse()?;
        ensure!(
            own_address == self.signer.address(),
            "DKG signer does not match the finalized committee slot"
        );

        let mut dealers = vec![dealer_identity(
            &state.e3_id,
            state.party_id,
            &current.pk_share,
            own_c2a,
            own_c2b,
        )?];
        for party_id in verified
            .iter()
            .filter(|party_id| !state.expelled_parties.contains(*party_id))
        {
            let Some(event) = self.recovery_payloads.share(*party_id) else {
                return Err(anyhow!("verified DKG share is missing from recovery state"));
            };
            let (Some(c2a), Some(c2b)) = (
                event.signed_c2a_proof.as_ref(),
                event.signed_c2b_proof.as_ref(),
            ) else {
                return Err(anyhow!("verified DKG share has no C2 proof pair"));
            };
            dealers.push(dealer_identity(
                &state.e3_id,
                *party_id,
                &event.share.pk_share,
                c2a,
                c2b,
            )?);
        }
        dealers.sort_unstable_by_key(|dealer| dealer.party_id);
        let committee_h = state.committee_h()?;
        if dealers.len() < committee_h {
            return Ok(());
        }
        ensure!(
            dealers
                .windows(2)
                .all(|pair| pair[0].party_id < pair[1].party_id),
            "duplicate dealer in DKG readiness"
        );

        if let Some(existing) = recovery.dkg_ready.as_ref() {
            match ready_update(&existing.dealers, &dealers, &state.expelled_parties) {
                ReadyUpdate::Extends => {}
                ReadyUpdate::Unchanged => return self.maybe_start_c4_for_accepted_roster(ec),
                ReadyUpdate::DropsLiveDealer { .. } => {
                    warn!(
                        e3_id = %state.e3_id,
                        party_id = state.party_id,
                        "Ignoring a non-monotonic DKG Ready update"
                    );
                    return Ok(());
                }
            }
        }

        let new_party = !recovery.ready_by_party.contains_key(&state.party_id);
        let ready = DkgCoordination::sign(
            state.e3_id.clone(),
            self.interfold_address,
            state.party_id,
            DkgCoordinationKind::Ready,
            dealers,
            &self.signer,
        )?;
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.dkg_ready = Some(ready.clone());
            recovery
                .ready_by_party
                .insert(state.party_id, ready.clone());
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.summarize_ready_set(state.party_id, new_party);
        if self.effects_enabled {
            self.bus.publish(ready, ec.clone())?;
            self.maybe_publish_roster_inputs_ready(ec.clone())?;
            self.propose_dkg_roster(ec.clone())?;
        }
        self.maybe_start_c4_for_accepted_roster(ec)
    }

    pub(in crate::actors::threshold_keyshare) fn handle_aggregator_changed(
        &mut self,
        change: AggregatorChanged,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if change.e3_id != state.e3_id {
            return Ok(());
        }
        ensure!(
            change.is_aggregator
                == change
                    .active_party_id
                    .is_some_and(|party_id| party_id == state.party_id),
            "aggregator role does not match the active party"
        );
        self.active_aggregator_party_id = change.active_party_id;
        self.is_aggregator = change.is_aggregator;
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.active_aggregator_party_id = change.active_party_id;
            recovery.is_aggregator = change.is_aggregator;
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.maybe_accept_pending_roster(ec.clone())?;
        if self.effects_enabled && self.is_aggregator {
            self.maybe_publish_roster_inputs_ready(ec.clone())?;
            self.propose_dkg_roster(ec)?;
        }
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn record_dkg_coordination(
        &mut self,
        message: DkgCoordination,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if message.e3_id != state.e3_id || message.interfold_address != self.interfold_address {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        let committee = &recovery
            .ciphernode_selected
            .as_ref()
            .ok_or_else(|| anyhow!("missing finalized committee for DKG coordination"))?
            .committee;
        let Some(expected) = committee.get(message.party_id as usize) else {
            return Ok(());
        };
        let expected: Address = expected.parse()?;
        let Ok(signer) = message.recover_address() else {
            return Ok(());
        };
        if signer != expected || !message.has_canonical_dealers(committee.len()) {
            return Ok(());
        }
        let committee_h = state.committee_h()?;
        match message.kind {
            DkgCoordinationKind::Ready => {
                if message.dealers.len() < committee_h
                    || state.expelled_parties.contains(&message.party_id)
                    || !message
                        .dealers
                        .iter()
                        .any(|dealer| dealer.party_id == message.party_id)
                {
                    return Ok(());
                }
                let reporter = message.party_id;
                let new_party = !recovery.ready_by_party.contains_key(&reporter);
                let update = recovery.ready_by_party.get(&reporter).map(|existing| {
                    ready_update(&existing.dealers, &message.dealers, &state.expelled_parties)
                });
                let replace = update.is_none_or(|update| update == ReadyUpdate::Extends);
                // A refused update that adds a dealer can become valid once this node sees the
                // expulsion of the dealer that it lacks.
                let hold = update
                    == Some(ReadyUpdate::DropsLiveDealer {
                        adds_live_dealer: true,
                    });
                let held_limit = committee.len();
                self.recovery.try_mutate(&ec, |mut recovery| {
                    if replace {
                        recovery.ready_by_party.insert(message.party_id, message);
                    } else if hold {
                        let held = recovery.held_ready_updates.entry(reporter).or_default();
                        if !held
                            .iter()
                            .any(|candidate| candidate.dealers == message.dealers)
                        {
                            held.push(message);
                            if held.len() > held_limit {
                                held.remove(0);
                            }
                        }
                    }
                    recovery.last_ec = Some(ec.clone());
                    Ok(recovery)
                })?;
                if replace {
                    self.summarize_ready_set(reporter, new_party);
                    self.apply_held_ready_updates(ec.clone())?;
                } else if hold {
                    info!(
                        e3_id = %state.e3_id,
                        reporter,
                        "Holding a DKG Ready update that lacks a dealer of the held report until an expulsion explains it"
                    );
                }
                self.maybe_accept_pending_roster(ec.clone())?;
            }
            DkgCoordinationKind::Roster => {
                if state.expelled_parties.contains(&message.party_id)
                    || message.dealers.len() != committee_h
                    || message
                        .dealers
                        .iter()
                        .any(|dealer| state.expelled_parties.contains(&dealer.party_id))
                {
                    return Ok(());
                }
                // A held Ready report can contradict a roster until this node sees the expulsion
                // that the proposer saw. Keep the roster: acceptance checks the support again.
                if recovery
                    .ready_by_party
                    .get(&message.party_id)
                    .is_some_and(|ready| !ready_contains_roster(ready, &message))
                    || message.dealers.iter().any(|dealer| {
                        recovery
                            .ready_by_party
                            .get(&dealer.party_id)
                            .is_some_and(|ready| !ready_contains_roster(ready, &message))
                    })
                {
                    warn!(
                        e3_id = %message.e3_id,
                        proposer = message.party_id,
                        "Holding a DKG roster that authenticated Ready reports do not support yet"
                    );
                }
                if recovery.dkg_roster.is_some() {
                    let existing = recovery.dkg_roster.as_ref().expect("checked above");
                    if existing.dealers == message.dealers {
                        return Ok(());
                    }
                    let c4_started = self.dkg_roster_is_fixed(&state);
                    if c4_started || message.party_id >= existing.party_id {
                        warn!(
                            e3_id = %message.e3_id,
                            accepted_proposer = existing.party_id,
                            ignored_proposer = message.party_id,
                            c4_started,
                            "Ignoring a conflicting DKG roster that cannot outrank the accepted roster"
                        );
                        return Ok(());
                    }
                }
                self.recovery.try_mutate(&ec, |mut recovery| {
                    // Keep the first supported roster of a proposer. A later roster replaces one
                    // that the local Ready state does not support.
                    // A held roster with an expelled member can never be accepted, also when a
                    // refused write kept it after the expulsion.
                    let replace_held =
                        recovery
                            .pending_rosters
                            .get(&message.party_id)
                            .is_none_or(|held| {
                                !roster_is_supported_by_local_state(&recovery, held)
                                    || !roster_members_are_live(held, &state.expelled_parties)
                            });
                    if replace_held {
                        recovery
                            .pending_rosters
                            .insert(message.party_id, message.clone());
                    }
                    recovery.last_ec = Some(ec.clone());
                    Ok(recovery)
                })?;
                if !self.maybe_accept_pending_roster(ec.clone())? {
                    self.maybe_publish_roster_inputs_ready(ec.clone())?;
                    warn!(
                        e3_id = %message.e3_id,
                        proposer = message.party_id,
                        active_party_id = ?self.active_aggregator_party_id,
                        "Holding a DKG roster until its proposer is eligible and has published a matching Ready report"
                    );
                }
            }
        }
        Ok(())
    }

    /// Logs the authenticated Ready set after a Ready report changed it, as often as the summary
    /// gate allows: `new_party` when the report added a Ready party. Only logging depends on it,
    /// so a missing state skips the line.
    fn summarize_ready_set(&mut self, reporter: u64, new_party: bool) {
        let (Ok(state), Ok(recovery)) = (self.state.try_get(), self.recovery.try_get()) else {
            return;
        };
        let Ok(roster_size) = state.committee_h() else {
            return;
        };
        let ready = eligible_ready_dealers(&recovery, &state);
        let Some(suppressed_updates) = self.ready_summary.admit(Instant::now(), new_party) else {
            return;
        };
        let committee = recovery
            .ciphernode_selected
            .as_ref()
            .map_or(0, |selected| selected.committee.len());
        info!(
            e3_id = %state.e3_id,
            reporter,
            ready = ready.len(),
            committee,
            roster_size,
            ready_parties = ?ready.keys().collect::<Vec<_>>(),
            suppressed_updates,
            "DKG Ready set updated"
        );
    }

    /// Whether this node started C4 from its accepted roster, which fixes the roster. The
    /// persisted flag keeps this across a restart that loses the running calculation.
    fn dkg_roster_is_fixed(&self, state: &ThresholdKeyshareState) -> bool {
        state.dkg_roster_fixed
            || self.pending.share_decryption_data.is_some()
            || !matches!(state.state, KeyshareState::AggregatingDecryptionKey(_))
    }

    fn maybe_accept_pending_roster(&mut self, ec: EventContext<Sequenced>) -> Result<bool> {
        let Some(active_party_id) = self.active_aggregator_party_id else {
            return Ok(false);
        };
        let recovery = self.recovery.try_get()?;
        let expelled = self.state.try_get()?.expelled_parties;
        let accepted_proposer = recovery.dkg_roster.as_ref().map(|roster| roster.party_id);
        let c4_started = self.dkg_roster_is_fixed(&self.state.try_get()?);
        if accepted_proposer.is_some() && c4_started {
            return Ok(false);
        }
        let candidate = recovery
            .pending_rosters
            .iter()
            .filter(|(proposer, roster)| {
                **proposer <= active_party_id
                    && accepted_proposer.is_none_or(|accepted| **proposer < accepted)
                    && roster_members_are_live(roster, &expelled)
                    && roster_is_supported_by_local_state(&recovery, roster)
            })
            .min_by_key(|(proposer, _)| **proposer)
            .map(|(_, roster)| roster.clone());
        let Some(roster) = candidate else {
            return Ok(false);
        };
        self.accept_dkg_roster(roster, ec)?;
        Ok(true)
    }

    /// Apply the held Ready updates that the current expulsions make extensions, drop the ones that
    /// can no longer become one, and drop pending rosters with an expelled member. Run in the DKG
    /// phases after an expulsion, after a direct Ready update, and when effects resume after a
    /// restart.
    pub(in crate::actors::threshold_keyshare) fn apply_held_ready_updates(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        // A later phase has no roster to settle; a saved failure must be redriven unhindered.
        if !matches!(
            state.state,
            KeyshareState::Init
                | KeyshareState::CollectingEncryptionKeys(_)
                | KeyshareState::GeneratingThresholdShare(_)
                | KeyshareState::AggregatingDecryptionKey(_)
        ) {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        let expelled = &state.expelled_parties;
        let mut applied = Vec::new();
        let mut settled = BTreeMap::new();
        for (reporter, held) in &recovery.held_ready_updates {
            if expelled.contains(reporter) {
                settled.insert(*reporter, Vec::new());
                continue;
            }
            let (current, remaining) = settle_held_updates(
                recovery.ready_by_party.get(reporter).cloned(),
                held.clone(),
                expelled,
            );
            if let Some(current) = current {
                applied.push((*reporter, current));
            }
            if remaining.len() != held.len() {
                settled.insert(*reporter, remaining);
            }
        }
        let stale_rosters: Vec<u64> = recovery
            .pending_rosters
            .iter()
            .filter(|(_, roster)| !roster_members_are_live(roster, expelled))
            .map(|(proposer, _)| *proposer)
            .collect();
        if applied.is_empty() && settled.is_empty() && stale_rosters.is_empty() {
            return Ok(());
        }
        self.recovery.try_mutate(&ec, |mut recovery| {
            for (reporter, current) in &applied {
                recovery.ready_by_party.insert(*reporter, current.clone());
            }
            for (reporter, remaining) in &settled {
                if remaining.is_empty() {
                    recovery.held_ready_updates.remove(reporter);
                } else {
                    recovery
                        .held_ready_updates
                        .insert(*reporter, remaining.clone());
                }
            }
            for proposer in &stale_rosters {
                recovery.pending_rosters.remove(proposer);
            }
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        for (reporter, _) in applied {
            info!(
                e3_id = %state.e3_id,
                reporter,
                "Applied a held DKG Ready update after an expulsion"
            );
            self.summarize_ready_set(reporter, false);
        }
        self.maybe_accept_pending_roster(ec.clone())?;
        if self.effects_enabled {
            self.maybe_publish_roster_inputs_ready(ec.clone())?;
            self.propose_dkg_roster(ec)?;
        }
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn maybe_publish_roster_inputs_ready(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if !self.effects_enabled || self.roster_inputs_ready {
            return Ok(());
        }
        let state = self.state.try_get()?;
        if !matches!(state.state, KeyshareState::AggregatingDecryptionKey(_)) {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        if recovery.dkg_roster.is_some() {
            return Ok(());
        }
        let committee_h = state.committee_h()?;
        let ready = eligible_ready_dealers(&recovery, &state);
        let held_roster_is_usable = recovery.pending_rosters.values().any(|roster| {
            roster_members_are_live(roster, &state.expelled_parties)
                && roster_is_supported_by_local_state(&recovery, roster)
                && roster.dealers.len() == committee_h
        });
        if select_ready_roster(&ready, committee_h).is_none() && !held_roster_is_usable {
            return Ok(());
        }

        self.roster_inputs_ready = true;
        if let Err(error) = self.bus.publish(
            AggregationInputsReady {
                e3_id: state.e3_id,
                phase: AggregationPhase::DkgRoster,
            },
            ec,
        ) {
            self.roster_inputs_ready = false;
            return Err(error);
        }
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn propose_dkg_roster(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if !self.effects_enabled
            || !self.is_aggregator
            || self.roster_proposal_pending
            || !matches!(state.state, KeyshareState::AggregatingDecryptionKey(_))
        {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        let committee_h = state.committee_h()?;
        let dealers = if let Some(accepted) = recovery.dkg_roster.as_ref() {
            if accepted.party_id == state.party_id {
                return Ok(());
            }
            accepted.dealers.clone()
        } else {
            let ready = eligible_ready_dealers(&recovery, &state);
            let Some(dealers) = select_ready_roster(&ready, committee_h) else {
                return Ok(());
            };
            dealers
        };
        let roster = DkgCoordination::sign(
            state.e3_id,
            self.interfold_address,
            state.party_id,
            DkgCoordinationKind::Roster,
            dealers,
            &self.signer,
        )?;
        let e3_id = roster.e3_id.clone();
        let proposer = roster.party_id;
        let party_ids = roster
            .dealers
            .iter()
            .map(|dealer| dealer.party_id)
            .collect::<Vec<_>>();
        self.roster_proposal_pending = true;
        if let Err(error) = self.bus.publish(roster, ec) {
            self.roster_proposal_pending = false;
            return Err(error);
        }
        info!(
            %e3_id,
            proposer,
            ?party_ids,
            "Proposed DKG roster"
        );
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn accept_dkg_roster(
        &mut self,
        roster: DkgCoordination,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let party_ids: BTreeSet<u64> = roster
            .dealers
            .iter()
            .map(|dealer| dealer.party_id)
            .collect();
        if party_ids.contains(&state.party_id) {
            let recovery = self.recovery.try_get()?;
            let locally_verified = recovery
                .dkg_ready
                .as_ref()
                .is_some_and(|ready| ready_contains_roster(ready, &roster));
            if !locally_verified {
                warn!(
                    e3_id = %state.e3_id,
                    proposer = roster.party_id,
                    party_id = state.party_id,
                    "Ignoring a DKG roster that does not match this selected party's verified contributions"
                );
                return Ok(());
            }
        }
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.dkg_roster = Some(roster.clone());
            // Keep only proposals that could still outrank this one before C4 starts. A Ready
            // report may arrive after its roster, making that lower-ranked proposal usable.
            recovery
                .pending_rosters
                .retain(|proposer, _| *proposer < roster.party_id);
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        self.roster_proposal_pending = false;
        self.roster_inputs_ready = false;
        // Live, an expulsion takes the dealer out of the honest parties of an accepted roster.
        // Restoring the roster after a restart does the same until C4 starts. A fixed roster is
        // restored in full: the calculation that started from it used every dealer.
        let honest: BTreeSet<u64> = if self.dkg_roster_is_fixed(&state) {
            party_ids.clone()
        } else {
            party_ids
                .iter()
                .copied()
                .filter(|party_id| !state.expelled_parties.contains(party_id))
                .collect()
        };
        self.state.try_mutate(&ec, |mut state| {
            state.honest_parties = Some(honest.clone());
            Ok(state)
        })?;
        info!(
            e3_id = %state.e3_id,
            proposer = roster.party_id,
            party_ids = ?party_ids,
            "Accepted DKG roster"
        );
        self.bus.publish(
            CommitmentRosterSelected {
                e3_id: state.e3_id.clone(),
                party_ids: party_ids.iter().copied().collect(),
            },
            ec.clone(),
        )?;
        self.maybe_start_c4_for_accepted_roster(ec)
    }

    fn maybe_start_c4_for_accepted_roster(&mut self, ec: EventContext<Sequenced>) -> Result<()> {
        let state = self.state.try_get()?;
        if !self.effects_enabled
            || !matches!(state.state, KeyshareState::AggregatingDecryptionKey(_))
            || self.pending.share_decryption_data.is_some()
        {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        let Some(roster) = recovery.dkg_roster else {
            return Ok(());
        };
        let Some(own_ready) = recovery.dkg_ready else {
            return Ok(());
        };
        if !ready_contains_roster(&own_ready, &roster) {
            warn!(
                e3_id = %state.e3_id,
                party_id = state.party_id,
                "This party cannot start C4 because it does not hold every accepted roster contribution"
            );
            return Ok(());
        }
        self.proceed_with_decryption_key_calculation(None, ec)
    }
}

/// Dealer sets of the authenticated Ready reports from parties that are not expelled.
fn eligible_ready_dealers(
    recovery: &ThresholdKeyshareRecoveryState,
    state: &ThresholdKeyshareState,
) -> BTreeMap<u64, Vec<DkgDealer>> {
    recovery
        .ready_by_party
        .iter()
        .filter(|(party_id, _)| !state.expelled_parties.contains(*party_id))
        .map(|(&party_id, message)| (party_id, message.dealers.clone()))
        .collect()
}

fn ready_contains_roster(ready: &DkgCoordination, roster: &DkgCoordination) -> bool {
    roster
        .dealers
        .iter()
        .all(|dealer| ready.dealers.contains(dealer))
}

/// How a new Ready dealer list relates to the one held for the same party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadyUpdate {
    /// Keeps every dealer of the held list that is not expelled and adds at least one more.
    Extends,
    /// Keeps every dealer of the held list that is not expelled and adds none.
    Unchanged,
    /// Lacks a dealer of the held list that is not expelled. Only that dealer's later expulsion
    /// can make the list an extension, and only when it adds a dealer.
    DropsLiveDealer { adds_live_dealer: bool },
}

/// Compare Ready dealer lists. An expelled dealer never returns to a roster, so a list may drop it,
/// and it does not count as growth.
fn ready_update(
    existing: &[DkgDealer],
    candidate: &[DkgDealer],
    expelled: &HashSet<u64>,
) -> ReadyUpdate {
    let live = |dealer: &&DkgDealer| !expelled.contains(&dealer.party_id);
    let adds_live_dealer = candidate
        .iter()
        .filter(live)
        .any(|dealer| !existing.contains(dealer));
    if !existing
        .iter()
        .filter(live)
        .all(|dealer| candidate.contains(dealer))
    {
        return ReadyUpdate::DropsLiveDealer { adds_live_dealer };
    }
    if adds_live_dealer {
        ReadyUpdate::Extends
    } else {
        ReadyUpdate::Unchanged
    }
}

/// Neither the proposer nor a selected dealer of the roster is expelled.
fn roster_members_are_live(roster: &DkgCoordination, expelled: &HashSet<u64>) -> bool {
    !expelled.contains(&roster.party_id)
        && roster
            .dealers
            .iter()
            .all(|dealer| !expelled.contains(&dealer.party_id))
}

/// Apply held updates to a reporter's Ready report while one of them extends it, the one with the
/// most dealers that are not expelled first. Returns the new report when it changed, and the held
/// updates that a later expulsion can still make extensions.
fn settle_held_updates(
    mut current: Option<DkgCoordination>,
    mut held: Vec<DkgCoordination>,
    expelled: &HashSet<u64>,
) -> (Option<DkgCoordination>, Vec<DkgCoordination>) {
    let live_count = |update: &DkgCoordination| {
        update
            .dealers
            .iter()
            .filter(|dealer| !expelled.contains(&dealer.party_id))
            .count()
    };
    let mut changed = false;
    loop {
        let next = held
            .iter()
            .enumerate()
            .filter(|(_, update)| {
                current.as_ref().is_none_or(|current| {
                    ready_update(&current.dealers, &update.dealers, expelled)
                        == ReadyUpdate::Extends
                })
            })
            .max_by_key(|(index, update)| (live_count(update), std::cmp::Reverse(*index)))
            .map(|(index, _)| index);
        let Some(index) = next else {
            break;
        };
        current = Some(held.remove(index));
        changed = true;
    }
    held.retain(|update| {
        current.as_ref().is_some_and(|current| {
            ready_update(&current.dealers, &update.dealers, expelled)
                == ReadyUpdate::DropsLiveDealer {
                    adds_live_dealer: true,
                }
        })
    });
    (changed.then_some(current).flatten(), held)
}

fn roster_is_supported_by_local_state(
    recovery: &ThresholdKeyshareRecoveryState,
    roster: &DkgCoordination,
) -> bool {
    let local_supports = recovery
        .dkg_ready
        .as_ref()
        .is_some_and(|ready| ready_contains_roster(ready, roster));
    let proposer_supports = recovery
        .ready_by_party
        .get(&roster.party_id)
        .is_some_and(|ready| ready_contains_roster(ready, roster));
    local_supports
        && proposer_supports
        && roster.dealers.iter().all(|dealer| {
            recovery
                .ready_by_party
                .get(&dealer.party_id)
                .is_none_or(|ready| ready_contains_roster(ready, roster))
        })
}

#[cfg(test)]
mod coordination_tests {
    use super::{ready_contains_roster, ready_update, settle_held_updates, ReadyUpdate};
    use e3_events::{DkgCoordination, DkgCoordinationKind, DkgDealer, E3id};
    use e3_utils::ArcBytes;

    fn message(party_id: u64, dealers: &[u64]) -> DkgCoordination {
        DkgCoordination {
            e3_id: E3id::new("1", 1),
            interfold_address: Default::default(),
            party_id,
            kind: DkgCoordinationKind::Ready,
            dealers: dealers
                .iter()
                .map(|&id| DkgDealer {
                    party_id: id,
                    contribution_hash: [id as u8; 32],
                })
                .collect(),
            signature: ArcBytes::from_bytes(&[]),
        }
    }

    #[test]
    fn outsider_can_compute_only_with_every_selected_dealer() {
        let roster = message(1, &[1, 2]);
        assert!(ready_contains_roster(&message(0, &[0, 1, 2]), &roster));
        assert!(!ready_contains_roster(&message(0, &[0, 1]), &roster));
    }

    #[test]
    fn a_ready_update_drops_only_expelled_dealers() {
        let d = |ids: &[u64]| message(0, ids).dealers;
        let none = std::collections::HashSet::new();
        let expelled = std::collections::HashSet::from([2]);
        let drops = |adds_live_dealer| ReadyUpdate::DropsLiveDealer { adds_live_dealer };

        assert_eq!(
            ready_update(&d(&[0, 1]), &d(&[0, 1, 2]), &none),
            ReadyUpdate::Extends
        );
        assert_eq!(
            ready_update(&d(&[0, 1, 2]), &d(&[0, 1, 3]), &none),
            drops(true)
        );
        assert_eq!(
            ready_update(&d(&[0, 1, 2]), &d(&[0, 1, 3]), &expelled),
            ReadyUpdate::Extends
        );
        assert_eq!(
            ready_update(&d(&[0, 1, 2]), &d(&[0, 1]), &expelled),
            ReadyUpdate::Unchanged
        );
        // An expelled dealer is not growth.
        assert_eq!(
            ready_update(&d(&[0, 1]), &d(&[0, 1, 2]), &expelled),
            ReadyUpdate::Unchanged
        );
        assert_eq!(ready_update(&d(&[0, 1]), &d(&[0]), &none), drops(false));
    }

    #[test]
    fn successive_held_updates_settle_on_the_latest_list() {
        let d = |ids: &[u64]| message(1, ids);
        let current = d(&[0, 1, 2, 3, 4]);
        let first = d(&[0, 1, 2, 3, 5]);
        let second = d(&[0, 1, 2, 3, 6]);
        let held = vec![first.clone(), second.clone()];

        // Dealer 4 is expelled, then dealer 5.
        let only_four = std::collections::HashSet::from([4]);
        let (applied, remaining) =
            settle_held_updates(Some(current.clone()), held.clone(), &only_four);
        assert_eq!(applied, Some(first.clone()));
        assert_eq!(remaining, vec![second.clone()]);
        let both = std::collections::HashSet::from([4, 5]);
        let (applied, remaining) = settle_held_updates(applied, remaining, &both);
        assert_eq!(applied, Some(second.clone()));
        assert!(remaining.is_empty());

        // Both expulsions arrive before the check, in either order of the held updates.
        for held in [held.clone(), vec![second.clone(), first.clone()]] {
            let (applied, remaining) = settle_held_updates(Some(current.clone()), held, &both);
            assert_eq!(applied, Some(second.clone()));
            assert!(remaining.is_empty());
        }
    }
}
