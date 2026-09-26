// SPDX-License-Identifier: LGPL-3.0-only

//! Authenticated readiness and active-aggregator DKG roster coordination.

use super::*;
use anyhow::ensure;

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
            if existing.dealers == dealers {
                return self.maybe_start_c4_for_accepted_roster(ec);
            }
            if !dealers_extend(&existing.dealers, &dealers) {
                warn!(
                    e3_id = %state.e3_id,
                    party_id = state.party_id,
                    "Ignoring a non-monotonic DKG Ready update"
                );
                return Ok(());
            }
        }

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
                self.recovery.try_mutate(&ec, |mut recovery| {
                    let replace = recovery
                        .ready_by_party
                        .get(&message.party_id)
                        .is_none_or(|existing| dealers_extend(&existing.dealers, &message.dealers));
                    if replace {
                        recovery.ready_by_party.insert(message.party_id, message);
                    }
                    recovery.last_ec = Some(ec.clone());
                    Ok(recovery)
                })?;
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
                        "Ignoring a DKG roster contradicted by authenticated Ready reports"
                    );
                    return Ok(());
                }
                if recovery.dkg_roster.is_some() {
                    let existing = recovery.dkg_roster.as_ref().expect("checked above");
                    if existing.dealers == message.dealers {
                        return Ok(());
                    }
                    let c4_started = self.pending.share_decryption_data.is_some()
                        || !matches!(state.state, KeyshareState::AggregatingDecryptionKey(_));
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
                    recovery
                        .pending_rosters
                        .entry(message.party_id)
                        .or_insert_with(|| message.clone());
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

    fn maybe_accept_pending_roster(&mut self, ec: EventContext<Sequenced>) -> Result<bool> {
        let Some(active_party_id) = self.active_aggregator_party_id else {
            return Ok(false);
        };
        let recovery = self.recovery.try_get()?;
        let accepted_proposer = recovery.dkg_roster.as_ref().map(|roster| roster.party_id);
        let c4_started = self.pending.share_decryption_data.is_some()
            || !matches!(
                self.state.try_get()?.state,
                KeyshareState::AggregatingDecryptionKey(_)
            );
        if accepted_proposer.is_some() && c4_started {
            return Ok(false);
        }
        let candidate = recovery
            .pending_rosters
            .iter()
            .filter(|(proposer, roster)| {
                **proposer <= active_party_id
                    && accepted_proposer.is_none_or(|accepted| **proposer < accepted)
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
        let ready: std::collections::BTreeMap<u64, Vec<DkgDealer>> = recovery
            .ready_by_party
            .iter()
            .filter(|(party_id, _)| !state.expelled_parties.contains(*party_id))
            .map(|(&party_id, message)| (party_id, message.dealers.clone()))
            .collect();
        let held_roster_is_usable = recovery.pending_rosters.values().any(|roster| {
            roster_is_supported_by_local_state(&recovery, roster)
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
            let ready: std::collections::BTreeMap<u64, Vec<DkgDealer>> = recovery
                .ready_by_party
                .iter()
                .filter(|(party_id, _)| !state.expelled_parties.contains(*party_id))
                .map(|(&party_id, message)| (party_id, message.dealers.clone()))
                .collect();
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
        self.state.try_mutate(&ec, |mut state| {
            state.honest_parties = Some(party_ids.clone());
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

fn ready_contains_roster(ready: &DkgCoordination, roster: &DkgCoordination) -> bool {
    roster
        .dealers
        .iter()
        .all(|dealer| ready.dealers.contains(dealer))
}

fn dealers_extend(existing: &[DkgDealer], candidate: &[DkgDealer]) -> bool {
    candidate.len() > existing.len() && existing.iter().all(|dealer| candidate.contains(dealer))
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
    use super::ready_contains_roster;
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
}
