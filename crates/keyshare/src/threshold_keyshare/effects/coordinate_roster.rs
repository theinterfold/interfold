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
        if recovery.dkg_ready.is_some() || recovery.share_verification_complete.is_none() {
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
            let Some(event) = recovery.threshold_shares.get(party_id) else {
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
        let committee_h = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?
        .values()
        .h;
        if dealers.len() < committee_h {
            return Ok(());
        }
        ensure!(
            dealers
                .windows(2)
                .all(|pair| pair[0].party_id < pair[1].party_id),
            "duplicate dealer in DKG readiness"
        );

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
        self.is_aggregator = change.is_aggregator;
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.is_aggregator = change.is_aggregator;
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
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
        let committee_h = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?
        .values()
        .h;
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
                    recovery
                        .ready_by_party
                        .entry(message.party_id)
                        .or_insert(message);
                    recovery.last_ec = Some(ec.clone());
                    Ok(recovery)
                })?;
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
                if let Some(existing) = recovery.dkg_roster {
                    if existing.dealers != message.dealers {
                        return Err(anyhow!("conflicting DKG rosters for the same E3"));
                    }
                    return Ok(());
                }
                self.accept_dkg_roster(message, ec)?;
            }
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
        let committee_h = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?
        .values()
        .h;
        let ready: std::collections::BTreeMap<u64, Vec<DkgDealer>> = recovery
            .ready_by_party
            .iter()
            .filter(|(party_id, _)| !state.expelled_parties.contains(*party_id))
            .map(|(&party_id, message)| (party_id, message.dealers.clone()))
            .collect();
        if select_ready_roster(&ready, committee_h).is_none() {
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
        if recovery.dkg_roster.is_some() {
            return Ok(());
        }
        let committee_h = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?
        .values()
        .h;
        let ready: std::collections::BTreeMap<u64, Vec<DkgDealer>> = recovery
            .ready_by_party
            .iter()
            .filter(|(party_id, _)| !state.expelled_parties.contains(*party_id))
            .map(|(&party_id, message)| (party_id, message.dealers.clone()))
            .collect();
        let Some(dealers) = select_ready_roster(&ready, committee_h) else {
            return Ok(());
        };
        let roster = DkgCoordination::sign(
            state.e3_id,
            self.interfold_address,
            state.party_id,
            DkgCoordinationKind::Roster,
            dealers,
            &self.signer,
        )?;
        info!(
            e3_id = %roster.e3_id,
            proposer = roster.party_id,
            party_ids = ?roster.dealers.iter().map(|dealer| dealer.party_id).collect::<Vec<_>>(),
            "Proposing DKG roster"
        );
        self.roster_proposal_pending = true;
        if let Err(error) = self.bus.publish(roster, ec) {
            self.roster_proposal_pending = false;
            return Err(error);
        }
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
            let own_ready = recovery
                .dkg_ready
                .ok_or_else(|| anyhow!("selected DKG party has no verified readiness"))?;
            ensure!(
                ready_contains_roster(&own_ready, &roster),
                "selected DKG party lacks a roster contribution"
            );
        }
        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.dkg_roster = Some(roster.clone());
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
