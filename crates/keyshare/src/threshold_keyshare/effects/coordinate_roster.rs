// SPDX-License-Identifier: LGPL-3.0-only

//! Authenticated readiness and timed-leader DKG roster coordination.

use super::*;
use anyhow::ensure;

const ROSTER_BACKUP_SLOT_BPS: u64 = 200;
const ROSTER_BACKUP_MIN_SECS: u64 = 30;
const ROSTER_BACKUP_MAX_SECS: u64 = 120;

impl ThresholdKeyshare {
    pub(in crate::actors::threshold_keyshare) fn schedule_roster_leadership_check(
        &self,
        ctx: &mut actix::Context<Self>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if state.party_id == 0 {
            return Ok(());
        }
        let (Some(deadline), Some(window)) = (state.dkg_deadline_unix_secs, state.dkg_window_secs)
        else {
            return Ok(());
        };
        let Some((start, end)) = roster_view_bounds(deadline, window, state.party_id) else {
            return Ok(());
        };
        let now = now_unix_secs();
        if now < end {
            ctx.notify_later(
                DkgRosterLeadershipCheck,
                std::time::Duration::from_secs(start.saturating_sub(now)),
            );
        }
        Ok(())
    }

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
        self.bus.publish(ready, ec.clone())?;
        self.maybe_start_c4_for_accepted_roster(ec)
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
            DkgCoordinationKind::Roster { view } => {
                if view != message.party_id
                    || state.expelled_parties.contains(&message.party_id)
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

    pub(in crate::actors::threshold_keyshare) fn propose_dkg_roster(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if !matches!(state.state, KeyshareState::AggregatingDecryptionKey(_)) {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        if recovery.dkg_roster.is_some() || recovery.dkg_ready.is_none() {
            return Ok(());
        }
        let (Some(deadline), Some(window)) = (state.dkg_deadline_unix_secs, state.dkg_window_secs)
        else {
            return Ok(());
        };
        if !roster_view_bounds(deadline, window, state.party_id)
            .is_some_and(|(start, end)| (start..end).contains(&now_unix_secs()))
        {
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
            DkgCoordinationKind::Roster {
                view: state.party_id,
            },
            dealers,
            &self.signer,
        )?;
        info!(
            e3_id = %roster.e3_id,
            proposer = roster.party_id,
            party_ids = ?roster.dealers.iter().map(|dealer| dealer.party_id).collect::<Vec<_>>(),
            "Proposing DKG roster"
        );
        self.accept_dkg_roster(roster.clone(), ec.clone())?;
        self.bus.publish(roster, ec)?;
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
        if !matches!(state.state, KeyshareState::AggregatingDecryptionKey(_))
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

fn roster_view_bounds(deadline: u64, window: u64, party_id: u64) -> Option<(u64, u64)> {
    if deadline == 0 || window == 0 {
        return None;
    }
    let share_cutoff =
        phase_cutoff_unix_secs(deadline, window, DkgTimeoutPhase::ThresholdShareCollection);
    let grace = (window.saturating_mul(ROSTER_BACKUP_SLOT_BPS) / 10_000)
        .clamp(ROSTER_BACKUP_MIN_SECS, ROSTER_BACKUP_MAX_SECS);
    let start = if party_id == 0 {
        deadline.saturating_sub(window)
    } else {
        share_cutoff.saturating_add(grace.saturating_mul(party_id))
    };
    let end = share_cutoff
        .saturating_add(grace.saturating_mul(party_id.saturating_add(1)))
        .min(deadline);
    (start < end).then_some((start, end))
}

#[cfg(test)]
mod leadership_tests {
    use super::{ready_contains_roster, roster_view_bounds};
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
    fn backup_views_follow_the_frozen_share_cutoff() {
        let deadline = 10_000;
        let window = 3_600;
        let primary = roster_view_bounds(deadline, window, 0).unwrap();
        let backup = roster_view_bounds(deadline, window, 1).unwrap();
        let second_backup = roster_view_bounds(deadline, window, 2).unwrap();
        assert_eq!(primary, (6_400, 8_632));
        assert_eq!(backup, (8_632, 8_704));
        assert_eq!(second_backup, (8_704, 8_776));
    }
}
