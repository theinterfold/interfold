// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The H-roster: the dealers whose shares every member sums into its decryption key. The roster
//! aggregator proposes the first H mutually ready dealers, and each member accepts the supported
//! roster of the lowest proposer that is not later than the current aggregator. Acceptance starts
//! C4, which fixes the roster.

use super::{Dealer, Dkg, DkgMessage, Phase};
use crate::{
    failover::Failover,
    node::{Effect, Noted},
    UnixSecs,
};
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The roster aggregator's budget: from when this node can derive or holds a usable roster.
const ROSTER_BUDGET: UnixSecs = 10 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Rosters {
    /// The first supported roster of each proposer; a later one replaces an unusable one.
    proposed: BTreeMap<Address, Vec<Dealer>>,
    accepted: Option<Accepted>,
    failover: Failover,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Accepted {
    proposer: Address,
    dealers: Vec<Dealer>,
}

impl Default for Rosters {
    fn default() -> Self {
        Self {
            proposed: BTreeMap::new(),
            accepted: None,
            failover: Failover::new(ROSTER_BUDGET),
        }
    }
}

impl Dkg {
    pub fn roster(&self) -> Option<&[Dealer]> {
        let accepted = self.rosters.accepted.as_ref()?;
        Some(&accepted.dealers)
    }

    pub(crate) fn roster_members(&self) -> Option<Vec<Address>> {
        let roster = self.roster()?;
        Some(roster.iter().map(|dealer| dealer.member).collect())
    }

    pub(super) fn admits_roster(&self, proposer: Address, dealers: &[Dealer]) -> bool {
        let well_formed = self.rosters.accepted.is_none()
            && self.is_member(proposer)
            && self.is_live(&proposer)
            && dealers.len() == self.h()
            && dealers
                .windows(2)
                .all(|pair| pair[0].member < pair[1].member)
            && dealers
                .iter()
                .all(|dealer| self.is_member(dealer.member) && self.is_live(&dealer.member));
        let held_is_usable = self
            .rosters
            .proposed
            .get(&proposer)
            .is_some_and(|held| self.is_usable(proposer, held));
        well_formed && !held_is_usable
    }

    pub(super) fn receive_roster(&mut self, proposer: Address, dealers: Vec<Dealer>) {
        self.rosters.proposed.insert(proposer, dealers);
    }

    /// Start the aggregator's budget, propose as the aggregator, and accept the best usable
    /// roster. Every DKG input ends here, since any of them can change Ready reports, rosters,
    /// expulsions, or the aggregator. A roster needs this node's Ready report, so nothing happens
    /// before this node has dealt.
    pub(super) fn advance_roster(&mut self, now: UnixSecs) -> Vec<Effect> {
        if !matches!(self.phase, Phase::Dealt(..)) {
            return Vec::new();
        }
        let derivable = self.select_ready_roster();
        let held_usable = self
            .rosters
            .proposed
            .iter()
            .any(|(proposer, roster)| self.is_usable(*proposer, roster));
        if self.rosters.accepted.is_none() && (derivable.is_some() || held_usable) {
            self.rosters
                .failover
                .inputs_ready(now, &self.members, &self.expelled);
        }
        let mut effects = Vec::new();
        let aggregator = self
            .rosters
            .failover
            .aggregator(&self.members, &self.expelled);
        let proposes = aggregator == Some(self.me)
            && self.rosters.accepted.is_none()
            && !self.rosters.proposed.contains_key(&self.me);
        if let (true, Some(dealers)) = (proposes, derivable) {
            self.rosters.proposed.insert(self.me, dealers.clone());
            effects.push(self.gossip(DkgMessage::Roster(dealers)));
        }
        effects.extend(self.accept_best_roster());
        effects
    }

    /// `member` proposes no roster for the others any more; whether this is news.
    pub(super) fn convict_roster_aggregator(&mut self, member: Address) -> bool {
        self.rosters.failover.convict(member)
    }

    pub(super) fn pass_roster_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        if self.rosters.accepted.is_some() {
            return Vec::new();
        }
        self.rosters
            .failover
            .pass_deadlines(now, &self.members, &self.expelled);
        self.advance_roster(now)
    }

    pub(super) fn roster_deadline(&self) -> Option<UnixSecs> {
        match self.rosters.accepted {
            Some(_) => None,
            None => self.rosters.failover.next_deadline(),
        }
    }

    fn accept_best_roster(&mut self) -> Vec<Effect> {
        let aggregator = self
            .rosters
            .failover
            .aggregator(&self.members, &self.expelled);
        let (Some(aggregator), None) = (aggregator, &self.rosters.accepted) else {
            return Vec::new();
        };
        let best = self
            .rosters
            .proposed
            .iter()
            .find(|(proposer, roster)| {
                **proposer <= aggregator && self.is_usable(**proposer, roster)
            })
            .map(|(proposer, roster)| Accepted {
                proposer: *proposer,
                dealers: roster.clone(),
            });
        let Some(best) = best else {
            return Vec::new();
        };
        let noted = self.note(Noted::RosterAccepted {
            proposer: best.proposer,
            dealers: best.dealers.iter().map(|dealer| dealer.member).collect(),
        });
        self.rosters.proposed.clear();
        self.rosters.accepted = Some(best);
        let mut effects = self.start_decryption_key();
        effects.push(noted);
        effects
    }

    /// A roster is usable when no member of it is expelled and it is supported: this node's
    /// Ready report, the proposer's, and every held report of a selected dealer contain it.
    fn is_usable(&self, proposer: Address, roster: &[Dealer]) -> bool {
        let contains = |member: &Address| {
            self.ready
                .get(member)
                .is_some_and(|ready| roster.iter().all(|dealer| ready.contains(dealer)))
        };
        self.is_live(&proposer)
            && roster.iter().all(|dealer| self.is_live(&dealer.member))
            && contains(&self.me)
            && contains(&proposer)
            && roster
                .iter()
                .all(|dealer| !self.ready.contains_key(&dealer.member) || contains(&dealer.member))
    }

    /// The first H live reporters, in committee order, whose reports all name each other's own
    /// contributions. This node leaves out the members it found convicted. It judges a roster it
    /// receives only by chain facts: nodes that count votes at different times must not refuse
    /// each other's rosters and stop the same DKG.
    fn select_ready_roster(&self) -> Option<Vec<Dealer>> {
        let reports: BTreeMap<Address, &[Dealer]> = self
            .ready
            .iter()
            .filter(|(reporter, _)| {
                self.is_live(reporter) && !self.rosters.failover.is_convicted(reporter)
            })
            .map(|(reporter, report)| (*reporter, report.as_slice()))
            .collect();
        let candidates: Vec<Dealer> = reports
            .iter()
            .filter_map(|(reporter, report)| {
                report
                    .iter()
                    .find(|dealer| dealer.member == *reporter)
                    .copied()
            })
            .collect();
        let mut selected = Vec::with_capacity(self.h());
        select(&reports, &candidates, self.h(), &mut selected).then_some(selected)
    }
}

fn select(
    reports: &BTreeMap<Address, &[Dealer]>,
    candidates: &[Dealer],
    h: usize,
    selected: &mut Vec<Dealer>,
) -> bool {
    if selected.len() == h {
        return true;
    }
    for (index, candidate) in candidates.iter().enumerate() {
        if selected.len() + candidates.len() - index < h {
            return false;
        }
        let mutual = selected.iter().all(|dealer| {
            reports[&candidate.member].contains(dealer)
                && reports[&dealer.member].contains(candidate)
        });
        if !mutual {
            continue;
        }
        selected.push(*candidate);
        if select(reports, &candidates[index + 1..], h, selected) {
            return true;
        }
        selected.pop();
    }
    false
}
