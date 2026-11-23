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
        let held = self.rosters.proposed.get(&proposer);
        let replaces =
            held.is_none_or(|held| held.as_slice() != dealers && !self.is_usable(proposer, held));
        well_formed && replaces
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
                .is_some_and(|ready| roster.iter().all(|dealer| ready_contains(ready, dealer)))
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
        let h = self.h();
        if h == 0 {
            return Some(Vec::new());
        }
        let mut entries: Vec<(Dealer, &[Dealer])> = self
            .ready
            .iter()
            .filter(|(reporter, _)| {
                self.is_live(reporter) && !self.rosters.failover.is_convicted(reporter)
            })
            .filter_map(|(reporter, report)| {
                let slice = report.as_slice();
                let own = slice
                    .binary_search_by_key(reporter, |d| d.member)
                    .ok()
                    .map(|idx| slice[idx])?;
                Some((own, slice))
            })
            .collect();
        if entries.len() < h {
            return None;
        }
        // `self.ready` is a BTreeMap keyed by Address, so `entries` is strictly ascending by member.
        if entries.len() <= 128 {
            select_bitmask(&entries, h)
        } else {
            let reports: BTreeMap<Address, &[Dealer]> = entries
                .iter()
                .map(|(dealer, report)| (dealer.member, *report))
                .collect();
            let candidates: Vec<Dealer> = entries.drain(..).map(|(dealer, _)| dealer).collect();
            let mut selected = Vec::with_capacity(h);
            select_fallback(&reports, &candidates, h, &mut selected).then_some(selected)
        }
    }
}

/// Ready reports are strictly ascending by `dealer.member`, so membership is O(log N).
fn ready_contains(ready: &[Dealer], dealer: &Dealer) -> bool {
    ready
        .binary_search_by_key(&dealer.member, |d| d.member)
        .is_ok_and(|idx| ready[idx] == *dealer)
}

/// Finds the lexicographically-first H-clique using bitmask adjacency and iterative (H-1)-core
/// pruning. Guarantees the exact same committee-order output as backtracking over sorted slices.
fn select_bitmask(entries: &[(Dealer, &[Dealer])], h: usize) -> Option<Vec<Dealer>> {
    let n = entries.len();
    let mut adj = vec![0u128; n];
    for i in 0..n {
        let (di, ri) = entries[i];
        for j in (i + 1)..n {
            let (dj, rj) = entries[j];
            if ready_contains(ri, &dj) && ready_contains(rj, &di) {
                adj[i] |= 1u128 << j;
                adj[j] |= 1u128 << i;
            }
        }
    }

    let min_deg = (h - 1) as u32;
    let mut active: u128 = if n == 128 {
        u128::MAX
    } else {
        (1u128 << n) - 1
    };
    loop {
        let mut removed = 0u128;
        let mut scan = active;
        while scan != 0 {
            let v = scan.trailing_zeros() as usize;
            scan &= scan - 1;
            if (adj[v] & active).count_ones() < min_deg {
                removed |= 1u128 << v;
            }
        }
        if removed == 0 {
            break;
        }
        active &= !removed;
        if (active.count_ones() as usize) < h {
            return None;
        }
    }

    let mut chosen = Vec::with_capacity(h);
    if search_clique(&adj, active, h, &mut chosen) {
        Some(chosen.into_iter().map(|idx| entries[idx].0).collect())
    } else {
        None
    }
}

fn search_clique(adj: &[u128], mut candidates: u128, h: usize, chosen: &mut Vec<usize>) -> bool {
    let need = h - chosen.len();
    if need == 0 {
        return true;
    }
    while (candidates.count_ones() as usize) >= need {
        let v = candidates.trailing_zeros() as usize;
        candidates &= candidates - 1;
        let next = candidates & adj[v];
        if (next.count_ones() as usize) + 1 < need {
            continue;
        }
        chosen.push(v);
        if search_clique(adj, next, h, chosen) {
            return true;
        }
        chosen.pop();
    }
    false
}

fn select_fallback(
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
            ready_contains(reports[&candidate.member], dealer)
                && ready_contains(reports[&dealer.member], candidate)
        });
        if !mutual {
            continue;
        }
        selected.push(*candidate);
        if select_fallback(reports, &candidates[index + 1..], h, selected) {
            return true;
        }
        selected.pop();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn bitmask_roster_selection_matches_fallback_on_adversarial_graphs() {
        let n = 19usize;
        let h = 14usize;
        let dealers: Vec<Dealer> = (1..=n as u8)
            .map(|i| Dealer {
                member: Address::repeat_byte(i),
                contribution: B256::repeat_byte(i),
            })
            .collect();

        // Near-clique with a planted clique at indices [1, 3, 5..17] and tricky missing edges.
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for trial in 0..64 {
            let mut lists: Vec<Vec<Dealer>> = vec![Vec::new(); n];
            let plant = trial % 2 == 0;
            for (i, list) in lists.iter_mut().enumerate() {
                list.push(dealers[i]);
                for (j, &dealer) in dealers.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    let edge =
                        (plant && i >= 2 && j >= 2 && i < 16 && j < 16) || (next_u64() % 100) < 78;
                    if edge {
                        list.push(dealer);
                    }
                }
                list.sort_by_key(|d| d.member);
            }
            let entries: Vec<(Dealer, &[Dealer])> = dealers
                .iter()
                .zip(lists.iter())
                .map(|(d, l)| (*d, l.as_slice()))
                .collect();
            let reports: BTreeMap<Address, &[Dealer]> =
                entries.iter().map(|(d, l)| (d.member, *l)).collect();
            let mut expected = Vec::new();
            let expected =
                select_fallback(&reports, &dealers, h, &mut expected).then_some(expected);
            let actual = select_bitmask(&entries, h);
            assert_eq!(actual, expected, "mismatch on trial {trial}");
        }
    }
}
