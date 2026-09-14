// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure DKG roster selection.
//!
//! The DKG continues when up to `N - H` committee members are absent. After C2/C3
//! verification each member reports its ready set `R_j`: the senders whose complete,
//! verified share bundle it holds. The epoch leader picks a roster `S` of exactly `H`
//! members such that every member of `S` holds the bundle of every other member of `S`.
//! Members of `S` then compute their C4 share over `S`.
//!
//! No agreement protocol is needed for safety. The DKG aggregator circuit rejects C4
//! proofs that were not built over one roster, and the registry accepts one publication.
//! The leader only provides liveness. `leader(epoch) = eligible[epoch mod |eligible|]`.

use std::collections::{BTreeMap, BTreeSet};

use e3_events::DkgReady;

/// Ready sets keyed by reporting party id. Each set includes the reporter itself.
pub(crate) type ReadySets = BTreeMap<u64, BTreeSet<u64>>;

/// Record a verified `DkgReady` report. A later report from the same party replaces the
/// earlier one.
pub(crate) fn record_ready(sets: &mut ReadySets, report: &DkgReady) {
    sets.insert(report.party_id, report.ready_with_self());
}

/// Party id that proposes `epoch`. `eligible` is the ascending list of committee members
/// that are not expelled.
pub(crate) fn leader_for_epoch(eligible: &[u64], epoch: u32) -> Option<u64> {
    if eligible.is_empty() {
        return None;
    }
    eligible.get((epoch as usize) % eligible.len()).copied()
}

/// Choose an ascending roster of exactly `h` parties from `ready` such that every chosen
/// party holds the bundle of every other chosen party. Parties in `excluded` are never
/// chosen. Returns `None` when no such roster exists yet.
///
/// The search is greedy in ascending party id over the candidates whose reports arrived,
/// and drops the candidate held by the fewest others until a mutually complete set of
/// size `h` remains. `N <= 19` keeps this cheap.
pub(crate) fn select_roster(
    ready: &ReadySets,
    excluded: &BTreeSet<u64>,
    h: usize,
) -> Option<Vec<u64>> {
    if h == 0 {
        return None;
    }
    let mut candidates: BTreeSet<u64> = ready
        .keys()
        .copied()
        .filter(|id| !excluded.contains(id))
        .collect();

    loop {
        if candidates.len() < h {
            return None;
        }
        // For each candidate, count how many other candidates hold its bundle.
        let mut worst: Option<(u64, usize)> = None;
        let mut complete = true;
        for &id in &candidates {
            let held_by = candidates
                .iter()
                .filter(|&&other| other == id || ready[&other].contains(&id))
                .count();
            if held_by < candidates.len() {
                complete = false;
            }
            if worst.is_none_or(|(_, count)| held_by < count) {
                worst = Some((id, held_by));
            }
        }
        if complete {
            return Some(candidates.iter().take(h).copied().collect());
        }
        // A candidate whose bundle is missing somewhere cannot be in a mutually complete set
        // with that member. Drop the least-held candidate and retry.
        let (drop, _) = worst?;
        candidates.remove(&drop);
    }
}

/// True when `party` can compute C4 over `roster`: it is in the roster and holds the
/// bundle of every other roster member.
pub(crate) fn can_serve_roster(party: u64, held: &BTreeSet<u64>, roster: &[u64]) -> bool {
    roster.contains(&party) && roster.iter().all(|id| *id == party || held.contains(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sets(entries: &[(u64, &[u64])]) -> ReadySets {
        entries
            .iter()
            .map(|(id, held)| {
                let mut set: BTreeSet<u64> = held.iter().copied().collect();
                set.insert(*id);
                (*id, set)
            })
            .collect()
    }

    #[test]
    fn leader_rotates_by_epoch_over_eligible_parties() {
        let eligible = [0, 2, 3];
        assert_eq!(leader_for_epoch(&eligible, 0), Some(0));
        assert_eq!(leader_for_epoch(&eligible, 1), Some(2));
        assert_eq!(leader_for_epoch(&eligible, 2), Some(3));
        assert_eq!(leader_for_epoch(&eligible, 3), Some(0));
        assert_eq!(leader_for_epoch(&[], 0), None);
    }

    #[test]
    fn full_committee_yields_lowest_h() {
        let ready = sets(&[(0, &[1, 2]), (1, &[0, 2]), (2, &[0, 1])]);
        assert_eq!(select_roster(&ready, &BTreeSet::new(), 2), Some(vec![0, 1]));
    }

    #[test]
    fn absent_member_is_skipped_and_roster_is_not_a_prefix() {
        // Party 1 never reported and nobody holds its bundle.
        let ready = sets(&[(0, &[2]), (2, &[0])]);
        assert_eq!(select_roster(&ready, &BTreeSet::new(), 2), Some(vec![0, 2]));
    }

    #[test]
    fn member_whose_bundle_is_missing_somewhere_is_dropped() {
        // Party 1 reported, but party 2 never received party 1's bundle.
        let ready = sets(&[(0, &[1, 2]), (1, &[0, 2]), (2, &[0])]);
        assert_eq!(select_roster(&ready, &BTreeSet::new(), 2), Some(vec![0, 2]));
    }

    #[test]
    fn too_few_mutually_complete_parties_yields_none() {
        let ready = sets(&[(0, &[]), (2, &[])]);
        assert_eq!(select_roster(&ready, &BTreeSet::new(), 2), None);
    }

    #[test]
    fn excluded_parties_are_never_chosen() {
        let ready = sets(&[(0, &[1, 2]), (1, &[0, 2]), (2, &[0, 1])]);
        let excluded = BTreeSet::from([0]);
        assert_eq!(select_roster(&ready, &excluded, 2), Some(vec![1, 2]));
    }

    #[test]
    fn serving_requires_membership_and_held_bundles() {
        let held = BTreeSet::from([0, 2]);
        assert!(can_serve_roster(1, &held, &[0, 1, 2]));
        assert!(!can_serve_roster(1, &held, &[0, 1, 3]));
        assert!(!can_serve_roster(3, &held, &[0, 1, 2]));
    }
}
