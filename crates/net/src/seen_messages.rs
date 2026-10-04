// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bounded memory of message and event IDs that this node has already handled.

use crate::ingress_limits::{SEEN_BURST, SEEN_RATE};
use libp2p::PeerId;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    time::{Duration, Instant},
};

pub(crate) const SEEN_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const SEEN_CAPACITY: usize = SEEN_RATE * SEEN_TTL.as_secs() as usize + SEEN_BURST;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    New,
    Duplicate,
}

/// Peers borrow unused space. At capacity, a peer at its fair share replaces its own oldest ID.
/// A peer below its share reclaims space from the largest owner. Duplicates keep their first owner.
pub(crate) struct SeenIds<K> {
    capacity: usize,
    ids: HashSet<K>,
    peers: HashMap<Option<PeerId>, VecDeque<(Instant, K)>>,
    latest: Option<Option<PeerId>>,
    cache: &'static str,
    early_evictions: u64,
}

impl<K: Clone + Eq + Hash> SeenIds<K> {
    pub(crate) fn new(cache: &'static str) -> Self {
        Self {
            capacity: SEEN_CAPACITY,
            ids: HashSet::new(),
            peers: HashMap::new(),
            latest: None,
            cache,
            early_evictions: 0,
        }
    }

    pub(crate) fn contains(&mut self, id: &K, now: Instant) -> bool {
        self.expire(now);
        self.ids.contains(id)
    }

    /// New IDs are always admitted. Retention pressure must not discard protocol input.
    pub(crate) fn admit(&mut self, peer: Option<PeerId>, id: &K, now: Instant) -> Admission {
        if self.contains(id, now) {
            return Admission::Duplicate;
        }
        if self.ids.len() >= self.capacity {
            let owner = crate::ingress_limits::eviction_owner(
                peer,
                self.peers.iter().map(|(owner, ids)| (*owner, ids.len())),
                self.capacity,
            );
            let entries = self.peers.get_mut(&owner).unwrap();
            let (_, expired) = entries.pop_front().unwrap();
            self.ids.remove(&expired);
            if entries.is_empty() {
                self.peers.remove(&owner);
            }
            self.early_evictions = self.early_evictions.saturating_add(1);
            // This cumulative counter is a structured log metric. Limit warning volume under churn.
            if self.early_evictions.is_power_of_two() {
                tracing::warn!(
                    cache = self.cache,
                    seen_ids_early_evictions_total = self.early_evictions,
                    capacity = self.capacity,
                    ?owner,
                    "Seen-ID cache evicted an unexpired ID"
                );
            }
        }
        self.ids.insert(id.clone());
        self.peers
            .entry(peer)
            .or_default()
            .push_back((now, id.clone()));
        self.latest = Some(peer);
        Admission::New
    }

    /// Undo the most recent admission after a failed handoff.
    pub(crate) fn rollback_latest(&mut self, id: &K) {
        let Some(peer) = self.latest.take() else {
            return;
        };
        let Some(entries) = self.peers.get_mut(&peer) else {
            return;
        };
        if entries.back().is_some_and(|(_, latest)| latest == id) {
            entries.pop_back();
            self.ids.remove(id);
        }
        if entries.is_empty() {
            self.peers.remove(&peer);
        }
    }

    fn expire(&mut self, now: Instant) {
        self.peers.retain(|_, entries| {
            while let Some((recorded, _)) = entries.front() {
                if now.saturating_duration_since(*recorded) < SEEN_TTL {
                    break;
                }
                let (_, expired) = entries.pop_front().unwrap();
                self.ids.remove(&expired);
            }
            !entries.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_reclaims_borrowed_space_without_rejecting_new_ids() {
        let start = Instant::now();
        let mut seen = SeenIds::new("test");
        seen.capacity = 6;
        let busy = Some(PeerId::random());
        let other = Some(PeerId::random());
        for id in 0..6 {
            assert_eq!(
                seen.admit(busy, &id, start + Duration::from_millis(id as u64)),
                Admission::New
            );
        }
        for id in 6..9 {
            assert_eq!(
                seen.admit(other, &id, start + Duration::from_millis(id as u64)),
                Admission::New
            );
        }
        for id in 9..30 {
            assert_eq!(
                seen.admit(busy, &id, start + Duration::from_millis(id as u64)),
                Admission::New
            );
        }
        assert_eq!(seen.ids.len(), 6);
        assert_eq!(seen.early_evictions, 24);
        for id in 6..9 {
            assert_eq!(
                seen.admit(busy, &id, start + SEEN_TTL - Duration::from_secs(1)),
                Admission::Duplicate
            );
        }
        assert_eq!(
            seen.admit(other, &6, start + SEEN_TTL + Duration::from_secs(1)),
            Admission::New
        );
        assert_eq!(
            seen.early_evictions, 24,
            "TTL expiry is not an early eviction"
        );
    }
}
