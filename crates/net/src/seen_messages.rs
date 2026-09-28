// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bounded memory of message and event IDs that this node has already handled.

use std::{
    collections::{HashSet, VecDeque},
    hash::Hash,
    time::{Duration, Instant},
};

/// Remembers IDs for `ttl`, keeping at most `capacity` of them (oldest dropped first).
///
/// gossipsub forgets a message ID when its duplicate cache expires. A copy that returns later is
/// then delivered again and, when accepted, forwarded again, which lets old messages circulate.
/// The node checks gossip message IDs here before it accepts a message, and event IDs before it
/// stores an event received from gossip.
pub(crate) struct SeenIds<K> {
    ttl: Duration,
    capacity: usize,
    ids: HashSet<K>,
    order: VecDeque<(Instant, K)>,
}

impl<K: Clone + Eq + Hash> SeenIds<K> {
    pub(crate) fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            ids: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Whether `id` was recorded within the time-to-live.
    pub(crate) fn contains(&mut self, id: &K, now: Instant) -> bool {
        self.expire(now);
        self.ids.contains(id)
    }

    /// Records `id`. A repeated ID keeps its first record time.
    pub(crate) fn record(&mut self, id: K, now: Instant) {
        self.expire(now);
        if self.ids.contains(&id) {
            return;
        }
        if self.order.len() >= self.capacity {
            if let Some((_, oldest)) = self.order.pop_front() {
                self.ids.remove(&oldest);
            }
        }
        self.ids.insert(id.clone());
        self.order.push_back((now, id));
    }

    /// Records `id` and returns `false`, or returns `true` when `id` was already recorded within
    /// the time-to-live.
    pub(crate) fn check_and_record(&mut self, id: &K, now: Instant) -> bool {
        if self.contains(id, now) {
            return true;
        }
        self.record(id.clone(), now);
        false
    }

    fn expire(&mut self, now: Instant) {
        while let Some((recorded, _)) = self.order.front() {
            if now.saturating_duration_since(*recorded) < self.ttl {
                break;
            }
            if let Some((_, expired)) = self.order.pop_front() {
                self.ids.remove(&expired);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_ids_are_reported_until_they_expire() {
        let start = Instant::now();
        let mut seen = SeenIds::new(Duration::from_secs(60), 10);
        assert!(!seen.check_and_record(&1u8, start));
        assert!(seen.check_and_record(&1u8, start + Duration::from_secs(59)));
        assert!(!seen.check_and_record(&1u8, start + Duration::from_secs(60)));
    }

    #[test]
    fn capacity_drops_the_oldest_id() {
        let start = Instant::now();
        let mut seen = SeenIds::new(Duration::from_secs(3600), 2);
        assert!(!seen.check_and_record(&1u8, start));
        assert!(!seen.check_and_record(&2u8, start));
        assert!(!seen.check_and_record(&3u8, start));
        assert!(seen.check_and_record(&3u8, start));
        assert!(seen.check_and_record(&2u8, start));
        assert!(!seen.check_and_record(&1u8, start));
    }

    #[test]
    fn contains_does_not_record() {
        let start = Instant::now();
        let mut seen = SeenIds::new(Duration::from_secs(60), 10);
        assert!(!seen.contains(&7u8, start));
        assert!(!seen.contains(&7u8, start));
        seen.record(7u8, start);
        assert!(seen.contains(&7u8, start));
    }
}
