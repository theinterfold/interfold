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

/// Supported new IDs per second, with a short burst allowance, for each ingress cache.
pub(crate) const INGRESS_RATE: u64 = 16;
pub(crate) const INGRESS_BURST: u64 = 256;
pub(crate) const SEEN_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const SEEN_CAPACITY: usize = (INGRESS_RATE * SEEN_TTL.as_secs() + INGRESS_BURST) as usize;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    New,
    Duplicate,
    Throttled,
}

/// Remembers admitted IDs for the full TTL. Capacity pressure rejects new IDs.
pub(crate) struct SeenIds<K> {
    ttl: Duration,
    capacity: usize,
    ids: HashSet<K>,
    order: VecDeque<(Instant, K)>,
    budget: RateBudget,
    capacity_rejections: u64,
}

impl<K: Clone + Eq + Hash> SeenIds<K> {
    pub(crate) fn new() -> Self {
        Self {
            ttl: SEEN_TTL,
            capacity: SEEN_CAPACITY,
            ids: HashSet::new(),
            order: VecDeque::new(),
            budget: RateBudget::new(INGRESS_RATE, INGRESS_BURST),
            capacity_rejections: 0,
        }
    }

    pub(crate) fn contains(&mut self, id: &K, now: Instant) -> bool {
        self.expire(now);
        self.ids.contains(id)
    }

    /// Reserve retention before accepting or storing an ID. Copies keep their first record time.
    pub(crate) fn admit(&mut self, id: &K, now: Instant) -> Admission {
        if self.contains(id, now) {
            return Admission::Duplicate;
        }
        if self.order.len() >= self.capacity {
            self.capacity_rejections = self.capacity_rejections.saturating_add(1);
            if self.capacity_rejections.is_power_of_two() {
                tracing::warn!(
                    capacity = self.capacity,
                    capacity_rejections = self.capacity_rejections,
                    early_evictions = 0,
                    "Seen-ID capacity pressure; new IDs are rejected to preserve retention"
                );
            }
            return Admission::Throttled;
        }
        if !self.budget.take(1, now) {
            return Admission::Throttled;
        }
        self.ids.insert(id.clone());
        self.order.push_back((now, id.clone()));
        Admission::New
    }

    /// Undo the most recent admission after a failed handoff, without refunding its rate charge.
    pub(crate) fn rollback_latest(&mut self, id: &K) {
        if self.order.back().is_some_and(|(_, latest)| latest == id) {
            self.order.pop_back();
            self.ids.remove(id);
        }
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

/// A token budget with fractional refill retained between calls. Callers supply monotonic time.
pub(crate) struct RateBudget {
    rate: u64,
    burst: u64,
    credit: u128,
    updated: Option<Instant>,
}

impl RateBudget {
    const UNIT: u128 = 1_000_000_000;

    pub(crate) fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate,
            burst,
            credit: u128::from(burst) * Self::UNIT,
            updated: None,
        }
    }

    pub(crate) fn take(&mut self, amount: u64, now: Instant) -> bool {
        if let Some(updated) = self.updated {
            self.credit = self
                .credit
                .saturating_add(
                    now.saturating_duration_since(updated)
                        .as_nanos()
                        .saturating_mul(u128::from(self.rate)),
                )
                .min(u128::from(self.burst) * Self::UNIT);
        }
        self.updated = Some(now);
        let cost = u128::from(amount) * Self::UNIT;
        if self.credit < cost {
            return false;
        }
        self.credit -= cost;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_ids_are_reported_until_they_expire() {
        let start = Instant::now();
        let mut seen = SeenIds::new();
        assert_eq!(seen.admit(&1u8, start), Admission::New);
        assert_eq!(
            seen.admit(&1u8, start + SEEN_TTL - Duration::from_secs(1)),
            Admission::Duplicate
        );
        assert_eq!(seen.admit(&1u8, start + SEEN_TTL), Admission::New);
    }

    #[test]
    fn capacity_preserves_retained_ids() {
        let start = Instant::now();
        let mut seen = SeenIds::new();
        seen.capacity = 2;
        assert_eq!(seen.admit(&1u8, start), Admission::New);
        assert_eq!(seen.admit(&2u8, start), Admission::New);
        assert_eq!(seen.admit(&3u8, start), Admission::Throttled);
        assert_eq!(seen.admit(&1u8, start), Admission::Duplicate);
        assert_eq!(seen.admit(&3u8, start + SEEN_TTL), Admission::New);
    }
}
