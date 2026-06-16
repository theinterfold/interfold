// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use libp2p::PeerId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Entries are automatically cleaned up after this TTL to prevent unbounded growth.
const PEER_FAILURE_TTL: Duration = Duration::from_secs(300);

/// Tracks consecutive connection failures per peer to detect and evict stale peers.
///
/// This is pure decision/state logic with no network I/O: the network layer records
/// failures and queries the resulting consecutive-failure count to decide when to evict
/// an unreachable peer.
pub(crate) struct PeerFailureTracker {
    failures: HashMap<PeerId, (u32, Instant)>,
}

impl PeerFailureTracker {
    pub fn new() -> Self {
        Self {
            failures: HashMap::new(),
        }
    }

    /// Record a failure for the given peer and return the new consecutive failure count.
    pub fn record_failure(&mut self, peer_id: &PeerId) -> u32 {
        self.cleanup_stale();
        let now = Instant::now();
        let entry = self.failures.entry(*peer_id).or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;
        entry.0
    }

    /// Reset the failure count for a peer (e.g. on successful connection or after eviction).
    pub fn reset(&mut self, peer_id: &PeerId) {
        self.failures.remove(peer_id);
    }

    /// Remove entries older than PEER_FAILURE_TTL to prevent unbounded growth
    fn cleanup_stale(&mut self) {
        let now = Instant::now();
        self.failures
            .retain(|_, (_, last_seen)| now.duration_since(*last_seen) < PEER_FAILURE_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consecutive_failures_increment() {
        let mut tracker = PeerFailureTracker::new();
        let peer = PeerId::random();
        assert_eq!(tracker.record_failure(&peer), 1);
        assert_eq!(tracker.record_failure(&peer), 2);
        assert_eq!(tracker.record_failure(&peer), 3);
    }

    #[test]
    fn reset_clears_count() {
        let mut tracker = PeerFailureTracker::new();
        let peer = PeerId::random();
        tracker.record_failure(&peer);
        tracker.record_failure(&peer);
        tracker.reset(&peer);
        assert_eq!(tracker.record_failure(&peer), 1);
    }

    #[test]
    fn failures_are_tracked_independently_per_peer() {
        let mut tracker = PeerFailureTracker::new();
        let a = PeerId::random();
        let b = PeerId::random();
        tracker.record_failure(&a);
        tracker.record_failure(&a);
        assert_eq!(tracker.record_failure(&b), 1);
        assert_eq!(tracker.record_failure(&a), 3);
    }
}
