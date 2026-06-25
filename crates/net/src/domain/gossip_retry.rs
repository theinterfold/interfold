// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure state machine for gossip retry queuing.
//!
//! When a `GossipPublish` fails with `InsufficientPeers`, the event is queued
//! and automatically retried when a peer connection is established. This holds
//! no actix/bus/channel state — the owning actor performs the actual I/O.

use crate::events::GossipData;
use e3_events::CorrelationId;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Max number of queued gossip events.
pub(crate) const GOSSIP_RETRY_QUEUE_CAP: usize = 100;
/// Drop queued events older than this.
pub(crate) const GOSSIP_RETRY_TTL: Duration = Duration::from_secs(300);
/// Max retries per queued event before permanently dropping.
pub(crate) const GOSSIP_RETRY_MAX_ATTEMPTS: u8 = 5;

/// Tracks an outbound gossip publish that hasn't been acked/errored yet.
pub(crate) struct PendingGossip {
    pub data: GossipData,
    pub topic: String,
    pub queued_at: Instant,
}

/// A gossip publish that is waiting for a peer connection before retrying.
pub(crate) struct QueuedGossip {
    pub data: GossipData,
    pub topic: String,
    pub queued_at: Instant,
    pub retries: u8,
}

/// Pure state machine for tracking in-flight gossip publishes and retrying
/// those that fail with `InsufficientPeers`.
pub(crate) struct GossipRetryQueue {
    /// CorrelationId → data for in-flight publishes, matched against
    /// GossipPublishError / GossipPublished events.
    pending: HashMap<CorrelationId, PendingGossip>,
    /// Events that failed with InsufficientPeers — retried on next peer connect.
    queue: VecDeque<QueuedGossip>,
}

impl GossipRetryQueue {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            queue: VecDeque::new(),
        }
    }

    /// Register a new outbound gossip publish.
    pub fn track_publish(&mut self, id: CorrelationId, data: GossipData, topic: String) {
        self.pending.insert(
            id,
            PendingGossip {
                data,
                topic,
                queued_at: Instant::now(),
            },
        );
    }

    /// A publish succeeded — clean up tracking (no retry needed).
    pub fn on_published(&mut self, id: CorrelationId) {
        self.pending.remove(&id);
    }

    /// A publish failed. If `InsufficientPeers`, enqueue for retry.
    /// Otherwise just clean up.
    pub fn on_publish_error(&mut self, id: CorrelationId, is_insufficient_peers: bool) {
        let Some(pending) = self.pending.remove(&id) else {
            return;
        };

        if !is_insufficient_peers {
            return;
        }

        self.evict_stale();

        if self.queue.len() >= GOSSIP_RETRY_QUEUE_CAP {
            self.queue.pop_front();
        }

        self.queue.push_back(QueuedGossip {
            data: pending.data,
            topic: pending.topic,
            queued_at: pending.queued_at,
            retries: 0,
        });
    }

    /// A peer connected — drain the retry queue. Returns items ready to
    /// re-publish: (correlation_id, data, topic). The correlation_id is
    /// already tracked in pending — the caller must use it as-is in the
    /// GossipPublish command so publish ack/error matching works.
    /// Exhausted items are silently dropped.
    pub fn on_peer_connected(&mut self) -> Vec<(CorrelationId, GossipData, String)> {
        self.evict_stale();

        let mut to_send = Vec::with_capacity(self.queue.len());
        while let Some(mut item) = self.queue.pop_front() {
            if item.retries >= GOSSIP_RETRY_MAX_ATTEMPTS {
                continue;
            }
            item.retries += 1;
            let id = CorrelationId::new();
            self.pending.insert(
                id,
                PendingGossip {
                    data: item.data.clone(),
                    topic: item.topic.clone(),
                    queued_at: item.queued_at,
                },
            );
            to_send.push((id, item.data, item.topic));
        }
        to_send
    }

    /// Push an item back onto the front of the queue (e.g. when the transport
    /// channel was full). The caller must also call `on_published(id)` to
    /// clean up the tracking that `on_peer_connected` created for this item.
    pub fn queue_back(&mut self, data: GossipData, topic: String, retries: u8) {
        self.queue.push_front(QueuedGossip {
            data,
            topic,
            queued_at: Instant::now(),
            retries,
        });
    }

    /// Remove items older than `GOSSIP_RETRY_TTL`.
    fn evict_stale(&mut self) {
        let cutoff = Instant::now()
            .checked_sub(GOSSIP_RETRY_TTL)
            .unwrap_or(Instant::now());
        while self.queue.front().is_some_and(|q| q.queued_at < cutoff) {
            self.queue.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::CorrelationId;

    fn gossip_data(tag: u8) -> GossipData {
        GossipData::GossipBytes(vec![tag])
    }

    #[test]
    fn published_cleans_up_without_queueing() {
        let mut q = GossipRetryQueue::new();
        let id = CorrelationId::new();
        q.track_publish(id, gossip_data(1), "t".into());
        q.on_published(id);
        assert!(q.pending.is_empty());
        assert!(q.queue.is_empty());
    }

    #[test]
    fn insufficient_peers_queues_for_retry() {
        let mut q = GossipRetryQueue::new();
        let id = CorrelationId::new();
        q.track_publish(id, gossip_data(1), "t".into());
        q.on_publish_error(id, true);
        assert!(q.pending.is_empty());
        assert_eq!(q.queue.len(), 1);
    }

    #[test]
    fn non_retryable_error_just_cleans_up() {
        let mut q = GossipRetryQueue::new();
        let id = CorrelationId::new();
        q.track_publish(id, gossip_data(1), "t".into());
        q.on_publish_error(id, false);
        assert!(q.pending.is_empty());
        assert!(q.queue.is_empty());
    }

    #[test]
    fn peer_connected_drains_queue() {
        let mut q = GossipRetryQueue::new();
        let id1 = CorrelationId::new();
        let id2 = CorrelationId::new();
        q.track_publish(id1, gossip_data(1), "t1".into());
        q.track_publish(id2, gossip_data(2), "t2".into());
        q.on_publish_error(id1, true);
        q.on_publish_error(id2, true);
        assert_eq!(q.queue.len(), 2);

        let retries = q.on_peer_connected();
        assert_eq!(retries.len(), 2);
        assert_eq!(retries[0].2, "t1");
        assert_eq!(retries[1].2, "t2");
        assert!(q.queue.is_empty());
        // Items were re-tracked with new correlation ids (different from originals).
        assert_eq!(q.pending.len(), 2);
        assert_ne!(retries[0].0, id1);
        assert_ne!(retries[1].0, id2);
    }

    #[test]
    fn exhausted_retries_are_dropped_on_flush() {
        let mut q = GossipRetryQueue::new();
        let id = CorrelationId::new();
        q.track_publish(id, gossip_data(1), "t".into());
        q.on_publish_error(id, true);
        // Manually exhaust the item.
        q.queue.front_mut().unwrap().retries = GOSSIP_RETRY_MAX_ATTEMPTS;

        let retries = q.on_peer_connected();
        assert!(retries.is_empty());
        assert!(q.queue.is_empty());
    }

    #[test]
    fn unknown_correlation_id_is_noop() {
        let mut q = GossipRetryQueue::new();
        // Neither on_published nor on_publish_error should panic for unknown ids.
        q.on_published(CorrelationId::new());
        q.on_publish_error(CorrelationId::new(), true);
    }
}
