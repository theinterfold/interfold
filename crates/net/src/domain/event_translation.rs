// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use bloom::{BloomFilter, ASMS};
use e3_events::{
    prelude::*, CorrelationId, Event, InterfoldEvent, InterfoldEventData, Unsequenced,
};
use tracing::{trace, warn};

use crate::domain::gossip_retry::GossipRetryQueue;
use crate::events::GossipData;

/// Pure translation/dedup/retry logic backing the `NetEventTranslator` actor.
///
/// Decides which local events should be gossiped to the network (and dedups them so the same
/// event is never rebroadcast), decodes inbound gossip into the internal event to publish,
/// and manages a retry queue for gossip publishes that fail with `InsufficientPeers`.
///
/// Holds no actix/bus/channel state — the actor performs the actual publish I/O.
pub struct EventTranslationService {
    sent_events: BloomFilter,
    topic: String,
    retry: GossipRetryQueue,
}

impl EventTranslationService {
    pub fn new(topic: &str) -> Self {
        Self {
            sent_events: BloomFilter::with_rate(0.001, 10_000),
            topic: topic.to_string(),
            retry: GossipRetryQueue::new(),
        }
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Function to determine which events are allowed to be automatically broadcast to the
    /// network. Static so the same rule can be reused elsewhere (e.g. sync responses).
    pub fn is_forwardable_event(event: &InterfoldEvent) -> bool {
        matches!(
            event.get_data(),
            InterfoldEventData::DecryptionshareCreated(_)
                | InterfoldEventData::DKGRecursiveAggregationComplete(_)
                | InterfoldEventData::KeyshareCreated(_)
                | InterfoldEventData::PlaintextAggregated(_)
                | InterfoldEventData::PublicKeyAggregated(_)
                | InterfoldEventData::ProofFailureAccusation(_)
                | InterfoldEventData::AccusationVote(_)
                | InterfoldEventData::DkgDocumentResyncRequest(_)
        )
    }

    /// Decide whether a local event should be gossiped.
    ///
    /// Returns `Some(GossipData)` to publish over the network, or `None` when the event is not
    /// forwardable or has already been broadcast.
    pub fn prepare_outbound(&mut self, event: InterfoldEvent) -> Result<Option<GossipData>> {
        if !Self::is_forwardable_event(&event) {
            let id = event.event_id();
            trace!(evt_id=%id, "Local events should not be rebroadcast so ignoring");
            return Ok(None);
        }

        let id = event.event_id();
        if self.sent_events.contains(&id) {
            trace!(evt_id=%id, "Have seen event before not rebroadcasting!");
            return Ok(None);
        }
        self.sent_events.insert(&id);

        warn!("GossipPublish event: {}", event.event_type());
        let data: GossipData = event.try_into()?;
        Ok(Some(data))
    }

    /// Decode an inbound gossip payload into the internal event to publish locally, recording it
    /// for dedup so it is not later rebroadcast.
    pub fn prepare_inbound(&mut self, data: GossipData) -> Result<InterfoldEvent<Unsequenced>> {
        let event: InterfoldEvent<Unsequenced> = data.try_into()?;
        let id = event.id();
        self.sent_events.insert(&id);
        Ok(event)
    }

    // ── Gossip retry delegation ──────────────────────────────────────────

    pub fn track_publish(&mut self, id: CorrelationId, data: GossipData, topic: String) {
        self.retry.track_publish(id, data, topic);
    }

    pub fn on_published(&mut self, id: CorrelationId) {
        self.retry.on_published(id);
    }

    pub fn on_publish_error(&mut self, id: CorrelationId, is_insufficient_peers: bool) {
        self.retry.on_publish_error(id, is_insufficient_peers);
    }

    pub fn on_peer_connected(&mut self) -> Vec<(CorrelationId, GossipData, String)> {
        self.retry.on_peer_connected()
    }

    pub fn queue_back(&mut self, data: GossipData, topic: String, retries: u8) {
        self.retry.queue_back(data, topic, retries);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{EventConstructorWithTimestamp, EventSource, TestEvent};

    fn local_test_event() -> InterfoldEvent {
        let unsequenced: InterfoldEvent<Unsequenced> = InterfoldEvent::new_with_timestamp(
            TestEvent::new("hello", 1).into(),
            None,
            42,
            None,
            EventSource::Local,
        );
        unsequenced.into_sequenced(1)
    }

    #[test]
    fn test_events_are_not_forwardable() {
        assert!(!EventTranslationService::is_forwardable_event(
            &local_test_event()
        ));
    }

    #[test]
    fn non_forwardable_events_produce_no_gossip() {
        let mut svc = EventTranslationService::new("topic");
        assert!(svc.prepare_outbound(local_test_event()).unwrap().is_none());
    }

    #[test]
    fn inbound_gossip_round_trips_to_event() {
        let mut svc = EventTranslationService::new("topic");
        let event: InterfoldEvent<Unsequenced> = InterfoldEvent::new_with_timestamp(
            TestEvent::new("fish", 7).into(),
            None,
            99,
            None,
            EventSource::Local,
        );
        let data: GossipData = event.clone().into_sequenced(3).try_into().unwrap();
        let decoded = svc.prepare_inbound(data).unwrap();
        assert_eq!(decoded.split().0, TestEvent::new("fish", 7).into());
    }
}
