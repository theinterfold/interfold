// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{ensure, Result};
use e3_events::{
    prelude::*, Event, EventId, InterfoldEvent, InterfoldEventData, SeqState, Unsequenced,
};
use std::collections::{HashSet, VecDeque};
use tracing::{trace, warn};

use crate::events::GossipData;

/// Pure translation/dedup logic backing the `NetEventTranslator` actor.
///
/// Decides which local events should be gossiped to the network (and dedups them so the same
/// event is never rebroadcast), and decodes inbound gossip into the internal event to publish.
///
/// Holds no actix/bus/channel state — the actor performs the actual publish I/O.
pub struct EventTranslationService {
    sent_events: HashSet<EventId>,
    sent_order: VecDeque<EventId>,
    dedup_capacity: usize,
    topic: String,
}

const SENT_EVENT_DEDUP_CAPACITY: usize = 10_000;

impl EventTranslationService {
    pub fn new(topic: &str) -> Self {
        Self {
            sent_events: HashSet::new(),
            sent_order: VecDeque::new(),
            dedup_capacity: SENT_EVENT_DEDUP_CAPACITY,
            topic: topic.to_string(),
        }
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Function to determine which events are allowed to be automatically broadcast to the
    /// network. Static so the same rule can be reused elsewhere (e.g. sync responses).
    pub fn is_forwardable_event<S: SeqState>(event: &InterfoldEvent<S>) -> bool {
        matches!(
            event.get_data(),
            InterfoldEventData::DecryptionshareCreated(_)
                | InterfoldEventData::DKGRecursiveAggregationComplete(_)
                | InterfoldEventData::KeyshareCreated(_)
                | InterfoldEventData::PlaintextAggregated(_)
                | InterfoldEventData::PublicKeyAggregated(_)
                | InterfoldEventData::ProofFailureAccusation(_)
                | InterfoldEventData::AccusationVote(_)
        )
    }

    /// Decide whether a local event should be gossiped.
    ///
    /// Returns `Some(GossipData)` to publish over the network, or `None` when the event is not
    /// forwardable or has already been broadcast.
    pub fn prepare_outbound(&self, event: InterfoldEvent) -> Result<Option<(EventId, GossipData)>> {
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
        warn!("GossipPublish event: {}", event.event_type());
        let data: GossipData = event.try_into()?;
        Ok(Some((id, data)))
    }

    /// Record an event only after the downstream command/bus has accepted it.
    pub fn mark_accepted(&mut self, id: EventId) {
        if !self.sent_events.insert(id) {
            return;
        }
        self.sent_order.push_back(id);
        while self.sent_order.len() > self.dedup_capacity {
            if let Some(expired) = self.sent_order.pop_front() {
                self.sent_events.remove(&expired);
            }
        }
    }

    /// Decode and authorize an inbound gossip payload. The actor records its ID only after the
    /// local event pipeline accepts it.
    pub fn prepare_inbound(
        &self,
        data: GossipData,
    ) -> Result<(EventId, InterfoldEvent<Unsequenced>)> {
        let event: InterfoldEvent<Unsequenced> = data.try_into()?;
        ensure!(
            Self::is_forwardable_event(&event),
            "inbound gossip event type {} is not allowed on the protocol gossip channel",
            event.event_type()
        );
        let id = event.id();
        Ok((id, event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{
        E3id, EventConstructorWithTimestamp, EventSource, PlaintextAggregated, TestEvent,
    };
    use e3_utils::ArcBytes;

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

    fn local_forwardable_event() -> InterfoldEvent {
        let unsequenced: InterfoldEvent<Unsequenced> = InterfoldEvent::new_with_timestamp(
            PlaintextAggregated {
                e3_id: E3id::new("1", 1),
                decrypted_output: vec![ArcBytes::from_bytes(&[1, 2, 3])],
                decryption_aggregator_proofs: vec![],
            }
            .into(),
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
        let svc = EventTranslationService::new("topic");
        assert!(svc.prepare_outbound(local_test_event()).unwrap().is_none());
    }

    #[test]
    fn inbound_gossip_rejects_non_forwardable_internal_events() {
        let svc = EventTranslationService::new("topic");
        let event: InterfoldEvent<Unsequenced> = InterfoldEvent::new_with_timestamp(
            TestEvent::new("fish", 7).into(),
            None,
            99,
            None,
            EventSource::Local,
        );
        let data: GossipData = event.clone().into_sequenced(3).try_into().unwrap();
        let error = svc.prepare_inbound(data).unwrap_err();
        assert!(error.to_string().contains("TestEvent"));
    }

    #[test]
    fn inbound_gossip_accepts_forwardable_protocol_events() {
        let svc = EventTranslationService::new("topic");
        let expected = local_forwardable_event();
        let data: GossipData = expected.clone().try_into().unwrap();

        let (_, decoded) = svc.prepare_inbound(data).unwrap();

        assert_eq!(decoded.get_data(), expected.get_data());
    }

    #[test]
    fn outbound_dedup_advances_only_after_acceptance() {
        let mut svc = EventTranslationService::new("topic");
        let event = local_forwardable_event();
        let (id, _) = svc.prepare_outbound(event.clone()).unwrap().unwrap();

        assert!(svc.prepare_outbound(event.clone()).unwrap().is_some());
        svc.mark_accepted(id);
        assert!(svc.prepare_outbound(event).unwrap().is_none());
    }
}
