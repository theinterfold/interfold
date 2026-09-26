// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::{HashSet, VecDeque},
    time::{Duration, Instant},
};

use anyhow::{ensure, Result};
use e3_events::{
    prelude::*, Event, EventId, EventSource, InterfoldEvent, InterfoldEventData, SeqState,
    Unsequenced,
};
use tracing::{debug, trace};

use crate::{events::GossipData, seen_messages::SeenIds, NetworkPolicy};

const EVENT_DEDUP_CAPACITY: usize = 10_000;
/// How long, and for how many IDs, an event from the peer network is not stored again. Peers
/// re-send DKG coordination and decryption shares in new gossip messages, and every stored copy
/// adds a record to the event log. The EventBus already stops repeated domain delivery.
const STORED_REMOTE_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const STORED_REMOTE_CAPACITY: usize = 20_000;

/// Pure translation/dedup logic backing the `NetEventTranslator` actor.
///
/// Decides which local events should be gossiped to the network (and dedups them so the same
/// event is never rebroadcast), and decodes inbound gossip into the internal event to publish.
///
/// Holds no actix/bus/channel state — the actor performs the actual publish I/O.
pub struct EventTranslationService {
    sent_events: HashSet<EventId>,
    sent_order: VecDeque<EventId>,
    pending_events: HashSet<EventId>,
    stored_remote: SeenIds<EventId>,
    topic: String,
    network: NetworkPolicy,
}

impl EventTranslationService {
    #[cfg(test)]
    pub fn new(topic: &str) -> Self {
        Self::with_network(topic, NetworkPolicy::local_unrestricted())
    }

    pub fn with_network(topic: &str, network: NetworkPolicy) -> Self {
        Self {
            sent_events: HashSet::with_capacity(EVENT_DEDUP_CAPACITY),
            sent_order: VecDeque::with_capacity(EVENT_DEDUP_CAPACITY),
            pending_events: HashSet::new(),
            stored_remote: SeenIds::new(STORED_REMOTE_TTL, STORED_REMOTE_CAPACITY),
            topic: topic.to_string(),
            network,
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
                | InterfoldEventData::DkgCoordination(_)
                | InterfoldEventData::DKGRecursiveAggregationComplete(_)
                | InterfoldEventData::KeyshareCreated(_)
                | InterfoldEventData::PublicKeyAggregated(_)
                | InterfoldEventData::ProofFailureAccusation(_)
                | InterfoldEventData::AccusationVote(_)
        )
    }

    /// Decide whether a local event should be gossiped.
    ///
    /// Returns `Some(GossipData)` to publish over the network, or `None` when the event is not
    /// forwardable or has already been broadcast.
    pub fn prepare_outbound(
        &mut self,
        event: InterfoldEvent,
    ) -> Result<Option<(EventId, GossipData)>> {
        if !Self::is_forwardable_event(&event) {
            let id = event.event_id();
            trace!(evt_id=%id, "Local events should not be rebroadcast so ignoring");
            return Ok(None);
        }

        let id = event.event_id();
        if self.sent_events.contains(&id) || self.pending_events.contains(&id) {
            trace!(evt_id=%id, "Have seen event before not rebroadcasting!");
            return Ok(None);
        }
        self.network.validate_event(&event)?;

        debug!("GossipPublish event: {}", event.event_type());
        let data: GossipData = event.try_into()?;
        self.pending_events.insert(id);
        Ok(Some((id, data)))
    }

    /// Record an event only after libp2p accepts the publish command.
    pub fn mark_published(&mut self, id: EventId) {
        self.pending_events.remove(&id);
        if !self.sent_events.insert(id) {
            return;
        }
        self.sent_order.push_back(id);
        if self.sent_order.len() > EVENT_DEDUP_CAPACITY {
            if let Some(expired) = self.sent_order.pop_front() {
                self.sent_events.remove(&expired);
            }
        }
    }

    /// Permit a later retry after all bounded publish attempts fail.
    pub fn mark_failed(&mut self, id: EventId) {
        self.pending_events.remove(&id);
    }

    /// Whether an event with this ID from the peer network was stored locally within the window.
    pub fn is_stored_remote_event(&mut self, id: &EventId, now: Instant) -> bool {
        self.stored_remote.contains(id, now)
    }

    /// Record a gossip event that was handed to the event store. A failed append stops the event
    /// store and the node, so recording before the commit cannot hide an event from a running
    /// node. Recording here, not only on bus delivery, also covers an event that the EventBus
    /// already knows from replay: the bus does not deliver such an event again.
    pub fn record_remote_event(&mut self, id: EventId, now: Instant) {
        self.stored_remote.record(id, now);
    }

    /// Record a protocol event from the peer network that the EventBus delivered, for example
    /// one that historical sync stored. The bus delivers an event only after it is stored.
    pub fn record_stored_event(&mut self, event: &InterfoldEvent, now: Instant) {
        if event.source() == EventSource::Net && Self::is_forwardable_event(event) {
            self.stored_remote.record(event.event_id(), now);
        }
    }

    /// Decode an inbound gossip payload into the internal event to publish locally, recording it
    /// for dedup so it is not later rebroadcast.
    pub fn prepare_inbound(&mut self, data: GossipData) -> Result<InterfoldEvent<Unsequenced>> {
        let event: InterfoldEvent<Unsequenced> = data.try_into()?;
        ensure!(
            Self::is_forwardable_event(&event),
            "inbound gossip event type {} is not allowed on the protocol gossip channel",
            event.event_type()
        );
        self.network.validate_event(&event)?;
        // Use the ID that the event store derives from the payload, not the peer-supplied context
        // ID, so a mislabeled event cannot mark another event as sent.
        self.mark_published(EventId::hash(event.get_data()));
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{
        DkgCoordination, DkgCoordinationKind, DkgDealer, E3id, EventConstructorWithTimestamp,
        KeyshareCreated, PlaintextAggregated, TestEvent,
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
            KeyshareCreated {
                pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
                e3_id: E3id::new("1", 1),
                node: "node-1".to_string(),
                party_id: 1,
                signed_pk_generation_proof: None,
            }
            .into(),
            None,
            42,
            None,
            EventSource::Local,
        );
        unsequenced.into_sequenced(1)
    }

    fn local_plaintext_event() -> InterfoldEvent {
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
    fn stored_remote_events_are_reported_until_the_window_ends() {
        let mut svc = EventTranslationService::new("topic");
        let remote = local_forwardable_event().with_source(EventSource::Net);
        let id = remote.event_id();
        let start = Instant::now();
        assert!(!svc.is_stored_remote_event(&id, start));
        svc.record_stored_event(&remote, start);
        assert!(svc.is_stored_remote_event(&id, start + STORED_REMOTE_TTL / 2));
        assert!(!svc.is_stored_remote_event(&id, start + STORED_REMOTE_TTL));
    }

    #[test]
    fn local_and_non_protocol_events_are_not_recorded_as_stored_remote_events() {
        let mut svc = EventTranslationService::new("topic");
        let start = Instant::now();
        let local = local_forwardable_event();
        svc.record_stored_event(&local, start);
        assert!(!svc.is_stored_remote_event(&local.event_id(), start));
        let internal = local_test_event().with_source(EventSource::Net);
        svc.record_stored_event(&internal, start);
        assert!(!svc.is_stored_remote_event(&internal.event_id(), start));
    }

    #[test]
    fn test_events_are_not_forwardable() {
        assert!(!EventTranslationService::is_forwardable_event(
            &local_test_event()
        ));
    }

    #[test]
    fn plaintext_results_are_not_forwardable() {
        assert!(!EventTranslationService::is_forwardable_event(
            &local_plaintext_event()
        ));
    }

    #[test]
    fn non_forwardable_events_produce_no_gossip() {
        let mut svc = EventTranslationService::new("topic");
        assert!(svc.prepare_outbound(local_test_event()).unwrap().is_none());
    }

    #[test]
    fn inbound_gossip_rejects_non_forwardable_internal_events() {
        let mut svc = EventTranslationService::new("topic");
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
        let mut svc = EventTranslationService::new("topic");
        let expected = local_forwardable_event();
        let data: GossipData = expected.clone().try_into().unwrap();

        let decoded = svc.prepare_inbound(data).unwrap();

        assert_eq!(decoded.get_data(), expected.get_data());
    }

    #[test]
    fn dkg_roster_round_trips_through_gossip() {
        let roster = DkgCoordination {
            e3_id: E3id::new("1", 1),
            interfold_address: Default::default(),
            party_id: 1,
            kind: DkgCoordinationKind::Roster,
            dealers: vec![DkgDealer {
                party_id: 1,
                contribution_hash: [7; 32],
            }],
            signature: ArcBytes::from_bytes(&[1, 2, 3]),
        };
        let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            roster.into(),
            None,
            42,
            None,
            EventSource::Local,
        )
        .into_sequenced(1);
        let mut outbound = EventTranslationService::new("topic");
        let (_, gossip) = outbound.prepare_outbound(event.clone()).unwrap().unwrap();
        let mut inbound = EventTranslationService::new("topic");
        let decoded = inbound.prepare_inbound(gossip).unwrap();
        assert_eq!(decoded.get_data(), event.get_data());
    }

    #[test]
    fn outbound_is_not_final_until_publish_is_confirmed() {
        let mut svc = EventTranslationService::new("topic");
        let event = local_forwardable_event();
        let (id, _) = svc.prepare_outbound(event.clone()).unwrap().unwrap();

        assert!(svc.prepare_outbound(event.clone()).unwrap().is_none());
        svc.mark_failed(id);
        assert!(svc.prepare_outbound(event.clone()).unwrap().is_some());
        svc.mark_published(id);
        assert!(svc.prepare_outbound(event).unwrap().is_none());
    }
}
