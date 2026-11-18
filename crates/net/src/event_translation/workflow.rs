// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::{HashSet, VecDeque},
    time::Instant,
};

use anyhow::Result;
use e3_events::{prelude::*, Event, EventId, EventSource, InterfoldEvent, SeqState, Unsequenced};
use libp2p::PeerId;
use tracing::{debug, trace};

use crate::{
    events::GossipData,
    seen_messages::{Admission, SeenIds},
    NetworkPolicy,
};

const EVENT_DEDUP_CAPACITY: usize = 10_000;
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
            stored_remote: SeenIds::new("stored_event"),
            topic: topic.to_string(),
            network,
        }
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Whether this node gossips `event`: a protocol event that this node created. Gossipsub
    /// relays an event to the whole mesh, so a node never gossips an event from the network again,
    /// such as one that startup fetched from a peer's history: a peer that forgot it would store
    /// another copy.
    pub fn gossips<S: SeqState>(event: &InterfoldEvent<S>) -> bool {
        event.source() == EventSource::Local && event.get_data().is_forwardable()
    }

    /// Returns the gossip to publish for `event`, or `None` when this node does not gossip it or
    /// has already published it.
    pub fn prepare_outbound(
        &mut self,
        event: InterfoldEvent,
    ) -> Result<Option<(EventId, GossipData)>> {
        if !Self::gossips(&event) {
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

    /// Reserve retention before handing a gossip event to the event store. Roll back a rejected
    /// handoff; a later failed append stops the node. Recording here also covers an event that
    /// the EventBus knows from replay and does not deliver again.
    pub fn admit_remote_event(&mut self, peer: Option<PeerId>, id: &EventId, now: Instant) -> bool {
        self.stored_remote.admit(peer, id, now) == Admission::New
    }

    /// Undo a rejected handoff immediately after admission, before any other cache operation.
    pub fn reject_remote_event(&mut self, id: &EventId) {
        self.stored_remote.rollback_latest(id);
    }

    /// Record a protocol event from the peer network that the EventBus delivered, for example
    /// one that historical sync stored. The bus delivers an event only after it is stored. The ID
    /// comes from the payload, because a sync peer supplies the context ID.
    pub fn record_stored_event(&mut self, event: &InterfoldEvent, now: Instant) {
        if event.source() == EventSource::Net && event.get_data().is_forwardable() {
            self.stored_remote
                .admit(None, &EventId::hash(event.get_data()), now);
        }
    }

    /// Decode an inbound gossip payload into the internal event to publish locally.
    pub fn prepare_inbound(&self, data: GossipData) -> Result<InterfoldEvent<Unsequenced>> {
        let event: InterfoldEvent<Unsequenced> = data.try_into()?;
        self.network.validate_peer_event(&event)?;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{
        AggregateId, DkgCoordination, DkgCoordinationKind, DkgDealer, E3id,
        EventConstructorWithTimestamp, EventContext, InterfoldEventData, KeyshareCreated,
        PlaintextAggregated, TestEvent,
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
    fn a_stored_network_event_is_not_admitted_again_within_the_window() {
        let mut svc = EventTranslationService::new("topic");
        let remote = local_forwardable_event().with_source(EventSource::Net);
        let id = remote.event_id();
        let start = Instant::now();
        svc.record_stored_event(&remote, start);
        assert!(!svc.admit_remote_event(None, &id, start + crate::seen_messages::SEEN_TTL / 2));
        assert!(svc.admit_remote_event(None, &id, start + crate::seen_messages::SEEN_TTL));
    }

    #[test]
    fn local_and_non_protocol_events_do_not_block_gossip() {
        let mut svc = EventTranslationService::new("topic");
        let start = Instant::now();
        let local = local_forwardable_event();
        svc.record_stored_event(&local, start);
        assert!(svc.admit_remote_event(None, &local.event_id(), start));
        let internal = local_test_event().with_source(EventSource::Net);
        svc.record_stored_event(&internal, start);
        assert!(svc.admit_remote_event(None, &internal.event_id(), start));
    }

    #[test]
    fn a_mislabeled_stored_event_does_not_block_the_genuine_one() -> Result<()> {
        let mut svc = EventTranslationService::new("topic");
        let genuine = local_forwardable_event();
        let payload: InterfoldEventData = KeyshareCreated {
            pubkey: ArcBytes::from_bytes(&[9]),
            e3_id: E3id::new("1", 1),
            node: "node-2".to_string(),
            party_id: 2,
            signed_pk_generation_proof: None,
        }
        .into();
        // A sync peer labels another event with the ID of the genuine event.
        let context = EventContext::<Unsequenced>::new_origin(
            genuine.event_id(),
            1,
            AggregateId::new(1),
            None,
            EventSource::Net,
        );
        let forged: InterfoldEvent<Unsequenced> =
            GossipData::GossipBytes(bincode::serialize(&(payload, context))?).try_into()?;
        let forged = forged.into_sequenced(1);
        assert_eq!(forged.event_id(), genuine.event_id());

        let now = Instant::now();
        svc.record_stored_event(&forged, now);
        assert!(svc.admit_remote_event(None, &genuine.event_id(), now));
        assert!(!svc.admit_remote_event(None, &EventId::hash(forged.get_data()), now));
        Ok(())
    }

    /// Plaintext results stay on the node that decrypted them.
    #[test]
    fn plaintext_results_are_not_gossiped() {
        let mut svc = EventTranslationService::new("topic");
        assert!(svc
            .prepare_outbound(local_plaintext_event())
            .unwrap()
            .is_none());
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
        assert!(error
            .to_string()
            .contains("TestEvent is not a forwardable protocol event"));
    }

    #[test]
    fn inbound_gossip_accepts_forwardable_protocol_events() {
        let svc = EventTranslationService::new("topic");
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
        let inbound = EventTranslationService::new("topic");
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
