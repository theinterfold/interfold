// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_events::{Event, EventId, InterfoldEvent, InterfoldEventData, SeqState};
use std::collections::{HashSet, VecDeque};
use tracing::{trace, warn};

use crate::events::GossipData;
use crate::{NetworkAuthorizationState, ProtocolAdmission, ProtocolSigner};

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
    admission: ProtocolAdmission,
}

const SENT_EVENT_DEDUP_CAPACITY: usize = 10_000;

impl EventTranslationService {
    pub fn new(topic: &str, authorization: NetworkAuthorizationState) -> Self {
        Self {
            sent_events: HashSet::new(),
            sent_order: VecDeque::new(),
            dedup_capacity: SENT_EVENT_DEDUP_CAPACITY,
            topic: topic.to_string(),
            admission: ProtocolAdmission::new(authorization),
        }
    }

    pub fn observe(&mut self, event: &InterfoldEvent) {
        self.admission.observe(event);
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
    pub fn prepare_outbound(
        &self,
        event: InterfoldEvent,
        signer: &ProtocolSigner,
    ) -> Result<Option<(EventId, GossipData)>> {
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
        self.admission
            .authorize_local_event(signer.address(), &event)?;
        let data = GossipData::ProtocolEvent(signer.sign_event(event)?);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use e3_events::{
        AggregatorLeaseUpdated, AggregatorPhase, Committee, E3id, EventConstructorWithTimestamp,
        EventSource, PlaintextAggregated, TestEvent, Unsequenced,
    };
    use e3_utils::ArcBytes;
    use libp2p::PeerId;
    use std::collections::HashMap;

    fn protocol_fixture(e3_id: &E3id) -> (ProtocolSigner, NetworkAuthorizationState) {
        let signer = PrivateKeySigner::random();
        let protocol_signer = ProtocolSigner::new(signer.clone(), PeerId::random());
        let authorization = NetworkAuthorizationState::new(
            HashMap::from([(
                e3_id.clone(),
                Committee::new(vec![signer.address().to_string()]),
            )]),
            HashMap::new(),
        );
        (protocol_signer, authorization)
    }

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
    fn chain_derived_failover_leases_are_never_gossip_admissible() {
        let event: InterfoldEvent<Unsequenced> = InterfoldEvent::new_with_timestamp(
            AggregatorLeaseUpdated {
                e3_id: E3id::new("1", 7),
                phase: AggregatorPhase::AwaitingPublicKey,
                stage_deadline: 1_000,
            }
            .into(),
            None,
            42,
            None,
            EventSource::Local,
        );
        assert!(!EventTranslationService::is_forwardable_event(&event));
    }

    #[test]
    fn test_events_are_not_forwardable() {
        assert!(!EventTranslationService::is_forwardable_event(
            &local_test_event()
        ));
    }

    #[test]
    fn non_forwardable_events_produce_no_gossip() {
        let (signer, authorization) = protocol_fixture(&E3id::new("1", 1));
        let svc = EventTranslationService::new("topic", authorization);
        assert!(svc
            .prepare_outbound(local_test_event(), &signer)
            .unwrap()
            .is_none());
    }

    #[test]
    fn outbound_dedup_advances_only_after_acceptance() {
        let event = local_forwardable_event();
        let (signer, authorization) = protocol_fixture(&event.get_e3_id().unwrap());
        let mut svc = EventTranslationService::new("topic", authorization);
        let (id, _) = svc
            .prepare_outbound(event.clone(), &signer)
            .unwrap()
            .unwrap();

        assert!(svc
            .prepare_outbound(event.clone(), &signer)
            .unwrap()
            .is_some());
        svc.mark_accepted(id);
        assert!(svc.prepare_outbound(event, &signer).unwrap().is_none());
    }
}
