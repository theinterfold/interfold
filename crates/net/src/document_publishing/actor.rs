// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::net_interface_handle::NetEventSubscriber;
use crate::{
    domain::{datetime_to_instant_from_now, DocumentPublishingService},
    events::{
        call_and_await_response, DocumentPublishedNotification, GossipData, NetCommand, NetEvent,
    },
    ContentHash,
};
use actix::prelude::*;
use anyhow::{Context, Result};
use e3_events::{
    prelude::*, trap, trap_fut, BusHandle, CiphernodeSelected, CorrelationId, DocumentReceived,
    E3Stage, E3id, EType, EventSource, EventType, InterfoldEvent, InterfoldEventData,
    LbfvKeyShareDocumentFetchRequested, PartyId, PublishDocumentRequested, TypedEvent,
};
use e3_utils::ArcBytes;
use e3_utils::NotifySync;
use e3_utils::{
    retry::{retry_with_backoff, to_retry},
    MAILBOX_LIMIT,
};
use futures::{future::AbortHandle, TryFutureExt};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::{debug, info};

use super::event_converter::EventConverter;

const KADEMLIA_PUT_TIMEOUT: Duration = Duration::from_secs(30);
const KADEMLIA_GET_TIMEOUT: Duration = Duration::from_secs(30);
const KADEMLIA_BROADCAST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PENDING_PUBLICATIONS: usize = 256;
const MAX_PENDING_PUBLICATION_BYTES: usize = 256 * 1024 * 1024;
const MAX_BUFFERED_NOTIFICATIONS: usize = 1_024;
const MAX_RECEIVED_DOCUMENTS: usize = 8_192;
const MAX_INFLIGHT_TRANSFERS: usize = 8;
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_secs(15);

type DocumentId = (E3id, ContentHash);

#[derive(Default)]
pub struct RecoveredDocumentState {
    pub publications: Vec<PublishDocumentRequested>,
    pub received: HashSet<(E3id, ContentHash)>,
    pub closed_e3s: VecDeque<E3id>,
}

#[derive(Message)]
#[rtype(result = "()")]
struct AnnounceDocument(DocumentId);

/// DocumentPublisher is an actor that monitors events from both the Libp2pNetInterface and the
/// Interfold EventBus in order to manage document publishing interactions. The decision/state logic
/// lives in [`DocumentPublishingService`]; this actor only wires events to that service and
/// performs the resulting libp2p/Kademlia I/O.
pub struct DocumentPublisher {
    /// Interfold EventBus
    bus: BusHandle,
    /// NetCommand sender to forward commands to the Libp2pNetInterface
    tx: mpsc::Sender<NetCommand>,
    /// Subscriber used to open a fresh NetEvent receiver per publish operation.
    rx: NetEventSubscriber,
    /// The gossipsub broadcast topic
    topic: String,
    /// Pure decision/state service.
    service: DocumentPublishingService,
    effects_enabled: bool,
    publications: HashMap<DocumentId, PublishDocumentRequested>,
    publication_bytes: usize,
    publishing: HashSet<DocumentId>,
    publish_aborts: HashMap<DocumentId, AbortHandle>,
    received: HashSet<DocumentId>,
    fetching: HashSet<DocumentId>,
    fetch_aborts: HashMap<DocumentId, AbortHandle>,
    early_notifications: VecDeque<DocumentPublishedNotification>,
    closed_e3s: VecDeque<E3id>,
}

impl DocumentPublisher {
    /// Create a new DocumentPublisher actor
    pub fn new(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
    ) -> Self {
        Self::new_with_interests(bus, tx, rx, topic, HashMap::new())
    }

    pub fn new_with_interests(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
        interests: HashMap<E3id, PartyId>,
    ) -> Self {
        Self::new_with_interests_and_effects(
            bus,
            tx,
            rx,
            topic,
            interests,
            true,
            RecoveredDocumentState::default(),
        )
    }

    fn new_with_interests_and_effects(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
        interests: HashMap<E3id, PartyId>,
        effects_enabled: bool,
        recovered: RecoveredDocumentState,
    ) -> Self {
        let service = if interests.is_empty() {
            DocumentPublishingService::new()
        } else {
            DocumentPublishingService::with_interests(interests)
        };
        let mut publisher = Self {
            bus: bus.clone(),
            tx: tx.clone(),
            rx: rx.clone(),
            topic: topic.into(),
            service,
            effects_enabled,
            publications: HashMap::new(),
            publication_bytes: 0,
            publishing: HashSet::new(),
            publish_aborts: HashMap::new(),
            received: recovered.received,
            fetching: HashSet::new(),
            fetch_aborts: HashMap::new(),
            early_notifications: VecDeque::new(),
            closed_e3s: recovered.closed_e3s,
        };
        for event in recovered.publications {
            let id = (
                event.meta.e3_id.clone(),
                ContentHash::from_content(&event.value),
            );
            publisher.publication_bytes = publisher
                .publication_bytes
                .saturating_add(event.value.size());
            publisher.service.track_published_key(&id.0, &event.value);
            publisher.publications.insert(id, event);
        }
        publisher
    }

    /// This is needed to create simulation libp2p event routers
    pub fn is_document_publisher_event(event: &InterfoldEvent) -> bool {
        // Add a list of events with paylods for the DHT
        matches!(
            event.get_data(),
            InterfoldEventData::PublishDocumentRequested(_)
                | InterfoldEventData::ThresholdShareCreated(_)
                | InterfoldEventData::EncryptionKeyCreated(_)
                | InterfoldEventData::DecryptionKeyShared(_)
                | InterfoldEventData::LbfvKeyShareDocumentCreated(_)
                | InterfoldEventData::LbfvKeyShareDocumentFetchRequested(_)
        )
    }

    /// Setup the DocumentPublisher and start listening for GossipEvents
    pub fn setup(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
    ) -> Addr<Self> {
        Self::setup_with_interests(bus, tx, rx, topic, HashMap::new())
    }

    pub fn setup_with_interests(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
        interests: HashMap<E3id, PartyId>,
    ) -> Addr<Self> {
        Self::setup_with_effects(
            bus,
            tx,
            rx,
            topic,
            interests,
            true,
            RecoveredDocumentState::default(),
        )
    }

    pub fn setup_before_effects(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
        interests: HashMap<E3id, PartyId>,
        recovered: RecoveredDocumentState,
    ) -> Addr<Self> {
        Self::setup_with_effects(bus, tx, rx, topic, interests, false, recovered)
    }

    fn setup_with_effects(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
        interests: HashMap<E3id, PartyId>,
        effects_enabled: bool,
        recovered: RecoveredDocumentState,
    ) -> Addr<Self> {
        let mut events = rx.subscribe();
        let addr = Self::new_with_interests_and_effects(
            bus,
            tx,
            rx,
            topic,
            interests,
            effects_enabled,
            recovered,
        )
        .start();
        if effects_enabled {
            EventConverter::setup(bus);
        }
        // Listen on all events
        bus.subscribe(EventType::All, addr.clone().recipient());

        // Forward gossip data from NetEvent
        tokio::spawn({
            debug!("Spawning event receive loop!");
            let addr = addr.clone();
            async move {
                while let Some(event) =
                    crate::event_subscription::recv_net_event(&mut events, "DocumentPublisher")
                        .await
                {
                    debug!("Received event {:?}", event);
                    if let NetEvent::GossipData(GossipData::DocumentPublishedNotification(data)) =
                        event
                    {
                        if let Err(error) = addr.send(data).await {
                            tracing::warn!(
                                %error,
                                "DocumentPublisher stopped; ending DHT notification ingress"
                            );
                            break;
                        }
                    }
                }
            }
        });

        addr
    }

    fn handle_ciphernode_selected(
        &mut self,
        event: CiphernodeSelected,
        ctx: &mut actix::Context<Self>,
    ) -> Result<()> {
        let CiphernodeSelected {
            e3_id, party_id, ..
        } = event;
        if self.closed_e3s.contains(&e3_id) {
            return Ok(());
        }
        self.service.register_interest(e3_id.clone(), party_id);
        let mut retained = VecDeque::new();
        while let Some(notification) = self.early_notifications.pop_front() {
            if notification.meta.e3_id == e3_id {
                ctx.notify(notification);
            } else {
                retained.push_back(notification);
            }
        }
        self.early_notifications = retained;
        Ok(())
    }

    fn handle_canonical_dkg_end(&mut self, e3_id: &E3id) -> Result<()> {
        for (id, abort) in &self.publish_aborts {
            if &id.0 == e3_id {
                abort.abort();
            }
        }
        for (id, abort) in &self.fetch_aborts {
            if &id.0 == e3_id {
                abort.abort();
            }
        }
        if !self.closed_e3s.contains(e3_id) {
            if self.closed_e3s.len() == MAX_BUFFERED_NOTIFICATIONS {
                self.closed_e3s.pop_front();
            }
            self.closed_e3s.push_back(e3_id.clone());
        }
        let keys = self.service.complete_e3(e3_id);
        self.publications.retain(|(id, _), event| {
            if id == e3_id {
                self.publication_bytes = self.publication_bytes.saturating_sub(event.value.size());
                false
            } else {
                true
            }
        });
        self.publishing.retain(|(id, _)| id != e3_id);
        self.received.retain(|(id, _)| id != e3_id);
        self.fetching.retain(|(id, _)| id != e3_id);
        self.early_notifications
            .retain(|item| &item.meta.e3_id != e3_id);
        if !keys.is_empty() {
            info!(
                "Pruning {} DHT records for completed E3 {}",
                keys.len(),
                e3_id
            );
            let _ = self.tx.try_send(NetCommand::DhtRemoveRecords { keys });
        }
        Ok(())
    }
}

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;
#[path = "recovery.rs"]
mod recovery;

pub use effects::{
    handle_document_published_notification, handle_lbfv_document_fetch_requested,
    handle_publish_document_requested,
};
pub use recovery::recover_document_state;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
