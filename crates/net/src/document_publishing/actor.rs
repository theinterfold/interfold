// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::net_interface_handle::NetEventSubscriber;
use crate::{
    domain::{
        add_candidate, datetime_to_instant_from_now, notification_is_well_formed,
        DocumentPublishingService, FetchQueue, PublicationSchedule,
    },
    events::{
        call_and_await_response, DocumentPublishedNotification, GossipData, NetCommand, NetEvent,
    },
    ContentHash,
};
use actix::prelude::*;
use anyhow::{Context, Result};
use e3_events::{
    prelude::*, trap, BusHandle, CiphernodeSelected, CorrelationId, DocumentReceived, E3Stage,
    E3id, EType, EventSource, EventType, InterfoldEvent, InterfoldEventData, PartyId,
    PublishDocumentRequested, TypedEvent,
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
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tracing::{debug, info};

use super::event_converter::EventConverter;

/// Covers the Kademlia closest-peer lookup and the put that follows it; each has its own query
/// timeout in the network interface.
const KADEMLIA_PUT_TIMEOUT: Duration = Duration::from_secs(150);
const KADEMLIA_GET_TIMEOUT: Duration = Duration::from_secs(90);
const KADEMLIA_BROADCAST_TIMEOUT: Duration = Duration::from_secs(30);
/// The network interface stores a local record without network I/O, but during startup the
/// network event buffer holds the reply until `SyncEnded`. The wait matches the put's, so a
/// recovered publication waits for the end of the sync as quietly as its first upload does.
const DHT_STORE_LOCAL_TIMEOUT: Duration = KADEMLIA_PUT_TIMEOUT;
const MAX_PENDING_PUBLICATIONS: usize = 256;
const MAX_PENDING_PUBLICATION_BYTES: usize = 256 * 1024 * 1024;
const MAX_BUFFERED_NOTIFICATIONS: usize = 1_024;
const MAX_RECEIVED_DOCUMENTS: usize = 8_192;
/// Concurrent document fetches.
const MAX_INFLIGHT_TRANSFERS: usize = 8;
/// Notified documents that wait for a fetch slot or for a retry.
const MAX_WAITING_FETCHES: usize = 512;
/// Interval at which waiting fetches whose retry time has passed are started.
const FETCH_QUEUE_POLL: Duration = Duration::from_secs(5);
/// Concurrent full-document DHT replications. Each one uploads the document to up to 20 peers,
/// so more than one at a time can exceed a home uplink and time every upload out.
const MAX_INFLIGHT_REPLICATIONS: usize = 1;
/// Attempts per replication before the publication waits for its retry backoff.
const DHT_PUT_ATTEMPTS: u32 = 2;
/// Delay before a publication that waits for a replication slot checks again.
const REPLICATION_QUEUE_POLL: Duration = Duration::from_secs(5);

type DocumentId = (E3id, ContentHash);

#[derive(Default)]
pub struct RecoveredDocumentState {
    pub publications: Vec<PublishDocumentRequested>,
    pub received: HashSet<(E3id, ContentHash)>,
    pub closed_e3s: VecDeque<E3id>,
}

/// Store a pending publication in this node's DHT store and gossip its notification.
#[derive(Message)]
#[rtype(result = "()")]
struct AnnounceDocument(DocumentId);

/// Upload a pending publication to the DHT peers closest to its key, when an upload is due.
#[derive(Message)]
#[rtype(result = "()")]
struct ReplicateDocument(DocumentId);

/// A document this node publishes: the request, when it is next announced and uploaded, the
/// announcement and upload in flight, and the next ones while they wait for their delay.
struct Publication {
    event: PublishDocumentRequested,
    schedule: PublicationSchedule,
    announcing: Option<AbortHandle>,
    replicating: Option<AbortHandle>,
    next_announcement: Option<SpawnHandle>,
    next_replication: Option<SpawnHandle>,
}

impl Publication {
    fn new(event: PublishDocumentRequested) -> Self {
        Self {
            event,
            schedule: PublicationSchedule::default(),
            announcing: None,
            replicating: None,
            next_announcement: None,
            next_replication: None,
        }
    }

    fn is_expired(&self) -> bool {
        self.event.meta.expires_at <= chrono::Utc::now()
    }

    /// Stop the announcement and the upload in flight, and cancel the scheduled ones.
    fn stop(&self, ctx: &mut actix::Context<DocumentPublisher>) {
        for handle in [&self.announcing, &self.replicating].into_iter().flatten() {
            handle.abort();
        }
        for timer in [self.next_announcement, self.next_replication]
            .into_iter()
            .flatten()
        {
            ctx.cancel_future(timer);
        }
    }
}

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
    publications: HashMap<DocumentId, Publication>,
    publication_bytes: usize,
    received: HashSet<DocumentId>,
    /// Documents being fetched, with the failed attempts before the current one.
    fetching: HashMap<DocumentId, u32>,
    fetch_queue: FetchQueue,
    fetch_aborts: HashMap<DocumentId, AbortHandle>,
    /// Notifications that arrived while their document was being fetched. They become candidates
    /// for the next fetch if the current one does not deliver the document.
    late_notifications: HashMap<DocumentId, Vec<DocumentPublishedNotification>>,
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
            received: recovered.received,
            fetching: HashMap::new(),
            fetch_queue: FetchQueue::new(MAX_WAITING_FETCHES),
            fetch_aborts: HashMap::new(),
            late_notifications: HashMap::new(),
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
            publisher.publications.insert(id, Publication::new(event));
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

    /// Start the announcement and the upload of a publication.
    fn start_publication(&self, id: &DocumentId, ctx: &mut actix::Context<Self>) {
        ctx.notify(AnnounceDocument(id.clone()));
        ctx.notify(ReplicateDocument(id.clone()));
    }

    /// Announce a publication again after `delay`. It replaces the announcement scheduled before,
    /// so that each publication has one announcement loop.
    fn schedule_announcement(
        &mut self,
        id: DocumentId,
        delay: Duration,
        ctx: &mut actix::Context<Self>,
    ) {
        if let Some(publication) = self.publications.get_mut(&id) {
            let timer = ctx.notify_later(AnnounceDocument(id), delay);
            if let Some(previous) = publication.next_announcement.replace(timer) {
                ctx.cancel_future(previous);
            }
        }
    }

    /// Check a publication's upload again after `delay`. It replaces the check scheduled before,
    /// so that each publication has one upload loop.
    fn schedule_replication(
        &mut self,
        id: DocumentId,
        delay: Duration,
        ctx: &mut actix::Context<Self>,
    ) {
        if let Some(publication) = self.publications.get_mut(&id) {
            let timer = ctx.notify_later(ReplicateDocument(id), delay);
            if let Some(previous) = publication.next_replication.replace(timer) {
                ctx.cancel_future(previous);
            }
        }
    }

    /// The document of a publication that may run effects now. An expired publication is removed.
    fn ready_publication(
        &mut self,
        id: &DocumentId,
        ctx: &mut actix::Context<Self>,
    ) -> Option<PublishDocumentRequested> {
        let publication = self.publications.get(id)?;
        if publication.is_expired() {
            self.remove_publication(id, ctx);
            return None;
        }
        self.effects_enabled.then(|| publication.event.clone())
    }

    fn remove_publication(&mut self, id: &DocumentId, ctx: &mut actix::Context<Self>) {
        if let Some(publication) = self.publications.remove(id) {
            publication.stop(ctx);
            self.publication_bytes = self
                .publication_bytes
                .saturating_sub(publication.event.value.size());
        }
    }

    fn handle_canonical_dkg_end(
        &mut self,
        e3_id: &E3id,
        ctx: &mut actix::Context<Self>,
    ) -> Result<()> {
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
        self.publications.retain(|(id, _), publication| {
            if id == e3_id {
                publication.stop(ctx);
                self.publication_bytes = self
                    .publication_bytes
                    .saturating_sub(publication.event.value.size());
                false
            } else {
                true
            }
        });
        self.received.retain(|(id, _)| id != e3_id);
        self.fetching.retain(|(id, _), _| id != e3_id);
        self.late_notifications.retain(|(id, _), _| id != e3_id);
        self.fetch_queue.remove_e3(e3_id);
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

use effects::{
    announce_stored_document, bind_to_candidate, replicate_document, DocumentMetadataMismatch,
};
pub use effects::{handle_document_published_notification, handle_publish_document_requested};
pub use recovery::recover_document_state;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
