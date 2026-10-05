// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::net_interface_handle::NetEventSubscriber;
use crate::{
    domain::wire::notification_is_valid,
    domain::{
        closed_e3s::record_closed_e3, datetime_to_instant_from_now, Cleanup, CleanupQueue,
        DocumentPublishingService, FetchQueue, PublicationSchedule, RestorableDocuments,
        WaitingFetch,
    },
    events::{
        call_and_await_response, DocumentIngress, DocumentPublishedNotification, GossipData,
        NetCommand, NetEvent,
    },
    ContentHash,
};
use actix::prelude::*;
use anyhow::{Context, Result};
use e3_events::{
    prelude::*, trap, BusHandle, CiphernodeSelected, CorrelationId, DocumentMeta, DocumentReceived,
    E3Stage, E3id, EType, EventSource, EventType, InterfoldEvent, InterfoldEventData, PartyId,
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
use tracing::{debug, info, warn};

use super::event_converter::EventConverter;

/// Longer than the network interface's deadline for a put (240 s), which covers the closest-peer
/// lookup, the upload, and the lookup that checks that another peer serves the record back, so the
/// interface reports every put's result before its caller stops waiting.
const KADEMLIA_PUT_TIMEOUT: Duration = Duration::from_secs(270);
const KADEMLIA_GET_TIMEOUT: Duration = Duration::from_secs(90);
const KADEMLIA_BROADCAST_TIMEOUT: Duration = Duration::from_secs(30);
/// The network interface stores a local record without network I/O, so the reply comes at once
/// unless its command queue is busy. The wait matches the put's.
const DHT_STORE_LOCAL_TIMEOUT: Duration = KADEMLIA_PUT_TIMEOUT;
const MAX_PENDING_PUBLICATIONS: usize = 256;
const MAX_PENDING_PUBLICATION_BYTES: usize = 256 * 1024 * 1024;
/// DHT keys whose cleanup waits for room in the network command queue. A key is 32 bytes, so the
/// queue holds well under 1 MiB.
const MAX_QUEUED_CLEANUPS: usize = 4_096;
const MAX_BUFFERED_NOTIFICATIONS: usize = crate::ingress_limits::EARLY_NOTIFICATIONS;
const MAX_RECEIVED_DOCUMENTS: usize = 8_192;
/// Concurrent document fetches.
const MAX_INFLIGHT_TRANSFERS: usize = 8;
/// Notified documents that wait for a fetch slot or for a retry.
const MAX_WAITING_FETCHES: usize = crate::ingress_limits::WAITING_FETCHES;
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
    /// Received documents to store in this node's DHT store again at `SyncEnded`.
    pub restorable: RestorableDocuments,
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

    /// Stop the announcement and the upload in flight, and cancel the scheduled ones. Returns
    /// whether an upload was in flight: stopping its future does not end its Kademlia query.
    fn stop(&self, ctx: &mut actix::Context<DocumentPublisher>) -> bool {
        for handle in [&self.announcing, &self.replicating].into_iter().flatten() {
            handle.abort();
        }
        for timer in [self.next_announcement, self.next_replication]
            .into_iter()
            .flatten()
        {
            ctx.cancel_future(timer);
        }
        self.replicating.is_some()
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
    /// Whether publications may announce and upload their documents. During startup this turns on
    /// at `SyncEnded`: by then the node has seen the chain history of every E3, so it does not
    /// announce or upload a document of an E3 that ended while the node was offline.
    publishing_enabled: bool,
    publications: HashMap<DocumentId, Publication>,
    publication_bytes: usize,
    /// Cleanup commands that wait for room in the network command queue.
    cleanup: CleanupQueue,
    /// Whether a cleanup command waits for room now. Only one does at a time.
    sending_cleanup: bool,
    received: HashSet<DocumentId>,
    /// Documents being fetched, with the peer charged for each fetch.
    fetching: HashMap<DocumentId, WaitingFetch>,
    fetch_queue: FetchQueue,
    fetch_aborts: HashMap<DocumentId, AbortHandle>,
    early_notifications: VecDeque<DocumentIngress>,
    closed_e3s: VecDeque<E3id>,
    /// Received documents that wait for `SyncEnded` to be stored in this node's DHT store again.
    restorable: RestorableDocuments,
    /// The E3 of the received document being stored again, and whether that E3 closed since.
    restoring: Option<(E3id, bool)>,
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
            publishing_enabled: effects_enabled,
            publications: HashMap::new(),
            publication_bytes: 0,
            cleanup: CleanupQueue::new(MAX_QUEUED_CLEANUPS),
            sending_cleanup: false,
            received: recovered.received,
            fetching: HashMap::new(),
            fetch_queue: FetchQueue::new(MAX_WAITING_FETCHES),
            fetch_aborts: HashMap::new(),
            early_notifications: VecDeque::new(),
            closed_e3s: recovered.closed_e3s,
            restorable: recovered.restorable,
            restoring: None,
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
                    let ingress = match event {
                        NetEvent::DocumentIngress(ingress) => *ingress,
                        NetEvent::GossipData(GossipData::DocumentPublishedNotification(
                            notification,
                        )) => DocumentIngress {
                            propagation_source: None,
                            notification,
                        },
                        _ => continue,
                    };
                    if let Err(error) = addr.send(ingress).await {
                        tracing::warn!(
                            %error,
                            "DocumentPublisher stopped; ending DHT notification ingress"
                        );
                        break;
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
            if notification.notification.meta.e3_id == e3_id {
                ctx.notify(notification);
            } else {
                retained.push_back(notification);
            }
        }
        self.early_notifications = retained;
        Ok(())
    }

    /// Start the announcement and the upload of a publication. An expired publication is removed
    /// instead.
    fn start_publication(&mut self, id: &DocumentId, ctx: &mut actix::Context<Self>) {
        let Some(publication) = self.publications.get(id) else {
            return;
        };
        if publication.is_expired() {
            self.remove_publication(id, ctx);
            return;
        }
        info!(
            e3_id = %id.0,
            key = ?id.1,
            filter = ?publication.event.meta.filter,
            bytes = publication.event.value.size(),
            "Publishing a document"
        );
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
        self.publishing_enabled.then(|| publication.event.clone())
    }

    fn remove_expired_publications(&mut self, ctx: &mut actix::Context<Self>) {
        let expired: Vec<DocumentId> = self
            .publications
            .iter()
            .filter(|(_, publication)| publication.is_expired())
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            self.remove_publication(id, ctx);
        }
    }

    fn remove_publication(&mut self, id: &DocumentId, ctx: &mut actix::Context<Self>) {
        if let Some(publication) = self.publications.remove(id) {
            if publication.stop(ctx) {
                self.queue_cleanup([Cleanup::CancelPut(id.1.clone())], ctx);
            }
            self.publication_bytes = self
                .publication_bytes
                .saturating_sub(publication.event.value.size());
        }
    }

    /// Store the next restorable received document in this node's DHT store. The documents are
    /// stored one at a time, and their keys are pruned with the other records of their E3. A
    /// document that does not fit in a full store is skipped: the restore only makes the node
    /// serve documents again, and the node does not need it to fetch them.
    fn restore_next_received_document(&mut self, ctx: &mut actix::Context<Self>) {
        let Some(DocumentReceived { meta, value }) = self.restorable.pop(chrono::Utc::now()) else {
            return;
        };
        let key = self.service.track_published_key(&meta.e3_id, &value);
        self.restoring = Some((meta.e3_id.clone(), false));
        let (tx, rx) = (self.tx.clone(), self.rx.clone());
        let store = async move { store_document_locally(tx, rx, &meta, &value).await };
        ctx.spawn(store.into_actor(self).map(move |result, actor, ctx| {
            if let Err(error) = result {
                actor.bus.err(EType::IO, error);
            }
            // The E3 closed during the store, maybe before the store command was sent and so
            // before the removal of its records. A failed store can also have stored the record
            // and lost only its reply.
            if let Some((_, true)) = actor.restoring.take() {
                actor.queue_cleanup([Cleanup::RemoveRecord(key)], ctx);
            }
            actor.restore_next_received_document(ctx);
        }));
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
        record_closed_e3(&mut self.closed_e3s, e3_id);
        let keys = self.service.complete_e3(e3_id);
        let closed: Vec<DocumentId> = self
            .publications
            .keys()
            .filter(|(id, _)| id == e3_id)
            .cloned()
            .collect();
        for id in &closed {
            self.remove_publication(id, ctx);
        }
        self.received.retain(|(id, _)| id != e3_id);
        self.fetching.retain(|(id, _), _| id != e3_id);
        self.fetch_queue.remove_e3(e3_id);
        self.restorable.remove_e3(e3_id);
        if let Some((restoring, closed)) = &mut self.restoring {
            *closed |= restoring == e3_id;
        }
        self.early_notifications
            .retain(|item| &item.notification.meta.e3_id != e3_id);
        if !keys.is_empty() {
            info!(
                "Pruning {} DHT records for completed E3 {}",
                keys.len(),
                e3_id
            );
            self.queue_cleanup(keys.into_iter().map(Cleanup::RemoveRecord), ctx);
        }
        Ok(())
    }

    /// Queue network cleanup and send it in order. One send at a time waits for room in a busy
    /// command queue, so the wait holds no task per command, and a full cleanup queue drops its
    /// oldest entries.
    fn queue_cleanup(
        &mut self,
        cleanups: impl IntoIterator<Item = Cleanup>,
        ctx: &mut actix::Context<Self>,
    ) {
        let mut dropped = 0;
        for cleanup in cleanups {
            dropped += usize::from(self.cleanup.push(cleanup));
        }
        if dropped > 0 {
            warn!(
                "The network command queue is busy: dropped the {} oldest DHT cleanups. Their \
                 records expire and their puts time out on their own.",
                dropped
            );
        }
        self.send_next_cleanup(ctx);
    }

    fn send_next_cleanup(&mut self, ctx: &mut actix::Context<Self>) {
        if self.sending_cleanup {
            return;
        }
        let Some(command) = self.cleanup.next_command() else {
            return;
        };
        self.sending_cleanup = true;
        let tx = self.tx.clone();
        let send = async move { tx.send(command).await.is_ok() };
        ctx.spawn(send.into_actor(self).map(|sent, actor, ctx| {
            actor.sending_cleanup = false;
            if sent {
                actor.send_next_cleanup(ctx);
            } else {
                let dropped = actor.cleanup.clear();
                debug!(
                    "The network interface stopped: dropped {} more DHT cleanups",
                    dropped
                );
            }
        }));
    }
}

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;
#[path = "recovery.rs"]
mod recovery;

use effects::{
    announce_stored_document, bind_to_candidate, replicate_document, store_document_locally,
    DocumentMetadataMismatch,
};
pub use effects::{handle_document_published_notification, handle_publish_document_requested};
pub use recovery::recover_document_state;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
