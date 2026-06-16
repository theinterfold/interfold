// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    domain::{
        datetime_to_instant_from_now, DocumentPublishingService, EventConversionService,
        IncomingDocument,
    },
    events::{
        call_and_await_response, DocumentPublishedNotification, GossipData, NetCommand, NetEvent,
    },
    ContentHash,
};
use actix::prelude::*;
use anyhow::Result;
use e3_events::{
    prelude::*, trap, trap_fut, BusHandle, CiphernodeSelected, CorrelationId, DecryptionKeyShared,
    DocumentReceived, E3RequestComplete, E3id, EType, EncryptionKeyCreated, EventSource, EventType,
    InterfoldEvent, InterfoldEventData, PartyId, PublishDocumentRequested, ThresholdShareCreated,
    TypedEvent,
};
use e3_utils::ArcBytes;
use e3_utils::NotifySync;
use e3_utils::{
    retry::{retry_with_backoff, to_retry},
    MAILBOX_LIMIT,
};
use futures::TryFutureExt;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info};

const KADEMLIA_PUT_TIMEOUT: Duration = Duration::from_secs(30);
const KADEMLIA_GET_TIMEOUT: Duration = Duration::from_secs(30);
const KADEMLIA_BROADCAST_TIMEOUT: Duration = Duration::from_secs(30);

/// DocumentPublisher is an actor that monitors events from both the Libp2pNetInterface and the
/// Interfold EventBus in order to manage document publishing interactions. The decision/state logic
/// lives in [`DocumentPublishingService`]; this actor only wires events to that service and
/// performs the resulting libp2p/Kademlia I/O.
pub struct DocumentPublisher {
    /// Interfold EventBus
    bus: BusHandle,
    /// NetCommand sender to forward commands to the Libp2pNetInterface
    tx: mpsc::Sender<NetCommand>,
    /// NetEvent receiver to resubscribe for events from the Libp2pNetInterface. This is in an Arc
    /// so that we do not do excessive resubscribes without actually listening for events.
    rx: Arc<broadcast::Receiver<NetEvent>>,
    /// The gossipsub broadcast topic
    topic: String,
    /// Pure decision/state service.
    service: DocumentPublishingService,
}

impl DocumentPublisher {
    /// Create a new DocumentPublisher actor
    pub fn new(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &Arc<broadcast::Receiver<NetEvent>>,
        topic: impl Into<String>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            tx: tx.clone(),
            rx: rx.clone(),
            topic: topic.into(),
            service: DocumentPublishingService::new(),
        }
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
        rx: &Arc<broadcast::Receiver<NetEvent>>,
        topic: impl Into<String>,
    ) -> Addr<Self> {
        let mut events = rx.resubscribe();
        let addr = Self::new(bus, tx, rx, topic).start();
        EventConverter::setup(bus);
        // Listen on all events
        bus.subscribe(EventType::All, addr.clone().recipient());

        // Forward gossip data from NetEvent
        tokio::spawn({
            debug!("Spawning event receive loop!");
            let addr = addr.clone();
            async move {
                while let Ok(event) = events.recv().await {
                    debug!("Received event {:?}", event);
                    if let NetEvent::GossipData(GossipData::DocumentPublishedNotification(data)) =
                        event
                    {
                        addr.do_send(data)
                    }
                }
            }
        });

        addr
    }

    fn handle_ciphernode_selected(&mut self, event: CiphernodeSelected) -> Result<()> {
        let CiphernodeSelected {
            e3_id, party_id, ..
        } = event;
        self.service.register_interest(e3_id, party_id);
        Ok(())
    }

    fn handle_e3_request_complete(&mut self, event: E3RequestComplete) -> Result<()> {
        let keys = self.service.complete_e3(&event.e3_id);
        if !keys.is_empty() {
            info!(
                "Pruning {} DHT records for completed E3 {}",
                keys.len(),
                event.e3_id
            );
            let _ = self.tx.try_send(NetCommand::DhtRemoveRecords { keys });
        }
        Ok(())
    }
}

impl Actor for DocumentPublisher {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl Handler<InterfoldEvent> for DocumentPublisher {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::PublishDocumentRequested(data) => {
                ctx.notify(TypedEvent::new(data, ec))
            }
            InterfoldEventData::CiphernodeSelected(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3RequestComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<PublishDocumentRequested>> for DocumentPublisher {
    type Result = ResponseFuture<()>;
    fn handle(
        &mut self,
        msg: TypedEvent<PublishDocumentRequested>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let tx = self.tx.clone();
        let (msg, ec) = msg.into_components();

        self.service
            .track_published_key(&msg.meta.e3_id, &msg.value);

        let rx = self.rx.clone();
        let bus = self.bus.clone();
        let topic = self.topic.clone();
        trap_fut(
            EType::IO,
            &bus.with_ec(&ec),
            handle_publish_document_requested(tx, rx, msg, topic, bus),
        )
    }
}

impl Handler<TypedEvent<CiphernodeSelected>> for DocumentPublisher {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<CiphernodeSelected>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::DocumentPublishing, &self.bus.with_ec(&ec), || {
            self.handle_ciphernode_selected(msg)
        })
    }
}

impl Handler<TypedEvent<E3RequestComplete>> for DocumentPublisher {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<E3RequestComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::DocumentPublishing, &self.bus.with_ec(&ec), || {
            self.handle_e3_request_complete(msg)
        })
    }
}

/// Receiving DocumentPublishedNotification from libp2p
impl Handler<DocumentPublishedNotification> for DocumentPublisher {
    type Result = ResponseFuture<()>;
    fn handle(
        &mut self,
        msg: DocumentPublishedNotification,
        _: &mut Self::Context,
    ) -> Self::Result {
        let ids = self.service.interest_snapshot();
        let bus = self.bus.clone();
        let tx = self.tx.clone();
        let rx = self.rx.clone();
        trap_fut(
            EType::IO,
            &bus,
            handle_document_published_notification(tx, rx, bus.clone(), ids, msg),
        )
    }
}

/// Called when we receive a PublishDocumentRequested event
pub async fn handle_publish_document_requested(
    tx: mpsc::Sender<NetCommand>,
    rx: Arc<broadcast::Receiver<NetEvent>>,
    event: PublishDocumentRequested,
    topic: impl Into<String>,
    bus: BusHandle,
) -> Result<()> {
    let value = event.value;
    let key = ContentHash::from_content(&value);
    let expires = datetime_to_instant_from_now(event.meta.expires_at);

    retry_with_backoff(
        || {
            put_record(tx.clone(), rx.clone(), expires, value.clone(), key.clone())
                .map_err(to_retry)
        },
        4,
        1000,
    )
    .await?;
    let notification = DocumentPublishedNotification::new(event.meta, key, bus.ts()?);
    broadcast_document_published_notification(tx, rx, notification, topic).await?;
    Ok(())
}

/// Called when we receive a notification from the net_interface
pub async fn handle_document_published_notification(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: Arc<broadcast::Receiver<NetEvent>>,
    bus: BusHandle,
    ids: HashMap<E3id, PartyId>,
    event: DocumentPublishedNotification,
) -> Result<()> {
    let Some(party_id) = DocumentPublishingService::interest_in(&ids, &event) else {
        debug!("Node not interested in id {}", event.meta.e3_id);
        return Ok(());
    };

    debug!(
        "interested in document {:?} with party_id={:?}",
        event, party_id
    );

    let value = retry_with_backoff(
        || get_record(net_cmds.clone(), net_events.clone(), event.key.clone()).map_err(to_retry),
        4,
        1000,
    )
    .await?;

    debug!("Sending received event...");
    bus.publish_from_remote(
        DocumentReceived {
            meta: event.meta,
            value,
        },
        event.ts,
        None,
        EventSource::Net,
    )?;

    Ok(())
}

/// Call DhtPutRecord Command on the Libp2pNetInterface and handle the results
async fn put_record(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: Arc<broadcast::Receiver<NetEvent>>,
    expires: Option<std::time::Instant>,
    value: ArcBytes,
    key: ContentHash,
) -> Result<()> {
    let id = CorrelationId::new();
    call_and_await_response(
        net_cmds,
        net_events,
        NetCommand::DhtPutRecord {
            correlation_id: id,
            expires,
            value,
            key,
        },
        |event| match event {
            NetEvent::DhtPutRecordSucceeded { .. } => Some(Ok(())),
            NetEvent::DhtPutRecordError { error, .. } => {
                Some(Err(anyhow::anyhow!("DHT put record failed: {:?}", error)))
            }
            _ => None,
        },
        KADEMLIA_PUT_TIMEOUT,
    )
    .await
}

/// Call DhtGetRecord Command on the Libp2pNetInterface and handle the results
async fn get_record(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: Arc<broadcast::Receiver<NetEvent>>,
    key: ContentHash,
) -> Result<ArcBytes> {
    let id = CorrelationId::new();
    call_and_await_response(
        net_cmds,
        net_events,
        NetCommand::DhtGetRecord {
            correlation_id: id,
            key,
        },
        |event| match event {
            NetEvent::DhtGetRecordSucceeded { value, .. } => Some(Ok(value.clone())),
            NetEvent::DhtGetRecordError { error, .. } => {
                Some(Err(anyhow::anyhow!("DHT get record failed: {:?}", error)))
            }
            _ => None,
        },
        KADEMLIA_GET_TIMEOUT,
    )
    .await
}

/// Broadcasts document published notification on Libp2pNetInterface
async fn broadcast_document_published_notification(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: Arc<broadcast::Receiver<NetEvent>>,
    payload: DocumentPublishedNotification,
    topic: impl Into<String>,
) -> Result<()> {
    let id = CorrelationId::new();
    call_and_await_response(
        net_cmds,
        net_events,
        NetCommand::GossipPublish {
            topic: topic.into(),
            correlation_id: id,
            data: GossipData::DocumentPublishedNotification(payload),
        },
        |event| match event {
            NetEvent::GossipPublished { .. } => Some(Ok(())),
            NetEvent::GossipPublishError { error, .. } => {
                Some(Err(anyhow::anyhow!("GossipPublished failed: {:?}", error)))
            }
            _ => None,
        },
        KADEMLIA_BROADCAST_TIMEOUT,
    )
    .await
}

/// Converts between internal events and network documents.
///
/// Responsibilities:
/// - Outgoing: Converts ThresholdShareCreated → party-filtered PublishDocumentRequested
/// - Incoming: Converts DocumentReceived → ThresholdShareCreated/EncryptionKeyCreated
///
/// The conversion logic lives in [`EventConversionService`]; this actor only publishes the
/// resulting events on the bus.
pub struct EventConverter {
    bus: BusHandle,
}

impl EventConverter {
    pub fn new(bus: &BusHandle) -> Self {
        Self { bus: bus.clone() }
    }

    pub fn setup(bus: &BusHandle) -> Addr<Self> {
        let addr = Self::new(bus).start();
        bus.subscribe(EventType::ThresholdShareCreated, addr.clone().into());
        bus.subscribe(EventType::EncryptionKeyCreated, addr.clone().into());
        bus.subscribe(EventType::DecryptionKeyShared, addr.clone().into());
        bus.subscribe(EventType::DocumentReceived, addr.clone().into());
        addr
    }

    fn handle_threshold_share_created(&self, msg: TypedEvent<ThresholdShareCreated>) -> Result<()> {
        let (msg, ctx) = msg.into_components();
        if let Some(request) = EventConversionService::threshold_share_to_request(msg)? {
            self.bus.publish(request, ctx)?;
        }
        Ok(())
    }

    fn handle_encryption_key_created(&self, msg: TypedEvent<EncryptionKeyCreated>) -> Result<()> {
        let (msg, ctx) = msg.into_components();
        if let Some(request) = EventConversionService::encryption_key_to_request(msg)? {
            self.bus.publish(request, ctx)?;
        }
        Ok(())
    }

    fn handle_decryption_key_shared(&self, msg: TypedEvent<DecryptionKeyShared>) -> Result<()> {
        let (msg, ctx) = msg.into_components();
        if let Some(request) = EventConversionService::decryption_key_to_request(msg)? {
            self.bus.publish(request, ctx)?;
        }
        Ok(())
    }

    /// Convert received document to internal events.
    /// Note: Filtering already happened in DocumentPublisher before DHT fetch.
    fn handle_document_received(&self, msg: TypedEvent<DocumentReceived>) -> Result<()> {
        let (msg, ctx) = msg.into_components();
        match EventConversionService::decode_received(&msg.value.extract_bytes())? {
            IncomingDocument::ThresholdShare(evt) => {
                self.bus.publish(evt, ctx)?;
            }
            IncomingDocument::EncryptionKey(evt) => {
                self.bus.publish(evt, ctx)?;
            }
            IncomingDocument::DecryptionKey(evt) => {
                self.bus.publish(evt, ctx)?;
            }
        }
        Ok(())
    }
}

impl Actor for EventConverter {
    type Context = actix::Context<Self>;
}

impl Handler<InterfoldEvent> for EventConverter {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (data, ec) = msg.into_components();
        match data {
            InterfoldEventData::ThresholdShareCreated(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::EncryptionKeyCreated(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DecryptionKeyShared(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DocumentReceived(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<ThresholdShareCreated>> for EventConverter {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ThresholdShareCreated>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::DocumentPublishing,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_threshold_share_created(msg),
        )
    }
}

impl Handler<TypedEvent<EncryptionKeyCreated>> for EventConverter {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<EncryptionKeyCreated>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::DocumentPublishing,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_encryption_key_created(msg),
        )
    }
}

impl Handler<TypedEvent<DecryptionKeyShared>> for EventConverter {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<DecryptionKeyShared>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::DocumentPublishing,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_decryption_key_shared(msg),
        )
    }
}

impl Handler<TypedEvent<DocumentReceived>> for EventConverter {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<DocumentReceived>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::DocumentPublishing,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_document_received(msg),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, num::NonZero, time::Duration};

    use super::*;
    use crate::events::NetCommand;
    use actix::Addr;
    use anyhow::{bail, Result};
    use chrono::Utc;
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{
        BusHandle, CiphernodeSelected, DocumentKind, DocumentMeta, E3id, GetEvents,
        HistoryCollector, InterfoldError, InterfoldEvent, PublishDocumentRequested, TakeEvents,
    };
    use libp2p::kad::{GetRecordError, PutRecordError, RecordKey};
    use std::time::Instant;
    use tokio::{
        sync::{broadcast, mpsc},
        time::{sleep, timeout},
    };
    use tracing::subscriber::DefaultGuard;

    #[allow(clippy::type_complexity)]
    fn setup_test() -> Result<(
        DefaultGuard,
        BusHandle,
        mpsc::Sender<NetCommand>,
        mpsc::Receiver<NetCommand>,
        broadcast::Sender<NetEvent>,
        Arc<broadcast::Receiver<NetEvent>>,
        Addr<HistoryCollector<InterfoldEvent>>,
        Addr<HistoryCollector<InterfoldEvent>>,
        Addr<DocumentPublisher>,
    )> {
        use tracing_subscriber::{fmt, EnvFilter};

        let subscriber = fmt()
            .with_env_filter(EnvFilter::new("debug"))
            .with_test_writer()
            .finish();

        let guard = tracing::subscriber::set_default(subscriber);

        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("test");
        let (net_cmd_tx, net_cmd_rx) = mpsc::channel(100);
        let (net_evt_tx, net_evt_rx) = broadcast::channel(100);
        let net_evt_rx = Arc::new(net_evt_rx);
        let history = HistoryCollector::<InterfoldEvent>::new().start();
        let error = HistoryCollector::<InterfoldEvent>::new().start();
        bus.subscribe(EventType::All, history.clone().recipient());
        bus.subscribe(EventType::InterfoldError, error.clone().recipient());
        let publisher = DocumentPublisher::setup(&bus, &net_cmd_tx, &net_evt_rx, "topic");

        Ok((
            guard, bus, net_cmd_tx, net_cmd_rx, net_evt_tx, net_evt_rx, history, error, publisher,
        ))
    }

    #[actix::test]
    async fn test_publishes_document() -> Result<()> {
        let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _net_evt_rx, _, _, _) =
            setup_test()?;
        let value = ArcBytes::from_bytes(b"I am a special document");
        let expires_at = Some(Utc::now() + chrono::Duration::days(1));
        let e3_id = E3id::new("1243", 1);

        // 1. Send a request to publish
        bus.publish_without_context(PublishDocumentRequested {
            meta: DocumentMeta::new(e3_id, DocumentKind::TrBFV, vec![], expires_at),
            value: value.clone(),
        })?;

        // 2. Document publisher should have asked the Libp2pNetInterface to put the doc on Kademlia
        let Some(NetCommand::DhtPutRecord {
            correlation_id,
            expires,
            value: msg_value,
            key,
        }) = timeout(Duration::from_secs(1), net_cmd_rx.recv())
            .await
            .expect("did not receive DhtPutRecord")
        else {
            bail!("msg not as expected");
        };

        // Fake DHT put the record
        let mut mykad: HashMap<ContentHash, Vec<u8>> = HashMap::new();
        mykad.insert(key.clone(), msg_value.extract_bytes());

        // 3. Report that everything went well
        net_evt_tx.send(NetEvent::DhtPutRecordSucceeded {
            correlation_id,
            key,
        })?;

        // 4. Expect a DocumentPublishedNotification to have been emitted
        let Some(NetCommand::GossipPublish {
            topic,
            correlation_id,
            data: GossipData::DocumentPublishedNotification(notification),
            ..
        }) = timeout(Duration::from_secs(1), net_cmd_rx.recv())
            .await
            .expect("did not receive GossipPublish")
        else {
            bail!("msg not as expected");
        };

        // 5. Report everything went well
        net_evt_tx.send(NetEvent::GossipPublished {
            correlation_id,
            message_id: libp2p::gossipsub::MessageId::new(&[1, 2, 3]),
        })?;

        assert_eq!(topic, "topic");
        assert_eq!(notification.meta.e3_id, E3id::new("1243", 1));

        assert_eq!(
            mykad.get(&notification.key),
            Some(&b"I am a special document".to_vec()),
            "value was not correct"
        );

        assert!(
            is_between(expires.unwrap(), days_from_now(0), days_from_now(1)),
            "Expiry was not set"
        );

        Ok(())
    }
    #[actix::test]
    async fn test_get_document_fails_with_exponential_backoff() -> Result<()> {
        let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _net_evt_rx, _, errors, _) =
            setup_test()?;

        let value = b"I am a special document".to_vec();
        let expires_at = Some(Utc::now() + chrono::Duration::days(1));
        let e3_id = E3id::new("1243", 1);
        let cid = ContentHash::from_content(&value);

        // 1. Ensure the publisher is interested in the id by receiving CiphernodeSelected
        bus.publish_without_context(CiphernodeSelected {
            e3_id: e3_id.clone(),
            threshold_m: 3,
            threshold_n: 5,
            ..CiphernodeSelected::default()
        })?;

        net_evt_tx.send(NetEvent::GossipData(
            GossipData::DocumentPublishedNotification(DocumentPublishedNotification {
                key: cid.clone(),
                meta: DocumentMeta::new(e3_id, DocumentKind::TrBFV, vec![], expires_at),
                ts: 123,
            }),
        ))?;

        for _ in 0..4 {
            // Expect retry
            let Some(NetCommand::DhtGetRecord { correlation_id, .. }) =
                timeout(Duration::from_secs(15), net_cmd_rx.recv())
                    .await
                    .expect("did not receive DhtGetRecord")
            else {
                bail!("msg not as expected");
            };

            // Report failure
            net_evt_tx.send(NetEvent::DhtGetRecordError {
                correlation_id,
                error: GetRecordError::Timeout {
                    key: RecordKey::new(&cid),
                },
            })?;
        }

        // wait for events to settle
        let errors = errors.send(TakeEvents::new(1)).await?;
        let error: InterfoldError = errors.events.first().unwrap().try_into()?;
        assert_eq!(
            error.message,
            "Operation failed after 4 attempts. Last error: DHT get record failed: Timeout { key: Key(b\"\\xda-\\xe1\\xc0T\\x11$X\\x05\\xd1\\xd4\\xa6C\\x86\\x96\\xb7e\\xd9j\\x96\\x1bD\\xc8P#\\x0f\\\"\\xea A@b\") }"
        );

        Ok(())
    }

    #[actix::test]
    async fn test_publishes_document_fails_with_exponential_backoff() -> Result<()> {
        let (
            _guard,
            bus,
            _net_cmd_tx,
            mut net_cmd_rx,
            net_evt_tx,
            _net_evt_rx,
            _history,
            errors,
            _,
        ) = setup_test()?;
        let value = ArcBytes::from_bytes(b"I am a special document");
        let expires_at = Some(Utc::now() + chrono::Duration::days(1));
        let e3_id = E3id::new("1243", 1);

        // Send a request to publish
        bus.publish_without_context(PublishDocumentRequested {
            meta: DocumentMeta::new(e3_id, DocumentKind::TrBFV, vec![], expires_at),
            value: value.clone(),
        })?;

        for _ in 0..4 {
            // Expect retry
            let Some(NetCommand::DhtPutRecord { correlation_id, .. }) =
                timeout(Duration::from_secs(15), net_cmd_rx.recv())
                    .await
                    .expect("did not receive DhtPutRecord")
            else {
                bail!("msg not as expected");
            };

            // Report failure
            net_evt_tx.send(NetEvent::DhtPutRecordError {
                correlation_id,
                error: crate::events::PutOrStoreError::PutRecordError(
                    PutRecordError::QuorumFailed {
                        key: RecordKey::new(b"I got the secret"),
                        success: vec![],
                        quorum: NonZero::new(1).unwrap(),
                    },
                ),
            })?;
        }

        // Expect error to exist
        let errors = errors.send(TakeEvents::new(1)).await?;
        let error: InterfoldError = errors.events.first().unwrap().try_into()?;
        assert_eq!(
            error.message,
            "Operation failed after 4 attempts. Last error: DHT put record failed: PutRecordError(QuorumFailed { key: Key(b\"I got the secret\"), success: [], quorum: 1 })"
        );

        Ok(())
    }

    #[actix::test]
    async fn test_notified_of_document() -> Result<()> {
        let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _net_evt_rx, history, _, _) =
            setup_test()?;

        let value = ArcBytes::from_bytes(b"I am a special document");
        let expires_at = Utc::now() + chrono::Duration::days(1);
        let e3_id = E3id::new("1243", 1);
        let cid = ContentHash::from_content(&value);

        // 1. Ensure the publisher is interested in the id by receiving CiphernodeSelected
        bus.publish_without_context(CiphernodeSelected {
            e3_id: e3_id.clone(),
            threshold_m: 3,
            threshold_n: 5,
            ..CiphernodeSelected::default()
        })?;

        // 2. Dispatch a NetEvent from the Libp2pNetInterface signaling that a document was published
        net_evt_tx.send(NetEvent::GossipData(
            GossipData::DocumentPublishedNotification(DocumentPublishedNotification {
                key: ContentHash::from_content(b"wrong document".as_ref()),
                meta: DocumentMeta::new(
                    E3id::new("1111", 1),
                    DocumentKind::TrBFV,
                    vec![],
                    Some(expires_at),
                ),
                ts: 123,
            }),
        ))?;

        // 3. Nothing happens...
        let result = timeout(Duration::from_secs(1), net_cmd_rx.recv()).await;
        assert!(result.is_err(), "Expected timeout but received a message");

        // 4. Dispatch a NetEvent from the Libp2pNetInterface signaling that a document we ARE interested
        //    in was published
        net_evt_tx.send(NetEvent::GossipData(
            GossipData::DocumentPublishedNotification(DocumentPublishedNotification {
                key: cid.clone(),
                meta: DocumentMeta::new(e3_id, DocumentKind::TrBFV, vec![], Some(expires_at)),
                ts: 100,
            }),
        ))?;

        // 5. Expect that DocumentPublisher will make a DhtGetRecord request
        let Some(NetCommand::DhtGetRecord {
            key,
            correlation_id,
        }) = timeout(Duration::from_secs(1), net_cmd_rx.recv())
            .await
            .expect("did not receive DhtGetRecord")
        else {
            bail!("msg not as expected");
        };

        assert_eq!(key, cid);

        // 6. Forward the document
        net_evt_tx.send(NetEvent::DhtGetRecordSucceeded {
            key: cid,
            correlation_id,
            value, // This will error because this is not a ReceivableDocument which is fine
        })?;

        // wait for events to settle
        sleep(Duration::from_millis(100)).await;

        // Check event was dispatched
        let events = history.send(GetEvents::new()).await?;
        let Some(InterfoldEventData::DocumentReceived(DocumentReceived { value: doc, .. })) =
            events
                .iter()
                // Filter out the error
                .filter(|e| e.event_type() != "InterfoldError")
                .last()
                .map(|e| e.get_data())
        else {
            bail!("No event sent");
        };

        assert_eq!(
            doc.extract_bytes(),
            b"I am a special document",
            "document did not match"
        );

        Ok(())
    }

    pub fn is_between(instant: Instant, start: Instant, end: Instant) -> bool {
        let (min, max) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        instant >= min && instant <= max
    }

    pub fn days_from_now(days: u64) -> Instant {
        Instant::now() + Duration::from_secs(60 * 60 * 24 * days)
    }
}
