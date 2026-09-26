// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded DHT and gossip effects for content-addressed protocol documents.

use super::*;
use crate::domain::EventConversionService;
use crate::net_interface_handle::NetEventSubscriber;

/// A fetched document does not match the metadata of the notification that named it.
#[derive(Debug)]
pub(super) struct DocumentMetadataMismatch(anyhow::Error);

impl std::fmt::Display for DocumentMetadataMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl std::error::Error for DocumentMetadataMismatch {}

/// Replicate a document to the DHT, then announce it over gossip.
pub async fn handle_publish_document_requested(
    tx: mpsc::Sender<NetCommand>,
    rx: NetEventSubscriber,
    event: PublishDocumentRequested,
    topic: impl Into<String>,
    bus: BusHandle,
) -> Result<()> {
    replicate_document(tx.clone(), rx.clone(), &event).await?;
    announce_document(tx, rx, event, topic, bus).await
}

/// Store the full document on the DHT peers closest to its content hash.
pub(super) async fn replicate_document(
    tx: mpsc::Sender<NetCommand>,
    rx: NetEventSubscriber,
    event: &PublishDocumentRequested,
) -> Result<()> {
    let value = event.value.clone();
    let key = ContentHash::from_content(&value);
    let expires = Some(
        datetime_to_instant_from_now(event.meta.expires_at)
            .context("refusing to publish an expired DHT document")?,
    );

    retry_with_backoff(
        || {
            put_record(tx.clone(), rx.clone(), expires, value.clone(), key.clone())
                .map_err(to_retry)
        },
        DHT_PUT_ATTEMPTS,
        1000,
    )
    .await
}

/// Gossip a small notification that names an already replicated document.
pub(super) async fn announce_document(
    tx: mpsc::Sender<NetCommand>,
    rx: NetEventSubscriber,
    event: PublishDocumentRequested,
    topic: impl Into<String>,
    bus: BusHandle,
) -> Result<()> {
    let key = ContentHash::from_content(&event.value);
    let notification = DocumentPublishedNotification::new(event.meta, key, bus.ts()?);
    broadcast_document_published_notification(tx, rx, notification, topic).await
}

/// Called when we receive a notification from the net_interface
pub async fn handle_document_published_notification(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: NetEventSubscriber,
    ids: HashMap<E3id, PartyId>,
    event: DocumentPublishedNotification,
) -> Result<Option<DocumentReceived>> {
    let Some(party_id) = DocumentPublishingService::interest_in(&ids, &event) else {
        debug!("Node not interested in id {}", event.meta.e3_id);
        return Ok(None);
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

    // The gossiped metadata is not covered by the DHT content hash. Bind it to the decoded
    // payload before persisting DocumentReceived; otherwise a notification for an E3 this node is
    // interested in can inject a content-addressed document for a different E3 or party route.
    // A mismatch is final for this metadata, so the caller does not retry it; a correct
    // notification for the same document is fetched on its own.
    EventConversionService::validate_received(&event.meta, &value)
        .map_err(|error| anyhow::Error::new(DocumentMetadataMismatch(error)))?;

    Ok(Some(DocumentReceived {
        meta: event.meta,
        value,
    }))
}

/// Call DhtPutRecord Command on the Libp2pNetInterface and handle the results
async fn put_record(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: NetEventSubscriber,
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
    net_events: NetEventSubscriber,
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
    net_events: NetEventSubscriber,
    payload: DocumentPublishedNotification,
    topic: impl Into<String>,
) -> Result<()> {
    let id = CorrelationId::new();
    call_and_await_response(
        net_cmds,
        net_events,
        NetCommand::gossip_republish(
            topic.into(),
            GossipData::DocumentPublishedNotification(payload),
            id,
        ),
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
