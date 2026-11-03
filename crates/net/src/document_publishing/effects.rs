// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded DHT and gossip effects for content-addressed protocol documents.

use super::*;
use crate::domain::EventConversionService;
use crate::net_interface_handle::NetEventSubscriber;
use e3_events::hlc::HlcTimestamp;
use e3_events::{
    EventContext, LbfvKeyShareDocumentFetchFailed, LbfvKeyShareDocumentFetchFailedV1,
    LbfvKeyShareDocumentFetchFailureClass, Sequenced,
};

const LBFV_FETCH_MAX_ATTEMPTS: u32 = 4;
const LBFV_FETCH_BACKOFF_SECONDS: u64 = 1 + 2 + 4;
const LBFV_FETCH_RETRY_DELAY: Duration = Duration::from_secs(30);

/// A fetched document does not match the metadata of the notifications that named it. It keeps
/// the fetched bytes, so notifications that arrive later can be checked without fetching again.
#[derive(Debug)]
pub(super) struct DocumentMetadataMismatch {
    error: anyhow::Error,
    value: ArcBytes,
}

impl DocumentMetadataMismatch {
    pub(super) fn value(&self) -> &ArcBytes {
        &self.value
    }
}

impl std::fmt::Display for DocumentMetadataMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.error)
    }
}

impl std::error::Error for DocumentMetadataMismatch {}

/// Publish a document once: store it in this node's own DHT store, announce it over gossip, then
/// upload it to the DHT.
pub async fn handle_publish_document_requested(
    tx: mpsc::Sender<NetCommand>,
    rx: NetEventSubscriber,
    event: PublishDocumentRequested,
    topic: impl Into<String>,
    bus: BusHandle,
) -> Result<()> {
    announce_stored_document(tx.clone(), rx.clone(), event.clone(), topic, bus).await?;
    replicate_document(tx, rx, &event).await
}

/// Make a document fetchable from this node's own DHT store, then gossip its notification.
///
/// The notification goes out only after the local store holds the document, so a peer that
/// fetches on the notification can find it here, even when no upload to other peers has
/// succeeded.
pub(super) async fn announce_stored_document(
    tx: mpsc::Sender<NetCommand>,
    rx: NetEventSubscriber,
    event: PublishDocumentRequested,
    topic: impl Into<String>,
    bus: BusHandle,
) -> Result<()> {
    store_document_locally(tx.clone(), rx.clone(), &event.meta, &event.value).await?;
    announce_document(tx, rx, event, topic, bus).await
}

/// The DHT key of a document and the time its record expires. An expired document has no
/// record: it must not be stored or uploaded.
fn dht_record_of(
    meta: &DocumentMeta,
    value: &ArcBytes,
) -> Result<(ContentHash, Option<std::time::Instant>)> {
    let expires = datetime_to_instant_from_now(meta.expires_at)
        .context("refusing to store an expired DHT document")?;
    Ok((ContentHash::from_content(value), Some(expires)))
}

/// Store a document in this node's own DHT store, without uploading it to other peers.
pub(super) async fn store_document_locally(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: NetEventSubscriber,
    meta: &DocumentMeta,
    value: &ArcBytes,
) -> Result<()> {
    let (key, expires) = dht_record_of(meta, value)?;
    let value = value.clone();
    call_and_await_response(
        net_cmds,
        net_events,
        NetCommand::DhtStoreLocal {
            correlation_id: CorrelationId::new(),
            expires,
            value,
            key,
        },
        |event| match event {
            NetEvent::DhtStoreLocalSucceeded { .. } => Some(Ok(())),
            NetEvent::DhtStoreLocalError { error, .. } => {
                Some(Err(anyhow::anyhow!("DHT local store failed: {error:?}")))
            }
            _ => None,
        },
        DHT_STORE_LOCAL_TIMEOUT,
    )
    .await
}

/// Store the full document on the DHT peers closest to its content hash.
pub(super) async fn replicate_document(
    tx: mpsc::Sender<NetCommand>,
    rx: NetEventSubscriber,
    event: &PublishDocumentRequested,
) -> Result<()> {
    let (key, expires) = dht_record_of(&event.meta, &event.value)?;
    let value = event.value.clone();
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

/// Gossip a small notification that names a document this node already stores.
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

/// Fetch a notified document and bind it to the notification whose metadata matches it.
///
/// `notifications` name the same document (one content hash) and can carry different metadata,
/// because peers choose the metadata. The document is fetched once and accepted under the first
/// relevant notification whose metadata matches the payload. The returned notification supplies
/// the timestamp of the received event.
pub async fn handle_document_published_notification(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: NetEventSubscriber,
    ids: HashMap<E3id, PartyId>,
    notifications: Vec<DocumentPublishedNotification>,
) -> Result<Option<(DocumentReceived, DocumentPublishedNotification)>> {
    let relevant: Vec<_> = notifications
        .into_iter()
        .filter(|notification| {
            if matches!(
                notification.meta.kind,
                e3_events::DocumentKind::LbfvKeyShare
            ) {
                debug!(
                    e3_id = %notification.meta.e3_id,
                    "Ignoring generic l-BFV DHT document notification"
                );
                return false;
            }
            DocumentPublishingService::interest_in(&ids, notification).is_some()
        })
        .collect();
    let Some(first) = relevant.first() else {
        debug!("Node not interested in the notified document");
        return Ok(None);
    };
    let key = first.key.clone();
    debug!(
        "interested in document {:?} with {} candidate notification(s)",
        key,
        relevant.len()
    );

    // Release the slot after one attempt. The publisher queues retries behind other peers.
    let value = get_record(net_cmds, net_events, key).await?;

    // When no candidate matches, the mismatch is final for these notifications, so the caller does
    // not fetch the document again for them. It checks later notifications against these bytes.
    bind_to_candidate(&ids, relevant, value.clone())
        .map_err(|error| anyhow::Error::new(DocumentMetadataMismatch { error, value }))
}

/// Accept `value` under the first relevant candidate whose metadata matches its payload.
///
/// The gossiped metadata is not covered by the DHT content hash. Binding it to the decoded payload
/// before persisting DocumentReceived stops a notification for an E3 this node is interested in
/// from injecting a content-addressed document for a different E3 or party route. Returns
/// `Ok(None)` when no candidate is relevant to this node, and the last mismatch otherwise.
pub(super) fn bind_to_candidate(
    ids: &HashMap<E3id, PartyId>,
    candidates: Vec<DocumentPublishedNotification>,
    value: ArcBytes,
) -> Result<Option<(DocumentReceived, DocumentPublishedNotification)>> {
    let mut mismatch = None;
    for notification in candidates {
        if DocumentPublishingService::interest_in(ids, &notification).is_none() {
            continue;
        }
        match EventConversionService::validate_received(&notification.meta, &value) {
            Ok(()) => {
                let document = DocumentReceived {
                    meta: notification.meta.clone(),
                    value,
                };
                return Ok(Some((document, notification)));
            }
            Err(error) => mismatch = Some(error),
        }
    }
    match mismatch {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

/// Fetch one l-BFV document by its manifest-bound identity.
pub async fn handle_lbfv_document_fetch_requested(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: NetEventSubscriber,
    bus: BusHandle,
    request: LbfvKeyShareDocumentFetchRequested,
    ec: EventContext<Sequenced>,
) -> Result<()> {
    let identity = request.request().clone();
    let key = ContentHash(identity.content_hash.as_slice().to_vec());
    let value = match retry_with_backoff(
        || get_record(net_cmds.clone(), net_events.clone(), key.clone()).map_err(to_retry),
        LBFV_FETCH_MAX_ATTEMPTS,
        1000,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            debug!(%error, "Targeted l-BFV DHT document is unavailable");
            let fetch_budget = KADEMLIA_GET_TIMEOUT
                .as_secs()
                .saturating_mul(u64::from(LBFV_FETCH_MAX_ATTEMPTS))
                .saturating_add(LBFV_FETCH_BACKOFF_SECONDS)
                .saturating_add(LBFV_FETCH_RETRY_DELAY.as_secs());
            let retry_at = (HlcTimestamp::wall_time(ec.ts()) / 1_000_000).checked_add(fetch_budget);
            bus.publish(
                LbfvKeyShareDocumentFetchFailed::V1(LbfvKeyShareDocumentFetchFailedV1 {
                    e3_id: identity.e3_id,
                    proof_session_id: identity.proof_session_id,
                    party_id: identity.party_id,
                    role: identity.role,
                    content_hash: identity.content_hash,
                    attempt: identity.attempt,
                    failure_class: LbfvKeyShareDocumentFetchFailureClass::Unavailable,
                    retry_at,
                }),
                ec,
            )?;
            return Ok(());
        }
    };

    match EventConversionService::decode_lbfv_fetch(&request, &value) {
        Ok(received) => bus.publish(received, ec)?,
        Err(error) => {
            debug!(%error, "Targeted l-BFV DHT document is invalid");
            bus.publish(
                LbfvKeyShareDocumentFetchFailed::V1(LbfvKeyShareDocumentFetchFailedV1 {
                    e3_id: identity.e3_id,
                    proof_session_id: identity.proof_session_id,
                    party_id: identity.party_id,
                    role: identity.role,
                    content_hash: identity.content_hash,
                    attempt: identity.attempt,
                    failure_class: LbfvKeyShareDocumentFetchFailureClass::InvalidData,
                    retry_at: None,
                }),
                ec,
            )?;
        }
    }

    Ok(())
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
            deadline: std::time::Instant::now() + DHT_PUT_DEADLINE,
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
            key: key.clone(),
        },
        |event| match event {
            NetEvent::DhtGetRecordSucceeded {
                key: found, value, ..
            } if found == &key => Some(Ok(value.clone())),
            NetEvent::DhtGetRecordSucceeded { .. } => Some(Err(anyhow::anyhow!(
                "DHT get record returned a document for another key"
            ))),
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
