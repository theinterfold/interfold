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

/// Called when we receive a PublishDocumentRequested event
pub async fn handle_publish_document_requested(
    tx: mpsc::Sender<NetCommand>,
    rx: NetEventSubscriber,
    event: PublishDocumentRequested,
    topic: impl Into<String>,
    bus: BusHandle,
) -> Result<()> {
    let value = event.value;
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
    net_events: NetEventSubscriber,
    ids: HashMap<E3id, PartyId>,
    event: DocumentPublishedNotification,
) -> Result<Option<DocumentReceived>> {
    if matches!(event.meta.kind, e3_events::DocumentKind::LbfvKeyShare) {
        debug!(
            e3_id = %event.meta.e3_id,
            "Ignoring generic l-BFV DHT document notification"
        );
        return Ok(None);
    }

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
    EventConversionService::validate_received(&event.meta, &value)?;

    Ok(Some(DocumentReceived {
        meta: event.meta,
        value,
    }))
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
