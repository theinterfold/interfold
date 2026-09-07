// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded DHT and gossip effects for content-addressed protocol documents.

use super::*;
use crate::domain::EventConversionService;
use crate::net_interface_handle::NetEventSubscriber;

/// Called when we receive a PublishDocumentRequested event.
///
/// Returns the notification that was gossiped so the caller can keep it for re-announcement.
pub async fn handle_publish_document_requested(
    tx: mpsc::Sender<NetCommand>,
    rx: NetEventSubscriber,
    event: PublishDocumentRequested,
    topic: impl Into<String>,
    bus: BusHandle,
) -> Result<PublishOutcome> {
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

    // The DHT record is durable from here on, so the pointer is worth retaining even if the
    // gossip publish fails. `NoPeersSubscribed` is the normal outcome when this node is the
    // first to join the topic, and treating it as fatal would drop the announcement from
    // `announcements_to_repeat` — the late peer would then never learn about a record that is
    // sitting in the DHT. Report the outcome and let the caller retain the pointer either way.
    let broadcast = broadcast_document_published_notification(tx, rx, notification.clone(), topic)
        .await
        .map(|_| ());
    Ok(PublishOutcome {
        notification,
        broadcast,
    })
}

/// The result of publishing a document: the pointer to retain, and whether the initial gossip
/// broadcast reached the mesh.
///
/// The two are separate because the DHT put and the gossip publish fail independently: the
/// record can be durable while the broadcast finds no subscribed peers.
#[derive(Debug)]
pub(super) struct PublishOutcome {
    pub notification: DocumentPublishedNotification,
    pub broadcast: Result<()>,
}

/// Re-gossip a notification that was already announced once.
///
/// Used when a peer (re)subscribes to the topic after the original broadcast. The DHT
/// record is still present; only the pointer needs to reach the late peer.
///
/// gossipsub ids messages by the SHA-256 of their bytes and refuses an identical publish
/// for `duplicate_cache_time` (60 s). Re-sending the retained notification byte-for-byte
/// therefore does nothing for a peer that was **down** during the original announce: it
/// never saw the mesh copy, and the re-announce is rejected as `Duplicate`. Round 10
/// caught exactly this — a member restarted inside the DKG window, every peer re-announced,
/// every re-announce was rejected, and the member's collector waited two hours for shares
/// that were sitting in the DHT the whole time.
///
/// So the re-announce is re-stamped with a fresh HLC tick. The bytes differ, gossipsub
/// treats it as a new message, and the late peer receives it. Receivers key on the
/// content hash in `key`, not on `ts`, so a node that already fetched the document simply
/// fetches the same record again (idempotent: the collectors are keyed by party id).
///
/// `AlreadyPublished` can still occur if two `GossipSubscribed` events land inside the same
/// HLC tick; it is swallowed at `debug` because the first re-announce already went out.
pub async fn repeat_document_published_notification(
    tx: mpsc::Sender<NetCommand>,
    rx: NetEventSubscriber,
    mut notification: DocumentPublishedNotification,
    topic: impl Into<String>,
    bus: &BusHandle,
) -> Result<()> {
    notification.ts = bus.ts()?;
    match broadcast_document_published_notification(tx, rx, notification, topic).await {
        Err(error) if is_already_published(&error) => {
            debug!("Re-announce skipped: identical pointer is already in the gossip mesh");
            Ok(())
        }
        other => other,
    }
}

fn is_already_published(error: &anyhow::Error) -> bool {
    // `.context()` wraps the typed failure one level down; walk the whole chain.
    error
        .chain()
        .filter_map(|source| source.downcast_ref::<GossipPublishFailure>())
        .any(|failure| matches!(failure, GossipPublishFailure::AlreadyPublished))
}

/// Called when we receive a notification from the net_interface
pub async fn handle_document_published_notification(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: NetEventSubscriber,
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

    // The gossiped metadata is not covered by the DHT content hash. Bind it to the decoded
    // payload before persisting DocumentReceived; otherwise a notification for an E3 this node is
    // interested in can inject a content-addressed document for a different E3 or party route.
    EventConversionService::validate_received(&event.meta, &value)?;

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
        NetCommand::GossipPublish {
            topic: topic.into(),
            correlation_id: id,
            data: GossipData::DocumentPublishedNotification(payload),
        },
        |event| match event {
            NetEvent::GossipPublished { .. } => Some(Ok(())),
            NetEvent::GossipPublishError { error, .. } => {
                // Keep the typed failure as the error source so callers can match on it.
                // `error` is `&Arc<_>`; deref through the Arc or the source type is the Arc.
                let failure: GossipPublishFailure = (**error).clone();
                Some(Err(
                    anyhow::Error::new(failure).context("GossipPublished failed")
                ))
            }
            _ => None,
        },
        KADEMLIA_BROADCAST_TIMEOUT,
    )
    .await
}

#[cfg(test)]
mod already_published_tests {
    use super::*;

    #[test]
    fn a_context_wrapped_duplicate_is_recognised() {
        let error = anyhow::Error::new(GossipPublishFailure::AlreadyPublished)
            .context("GossipPublished failed");
        assert!(is_already_published(&error));
        // Exactly what the broadcast matcher builds from the network's `Arc<_>`. Cloning the
        // `Arc` itself (instead of the failure inside it) makes the source type
        // `Arc<GossipPublishFailure>` and the downcast silently miss — this pins it.
        let shared = std::sync::Arc::new(GossipPublishFailure::AlreadyPublished);
        let failure: GossipPublishFailure = (*shared).clone();
        let from_arc = anyhow::Error::new(failure).context("GossipPublished failed");
        assert!(is_already_published(&from_arc));
    }

    #[test]
    fn other_failures_are_not() {
        let error = anyhow::Error::new(GossipPublishFailure::NoPeersSubscribed)
            .context("GossipPublished failed");
        assert!(!is_already_published(&error));
        assert!(!is_already_published(&anyhow::anyhow!(
            "GossipPublished failed"
        )));
    }
}
