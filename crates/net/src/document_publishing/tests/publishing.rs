// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::net_interface_handle::NetEventSubscriber;

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

/// A `DocumentPublishedNotification` is gossiped once. A peer that subscribes to the topic
/// afterwards — restarting mid-DKG, or connecting late — never receives the pointer and cannot
/// fetch the DHT record even though it is still there. Observed live: a node killed and
/// restarted during DKG stalled forever waiting on encryption keys its peers had already
/// published. The publisher must re-announce its in-flight pointers when a peer subscribes.
#[actix::test]
async fn in_flight_pointers_are_reannounced_when_a_peer_subscribes() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _net_evt_rx, _, _, _) =
        setup_test()?;
    let e3_id = E3id::new("77", 1);

    // Publish one document and drive the fake network through put + gossip.
    bus.publish_without_context(PublishDocumentRequested {
        meta: DocumentMeta::new(e3_id.clone(), DocumentKind::TrBFV, vec![], None),
        value: ArcBytes::from_bytes(b"encryption key"),
    })?;
    let Some(NetCommand::DhtPutRecord {
        correlation_id,
        key,
        ..
    }) = timeout(Duration::from_secs(1), net_cmd_rx.recv()).await?
    else {
        bail!("expected DhtPutRecord");
    };
    net_evt_tx.send(NetEvent::DhtPutRecordSucceeded {
        correlation_id,
        key: key.clone(),
    })?;
    let Some(NetCommand::GossipPublish {
        correlation_id,
        data: GossipData::DocumentPublishedNotification(first),
        ..
    }) = timeout(Duration::from_secs(1), net_cmd_rx.recv()).await?
    else {
        bail!("expected the first GossipPublish");
    };
    net_evt_tx.send(NetEvent::GossipPublished {
        correlation_id,
        message_id: libp2p::gossipsub::MessageId::new(&[1]),
    })?;
    // Let the actor record the announced pointer.
    sleep(Duration::from_millis(50)).await;

    // A peer joins the topic after the fact.
    net_evt_tx.send(NetEvent::GossipSubscribed {
        count: 1,
        topic: libp2p::gossipsub::IdentTopic::new("topic").hash(),
    })?;

    // The same pointer goes out again. It must carry a FRESH ts: gossipsub ids messages by
    // the SHA-256 of their bytes, so a byte-identical re-send is rejected as `Duplicate`
    // for 60 s and never reaches a peer that was down for the original announce (Round 10).
    // Receivers key on `key`, not `ts`, so the changed ts is harmless to them.
    let Some(NetCommand::GossipPublish {
        correlation_id,
        data: GossipData::DocumentPublishedNotification(again),
        ..
    }) = timeout(Duration::from_secs(1), net_cmd_rx.recv())
        .await
        .expect("pointer was not re-announced on peer subscribe")
    else {
        bail!("expected the re-announced GossipPublish");
    };
    net_evt_tx.send(NetEvent::GossipPublished {
        correlation_id,
        message_id: libp2p::gossipsub::MessageId::new(&[2]),
    })?;
    assert_eq!(again.key, first.key);
    assert_eq!(again.meta.e3_id, e3_id);
    assert_ne!(
        again.ts, first.ts,
        "re-announce must be re-stamped so gossipsub does not reject it as a Duplicate"
    );
    assert_ne!(
        again.to_bytes()?,
        first.to_bytes()?,
        "re-announce bytes must differ or the gossipsub message id collides"
    );

    Ok(())
}

/// gossipsub ids messages by content hash and rejects an identical publish for 60 s. A
/// peer that subscribes inside that window makes the re-announce hit `Duplicate`; the first
/// announce is still in the mesh so nothing was lost, and it must not surface as an
/// `InterfoldError` (it did on every node of the Round 9 swarm at `nodes down`).
#[actix::test]
async fn a_duplicate_reannounce_is_not_an_error() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _net_evt_rx, _, errors, _) =
        setup_test()?;
    let e3_id = E3id::new("78", 1);

    bus.publish_without_context(PublishDocumentRequested {
        meta: DocumentMeta::new(e3_id.clone(), DocumentKind::TrBFV, vec![], None),
        value: ArcBytes::from_bytes(b"encryption key"),
    })?;
    let Some(NetCommand::DhtPutRecord {
        correlation_id,
        key,
        ..
    }) = timeout(Duration::from_secs(1), net_cmd_rx.recv()).await?
    else {
        bail!("expected DhtPutRecord");
    };
    net_evt_tx.send(NetEvent::DhtPutRecordSucceeded {
        correlation_id,
        key,
    })?;
    let Some(NetCommand::GossipPublish { correlation_id, .. }) =
        timeout(Duration::from_secs(1), net_cmd_rx.recv()).await?
    else {
        bail!("expected the first GossipPublish");
    };
    net_evt_tx.send(NetEvent::GossipPublished {
        correlation_id,
        message_id: libp2p::gossipsub::MessageId::new(&[1]),
    })?;
    sleep(Duration::from_millis(50)).await;

    net_evt_tx.send(NetEvent::GossipSubscribed {
        count: 1,
        topic: libp2p::gossipsub::IdentTopic::new("topic").hash(),
    })?;
    let Some(NetCommand::GossipPublish { correlation_id, .. }) =
        timeout(Duration::from_secs(1), net_cmd_rx.recv()).await?
    else {
        bail!("expected the re-announced GossipPublish");
    };
    // The network reports gossipsub's duplicate-cache rejection.
    net_evt_tx.send(NetEvent::GossipPublishError {
        correlation_id,
        error: std::sync::Arc::new(GossipPublishFailure::from_libp2p(
            libp2p::gossipsub::PublishError::Duplicate,
        )),
    })?;
    sleep(Duration::from_millis(100)).await;

    let errors = errors.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(
        errors.is_empty(),
        "a duplicate re-announce must be swallowed, got {errors:?}"
    );
    Ok(())
}

/// Once an E3 completes its pointers must not be re-announced to late peers.
#[actix::test]
async fn completed_e3_pointers_are_not_reannounced() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _net_evt_rx, _, _, _) =
        setup_test()?;
    let e3_id = E3id::new("78", 1);

    bus.publish_without_context(PublishDocumentRequested {
        meta: DocumentMeta::new(e3_id.clone(), DocumentKind::TrBFV, vec![], None),
        value: ArcBytes::from_bytes(b"done"),
    })?;
    let Some(NetCommand::DhtPutRecord {
        correlation_id,
        key,
        ..
    }) = timeout(Duration::from_secs(1), net_cmd_rx.recv()).await?
    else {
        bail!("expected DhtPutRecord");
    };
    net_evt_tx.send(NetEvent::DhtPutRecordSucceeded {
        correlation_id,
        key,
    })?;
    let Some(NetCommand::GossipPublish { correlation_id, .. }) =
        timeout(Duration::from_secs(1), net_cmd_rx.recv()).await?
    else {
        bail!("expected GossipPublish");
    };
    net_evt_tx.send(NetEvent::GossipPublished {
        correlation_id,
        message_id: libp2p::gossipsub::MessageId::new(&[1]),
    })?;
    sleep(Duration::from_millis(50)).await;

    bus.publish_without_context(e3_events::E3RequestComplete {
        e3_id: e3_id.clone(),
    })?;
    // Completion prunes the DHT records.
    let Some(NetCommand::DhtRemoveRecords { .. }) =
        timeout(Duration::from_secs(1), net_cmd_rx.recv()).await?
    else {
        bail!("expected DhtRemoveRecords");
    };

    net_evt_tx.send(NetEvent::GossipSubscribed {
        count: 1,
        topic: libp2p::gossipsub::IdentTopic::new("topic").hash(),
    })?;

    assert!(
        timeout(Duration::from_millis(300), net_cmd_rx.recv())
            .await
            .is_err(),
        "a completed E3's pointers must not be re-announced"
    );

    Ok(())
}

#[actix::test]
async fn expired_document_is_rejected_without_a_dht_write() -> Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("expired-document");
    let (net_cmd_tx, mut net_cmd_rx) = mpsc::channel(1);
    let (net_evt_tx, _net_evt_rx) = broadcast::channel(1);
    let event = PublishDocumentRequested {
        meta: DocumentMeta::new(
            E3id::new("expired", 1),
            DocumentKind::TrBFV,
            vec![],
            Some(Utc::now() - chrono::Duration::seconds(1)),
        ),
        value: ArcBytes::from_bytes(b"stale"),
    };

    let error = handle_publish_document_requested(
        net_cmd_tx,
        NetEventSubscriber::from(&net_evt_tx),
        event,
        "topic",
        bus,
    )
    .await
    .unwrap_err();

    assert!(format!("{error:#}").contains("expiry is not in the future"));
    assert!(matches!(
        net_cmd_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
    ));
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
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _net_evt_rx, _history, errors, _) =
        setup_test()?;
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
            error: crate::events::PutOrStoreError::PutRecordError(PutRecordError::QuorumFailed {
                key: RecordKey::new(b"I got the secret"),
                success: vec![],
                quorum: NonZero::new(1).unwrap(),
            }),
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
