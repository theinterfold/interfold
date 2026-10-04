// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_events::{E3StageChanged, EventConstructorWithTimestamp, EventSource, Unsequenced};

#[actix::test]
async fn test_notified_of_document() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _net_evt_rx, history, _, _) =
        setup_test()?;

    let expires_at = Utc::now() + chrono::Duration::days(1);
    let e3_id = E3id::new("1243", 1);
    let value = EventConversionService::encryption_key_to_request(EncryptionKeyCreated {
        e3_id: e3_id.clone(),
        key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(b"public key"))),
        external: false,
    })?
    .expect("local key should produce a document")
    .value;
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
        value: value.clone(),
    })?;

    // wait for events to settle
    sleep(Duration::from_millis(100)).await;

    // Check event was dispatched
    let events = history.send(GetEvents::new()).await?;
    let Some(InterfoldEventData::DocumentReceived(DocumentReceived { value: doc, .. })) =
        events.iter().find_map(|event| match event.get_data() {
            data @ InterfoldEventData::DocumentReceived(_) => Some(data),
            _ => None,
        })
    else {
        bail!("No event sent");
    };

    assert_eq!(
        doc.extract_bytes(),
        value.extract_bytes(),
        "document did not match"
    );

    Ok(())
}

#[actix::test]
async fn notification_cannot_relabel_payload_for_another_e3() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _rx, history, errors, publisher) =
        setup_test()?;
    let interested_e3 = E3id::new("100", 1);
    let payload_e3 = E3id::new("200", 1);
    let value = EventConversionService::encryption_key_to_request(EncryptionKeyCreated {
        e3_id: payload_e3,
        key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(b"public key"))),
        external: false,
    })?
    .expect("local key should produce a document")
    .value;
    let key = ContentHash::from_content(&value);

    bus.publish_without_context(CiphernodeSelected {
        e3_id: interested_e3.clone(),
        threshold_m: 3,
        threshold_n: 5,
        ..CiphernodeSelected::default()
    })?;
    net_evt_tx.send(NetEvent::GossipData(
        GossipData::DocumentPublishedNotification(DocumentPublishedNotification {
            key: key.clone(),
            meta: DocumentMeta::new(
                interested_e3,
                DocumentKind::TrBFV,
                vec![],
                Some(Utc::now() + chrono::Duration::days(1)),
            ),
            ts: 100,
        }),
    ))?;

    let Some(NetCommand::DhtGetRecord { correlation_id, .. }) =
        timeout(Duration::from_secs(1), net_cmd_rx.recv())
            .await
            .expect("did not receive DhtGetRecord")
    else {
        bail!("msg not as expected");
    };
    net_evt_tx.send(NetEvent::DhtGetRecordSucceeded {
        key,
        correlation_id,
        value,
    })?;

    let error_events = errors.send(TakeEvents::new(1)).await?;
    let error: InterfoldError = error_events.events.first().unwrap().try_into()?;
    assert!(error.message.contains("metadata E3 1:100"));
    assert!(error.message.contains("payload E3 1:200"));

    let events = history.send(GetEvents::new()).await?;
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.get_data(), InterfoldEventData::DocumentReceived(_))),
        "mismatched document must not be persisted"
    );
    assert_eq!(
        publisher.send(FetchBacklog).await?,
        (0, 0),
        "a metadata mismatch is final and is not queued for another fetch"
    );
    Ok(())
}

#[actix::test]
async fn notification_before_selection_is_fetched_once_after_selection() -> Result<()> {
    use crate::events::DocumentIngress;
    let (_guard, bus, _net_cmd_tx, mut commands, net_events, _, _, _, publisher) = setup_test()?;
    let peer = libp2p::PeerId::random();
    let ingress = |notification| DocumentIngress {
        propagation_source: Some(peer),
        notification,
    };
    let expiry = Utc::now() + chrono::Duration::seconds(2);
    for index in 0..64usize {
        publisher
            .send(ingress(DocumentPublishedNotification {
                key: ContentHash::from_content(&index.to_be_bytes()),
                meta: DocumentMeta::new(
                    E3id::new("unselected", 1),
                    DocumentKind::TrBFV,
                    vec![],
                    Some(expiry),
                ),
                ts: 100,
            }))
            .await?;
    }
    let until_expiry = (expiry - Utc::now()).to_std()?;
    sleep(until_expiry + Duration::from_millis(1)).await;
    let e3_id = E3id::new("early", 1);
    let value = EventConversionService::encryption_key_to_request(EncryptionKeyCreated {
        e3_id: e3_id.clone(),
        key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(b"public key"))),
        external: false,
    })?
    .expect("local key should produce a document")
    .value;
    let key = ContentHash::from_content(&value);
    let notification = DocumentPublishedNotification {
        key: key.clone(),
        meta: DocumentMeta::new(
            e3_id.clone(),
            DocumentKind::TrBFV,
            vec![],
            Some(Utc::now() + chrono::Duration::hours(1)),
        ),
        ts: 100,
    };
    timeout(
        Duration::from_secs(1),
        publisher.send(ingress(notification.clone())),
    )
    .await??;
    assert!(matches!(
        commands.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    bus.publish_without_context(CiphernodeSelected {
        e3_id,
        threshold_m: 2,
        threshold_n: 3,
        ..CiphernodeSelected::default()
    })?;
    let Some(NetCommand::DhtGetRecord { correlation_id, .. }) =
        timeout(Duration::from_secs(1), commands.recv()).await?
    else {
        bail!("expected the buffered document to be fetched");
    };
    let received = bus.wait_for(EventType::DocumentReceived);
    net_events.send(NetEvent::DhtGetRecordSucceeded {
        key: key.clone(),
        correlation_id,
        value,
    })?;
    timeout(Duration::from_secs(1), received).await??;

    timeout(
        Duration::from_secs(1),
        publisher.send(ingress(notification)),
    )
    .await??;
    assert!(matches!(
        commands.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    Ok(())
}

#[actix::test]
async fn terminal_stage_cancels_an_inflight_document_fetch() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut commands, net_events, _, history, _, publisher) =
        setup_test()?;
    let e3_id = E3id::new("terminal-fetch", 1);
    let value = EventConversionService::encryption_key_to_request(EncryptionKeyCreated {
        e3_id: e3_id.clone(),
        key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(b"public key"))),
        external: false,
    })?
    .expect("local key should produce a document")
    .value;
    let key = ContentHash::from_content(&value);

    bus.publish_without_context(CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: 2,
        threshold_n: 3,
        ..CiphernodeSelected::default()
    })?;
    let notification = DocumentPublishedNotification {
        key: key.clone(),
        meta: DocumentMeta::new(
            e3_id.clone(),
            DocumentKind::TrBFV,
            vec![],
            Some(Utc::now() + chrono::Duration::hours(1)),
        ),
        ts: 100,
    };
    let fetch = tokio::spawn({
        let publisher = publisher.clone();
        async move { publisher.send(notification).await }
    });
    let Some(NetCommand::DhtGetRecord { correlation_id, .. }) =
        timeout(Duration::from_secs(1), commands.recv()).await?
    else {
        bail!("expected DHT get");
    };

    let stage = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        E3StageChanged {
            e3_id,
            previous_stage: E3Stage::CiphertextReady,
            new_stage: E3Stage::Complete,
        }
        .into(),
        None,
        101,
        None,
        EventSource::Evm,
    )
    .into_sequenced(1);
    publisher.send(stage).await?;
    net_events.send(NetEvent::DhtGetRecordSucceeded {
        key,
        correlation_id,
        value,
    })?;
    timeout(Duration::from_secs(1), fetch).await???;
    bus.flush_event_pipeline().await?;

    let events = history.send(GetEvents::new()).await?;
    assert!(!events
        .iter()
        .any(|event| matches!(event.get_data(), InterfoldEventData::DocumentReceived(_))));
    Ok(())
}

#[actix::test]
async fn notification_ingress_does_not_wait_for_the_fetch() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut commands, _net_events, _, _, _, publisher) = setup_test()?;
    let e3_id = E3id::new("ingress", 1);
    bus.publish_without_context(CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: 2,
        threshold_n: 3,
        ..CiphernodeSelected::default()
    })?;
    let notification = |document: &[u8]| DocumentPublishedNotification {
        key: ContentHash::from_content(document),
        meta: DocumentMeta::new(
            e3_id.clone(),
            DocumentKind::TrBFV,
            vec![],
            Some(Utc::now() + chrono::Duration::hours(1)),
        ),
        ts: 100,
    };

    timeout(
        Duration::from_secs(1),
        publisher.send(notification(b"first")),
    )
    .await??;
    timeout(
        Duration::from_secs(1),
        publisher.send(notification(b"second")),
    )
    .await??;

    let mut requested = Vec::new();
    for _ in 0..2 {
        let Some(NetCommand::DhtGetRecord { key, .. }) =
            timeout(Duration::from_secs(1), commands.recv()).await?
        else {
            bail!("expected a DHT get");
        };
        requested.push(key);
    }
    assert!(requested.contains(&ContentHash::from_content(b"first".as_ref())));
    assert!(requested.contains(&ContentHash::from_content(b"second".as_ref())));
    Ok(())
}

#[actix::test]
async fn a_notification_flood_keeps_the_fetch_backlog_bounded() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut commands, _net_events, _, _, _, publisher) = setup_test()?;
    let e3_id = E3id::new("flood", 1);
    bus.publish_without_context(CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: 2,
        threshold_n: 3,
        ..CiphernodeSelected::default()
    })?;
    publisher.send(PublisherBarrier).await?;

    let peers: Vec<_> = (0..8).map(|_| libp2p::PeerId::random()).collect();
    let notifications = MAX_WAITING_FETCHES * 4;
    for index in 0..notifications {
        let notification = DocumentPublishedNotification {
            key: ContentHash::from_content(format!("document {index}").as_bytes()),
            meta: DocumentMeta::new(
                e3_id.clone(),
                DocumentKind::TrBFV,
                vec![],
                Some(Utc::now() + chrono::Duration::hours(1)),
            ),
            ts: 100,
        };
        timeout(
            Duration::from_secs(1),
            publisher.send(DocumentIngress {
                propagation_source: Some(peers[index % peers.len()]),
                notification,
            }),
        )
        .await??;
    }

    // No fetch completes, so only the in-flight limit of reads starts.
    for _ in 0..MAX_INFLIGHT_TRANSFERS {
        let Some(NetCommand::DhtGetRecord { .. }) =
            timeout(Duration::from_secs(1), commands.recv()).await?
        else {
            bail!("expected a DHT get");
        };
    }
    assert!(
        timeout(Duration::from_millis(200), commands.recv())
            .await
            .is_err(),
        "no fetch starts beyond the in-flight limit"
    );
    let (fetching, waiting) = publisher.send(FetchBacklog).await?;
    assert_eq!(fetching, MAX_INFLIGHT_TRANSFERS);
    assert_eq!(waiting, MAX_WAITING_FETCHES);
    Ok(())
}

#[actix::test]
async fn a_malformed_notification_is_not_fetched() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut commands, _net_events, _, _, _, publisher) = setup_test()?;
    let e3_id = E3id::new("malformed", 1);
    bus.publish_without_context(CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: 2,
        threshold_n: 3,
        ..CiphernodeSelected::default()
    })?;
    publisher.send(PublisherBarrier).await?;

    publisher
        .send(DocumentPublishedNotification {
            key: ContentHash(vec![7; 1024]),
            meta: DocumentMeta::new(
                e3_id,
                DocumentKind::TrBFV,
                vec![],
                Some(Utc::now() + chrono::Duration::hours(1)),
            ),
            ts: 100,
        })
        .await?;

    assert!(
        timeout(Duration::from_millis(200), commands.recv())
            .await
            .is_err(),
        "a key that is not a SHA-256 hash is not fetched"
    );
    assert_eq!(publisher.send(FetchBacklog).await?, (0, 0));
    Ok(())
}

/// A forged notification that reaches the node first must not cost it the document: the correct
/// notification that arrives during the forged fetch is checked against the fetched bytes, without
/// fetching the document again.
#[actix::test]
async fn a_forged_notification_does_not_block_the_correct_one() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut commands, net_events, _, history, _, publisher) =
        setup_test()?;
    let e3_id = E3id::new("forged", 1);
    let value = EventConversionService::encryption_key_to_request(EncryptionKeyCreated {
        e3_id: e3_id.clone(),
        key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(b"public key"))),
        external: false,
    })?
    .expect("local key should produce a document")
    .value;
    let key = ContentHash::from_content(&value);
    bus.publish_without_context(CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: 2,
        threshold_n: 3,
        ..CiphernodeSelected::default()
    })?;
    publisher.send(PublisherBarrier).await?;
    let expires_at = Some(Utc::now() + chrono::Duration::hours(1));
    // A broadcast key document carries no party filter. A filter that names this node's party
    // (0) passes the relevance check, but not the payload check.
    let forged = DocumentPublishedNotification {
        key: key.clone(),
        meta: DocumentMeta::new(
            e3_id.clone(),
            DocumentKind::TrBFV,
            vec![e3_events::Filter::Item(0)],
            expires_at,
        ),
        ts: 100,
    };
    let genuine = DocumentPublishedNotification {
        key: key.clone(),
        meta: DocumentMeta::new(e3_id.clone(), DocumentKind::TrBFV, vec![], expires_at),
        ts: 101,
    };

    publisher.send(forged).await?;
    let Some(NetCommand::DhtGetRecord { correlation_id, .. }) =
        timeout(Duration::from_secs(1), commands.recv()).await?
    else {
        bail!("expected a fetch for the forged notification");
    };
    publisher.send(genuine).await?;
    net_events.send(NetEvent::DhtGetRecordSucceeded {
        key: key.clone(),
        correlation_id,
        value: value.clone(),
    })?;
    sleep(Duration::from_millis(200)).await;

    assert!(
        timeout(Duration::from_millis(200), commands.recv())
            .await
            .is_err(),
        "the document must not be fetched again for the correct notification"
    );
    let events = history.send(GetEvents::new()).await?;
    let received = events.iter().find_map(|event| match event.get_data() {
        InterfoldEventData::DocumentReceived(document) => Some(document.clone()),
        _ => None,
    });
    let received = received.expect("the correct notification delivers the document");
    assert!(received.meta.filter.is_empty());
    assert_eq!(received.value.extract_bytes(), value.extract_bytes());
    Ok(())
}

/// A peer can answer a fetch with another valid document. The node must not accept a document
/// for a key that it did not ask for.
#[actix::test]
async fn a_document_for_another_key_is_not_accepted() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut commands, net_events, _, history, _, publisher) =
        setup_test()?;
    let e3_id = E3id::new("substituted", 1);
    let document = |label: &'static [u8]| {
        EventConversionService::encryption_key_to_request(EncryptionKeyCreated {
            e3_id: e3_id.clone(),
            key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(label))),
            external: false,
        })
        .map(|request| request.expect("local key should produce a document").value)
    };
    let requested = document(b"requested key")?;
    let other = document(b"other key")?;
    bus.publish_without_context(CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: 2,
        threshold_n: 3,
        ..CiphernodeSelected::default()
    })?;
    publisher.send(PublisherBarrier).await?;
    publisher
        .send(DocumentPublishedNotification {
            key: ContentHash::from_content(&requested),
            meta: DocumentMeta::new(
                e3_id,
                DocumentKind::TrBFV,
                vec![],
                Some(Utc::now() + chrono::Duration::hours(1)),
            ),
            ts: 100,
        })
        .await?;
    let Some(NetCommand::DhtGetRecord { correlation_id, .. }) =
        timeout(Duration::from_secs(1), commands.recv()).await?
    else {
        bail!("expected a fetch");
    };

    net_events.send(NetEvent::DhtGetRecordSucceeded {
        key: ContentHash::from_content(&other),
        correlation_id,
        value: other,
    })?;

    sleep(Duration::from_millis(200)).await;
    let events = history.send(GetEvents::new()).await?;
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.get_data(), InterfoldEventData::DocumentReceived(_))),
        "a document for another key must not be accepted"
    );
    Ok(())
}

/// A forged notification that arrives before this node knows it is on the committee must not hide
/// the correct one: both are buffered, and the fetch accepts the document under the correct one.
#[actix::test]
async fn a_forged_notification_before_selection_does_not_hide_the_correct_one() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut commands, net_events, _, history, _, publisher) =
        setup_test()?;
    let e3_id = E3id::new("early-forged", 1);
    let value = EventConversionService::encryption_key_to_request(EncryptionKeyCreated {
        e3_id: e3_id.clone(),
        key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(b"public key"))),
        external: false,
    })?
    .expect("local key should produce a document")
    .value;
    let key = ContentHash::from_content(&value);
    let expires_at = Some(Utc::now() + chrono::Duration::hours(1));
    let notification = |filter| DocumentPublishedNotification {
        key: key.clone(),
        meta: DocumentMeta::new(e3_id.clone(), DocumentKind::TrBFV, filter, expires_at),
        ts: 100,
    };
    publisher
        .send(notification(vec![e3_events::Filter::Item(0)]))
        .await?;
    publisher.send(notification(vec![])).await?;

    bus.publish_without_context(CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: 2,
        threshold_n: 3,
        ..CiphernodeSelected::default()
    })?;
    let Some(NetCommand::DhtGetRecord { correlation_id, .. }) =
        timeout(Duration::from_secs(1), commands.recv()).await?
    else {
        bail!("expected a fetch after selection");
    };
    net_events.send(NetEvent::DhtGetRecordSucceeded {
        key,
        correlation_id,
        value: value.clone(),
    })?;
    sleep(Duration::from_millis(200)).await;

    let events = history.send(GetEvents::new()).await?;
    let received = events.iter().find_map(|event| match event.get_data() {
        InterfoldEventData::DocumentReceived(document) => Some(document.clone()),
        _ => None,
    });
    let received = received.expect("the buffered correct notification delivers the document");
    assert!(received.meta.filter.is_empty());
    Ok(())
}

/// Before selection, a forged notification with the correct filter must not hide the correct one
/// by expiring first: the buffer keeps the notification with the latest expiry per filter, and
/// selection does not deliver notifications that expired while the node waited.
#[actix::test]
async fn an_early_forged_notification_that_expires_first_does_not_hide_the_correct_one(
) -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut commands, net_events, _, history, _, publisher) =
        setup_test()?;
    let e3_id = E3id::new("early-expiring", 1);
    let value = EventConversionService::encryption_key_to_request(EncryptionKeyCreated {
        e3_id: e3_id.clone(),
        key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(b"public key"))),
        external: false,
    })?
    .expect("local key should produce a document")
    .value;
    let key = ContentHash::from_content(&value);
    let notification = |filter, lifetime| DocumentPublishedNotification {
        key: key.clone(),
        meta: DocumentMeta::new(
            e3_id.clone(),
            DocumentKind::TrBFV,
            filter,
            Some(Utc::now() + lifetime),
        ),
        ts: 100,
    };
    publisher
        .send(notification(
            vec![e3_events::Filter::Item(0)],
            chrono::Duration::hours(1),
        ))
        .await?;
    publisher
        .send(notification(vec![], chrono::Duration::milliseconds(300)))
        .await?;
    publisher
        .send(notification(vec![], chrono::Duration::hours(1)))
        .await?;
    sleep(Duration::from_millis(500)).await;

    bus.publish_without_context(CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: 2,
        threshold_n: 3,
        ..CiphernodeSelected::default()
    })?;
    let Some(NetCommand::DhtGetRecord { correlation_id, .. }) =
        timeout(Duration::from_secs(1), commands.recv()).await?
    else {
        bail!("expected a fetch after selection");
    };
    net_events.send(NetEvent::DhtGetRecordSucceeded {
        key,
        correlation_id,
        value: value.clone(),
    })?;
    sleep(Duration::from_millis(200)).await;

    let events = history.send(GetEvents::new()).await?;
    let received = events.iter().find_map(|event| match event.get_data() {
        InterfoldEventData::DocumentReceived(document) => Some(document.clone()),
        _ => None,
    });
    let received = received.expect("the correct notification delivers the document");
    assert!(received.meta.filter.is_empty());
    Ok(())
}

#[actix::test]
async fn new_peers_get_the_next_slots_after_slow_reads() -> Result<()> {
    let (_guard, bus, _tx, mut commands, events, _, history, _, publisher) = setup_test()?;
    let e3_id = E3id::new("123", 1);
    publisher
        .send(
            bus.event_from(
                CiphernodeSelected {
                    e3_id: e3_id.clone(),
                    threshold_m: 14,
                    threshold_n: 19,
                    ..CiphernodeSelected::default()
                },
                None,
            )?
            .into_sequenced(1),
        )
        .await?;
    let peers = [
        libp2p::PeerId::random(),
        libp2p::PeerId::random(),
        libp2p::PeerId::random(),
    ];
    let meta = DocumentMeta::new(
        e3_id.clone(),
        DocumentKind::TrBFV,
        vec![],
        Some(Utc::now() + chrono::Duration::hours(1)),
    );
    for index in 0..MAX_WAITING_FETCHES * 2 {
        publisher
            .send(DocumentIngress {
                propagation_source: Some(peers[index / MAX_WAITING_FETCHES]),
                notification: DocumentPublishedNotification {
                    key: ContentHash::from_content(&index.to_le_bytes()),
                    meta: meta.clone(),
                    ts: 100,
                },
            })
            .await?;
    }
    let mut pending = std::collections::VecDeque::new();
    for _ in 0..MAX_INFLIGHT_TRANSFERS {
        let Some(NetCommand::DhtGetRecord {
            key,
            correlation_id,
        }) = timeout(Duration::from_secs(1), commands.recv()).await?
        else {
            bail!("idle fetch slots must serve the concentrated queue");
        };
        pending.push_back((key, correlation_id));
    }
    assert_eq!(
        publisher.send(FetchBacklog).await?,
        (8, MAX_WAITING_FETCHES)
    );
    let value = EventConversionService::encryption_key_to_request(EncryptionKeyCreated {
        e3_id,
        key: Arc::new(EncryptionKey::new(
            1,
            ArcBytes::from_bytes(b"available key"),
        )),
        external: false,
    })?
    .unwrap()
    .value;
    let key = ContentHash::from_content(&value);
    publisher
        .send(DocumentIngress {
            propagation_source: Some(peers[2]),
            notification: DocumentPublishedNotification {
                key: key.clone(),
                meta,
                ts: 101,
            },
        })
        .await?;
    assert!(
        timeout(Duration::from_millis(100), commands.recv())
            .await
            .is_err(),
        "never exceed eight active GETs"
    );
    // Existing reads may complete slowly. Each completion releases a slot, including failures.
    let mut delivered = false;
    for _ in 0..2 {
        let (waiting, correlation_id) = pending.pop_front().unwrap();
        events.send(NetEvent::DhtGetRecordError {
            correlation_id,
            error: GetRecordError::Timeout {
                key: RecordKey::new(&waiting.0),
            },
        })?;
        let Some(NetCommand::DhtGetRecord {
            key: requested,
            correlation_id,
        }) = timeout(Duration::from_secs(2), commands.recv()).await?
        else {
            bail!("a completion must schedule the next peer");
        };
        if requested == key {
            events.send(NetEvent::DhtGetRecordSucceeded {
                key: key.clone(),
                correlation_id,
                value: value.clone(),
            })?;
            delivered = true;
            break;
        }
        pending.push_back((requested, correlation_id));
    }
    assert!(
        delivered,
        "the new peer must receive one of the next two released slots"
    );
    timeout(Duration::from_secs(2), async {
        loop {
            let found = history.send(GetEvents::<InterfoldEvent>::new()).await?.into_iter().any(|event|
                matches!(event.get_data(), InterfoldEventData::DocumentReceived(document) if document.value == value));
            if found { return anyhow::Ok(()); }
            sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    Ok(())
}

#[actix::test]
async fn concentrated_concurrent_documents_use_idle_fetch_capacity() -> Result<()> {
    let (_guard, bus, _tx, mut commands, events, _, history, _, publisher) = setup_test()?;
    let peer = libp2p::PeerId::random();
    let mut values = HashMap::new();
    // Two N=19 committees each need 54 remote documents. Keep all reads pending until queued.
    for e3 in 1..=2 {
        let e3_id = E3id::new(e3.to_string(), 1);
        for index in 0..54 {
            let request =
                EventConversionService::encryption_key_to_request(EncryptionKeyCreated {
                    e3_id: e3_id.clone(),
                    key: Arc::new(EncryptionKey::new(
                        index % 18 + 1,
                        ArcBytes::from_bytes(format!("document {index}").as_bytes()),
                    )),
                    external: false,
                })?
                .unwrap();
            let key = ContentHash::from_content(&request.value);
            values.insert(key.clone(), request.value);
            publisher
                .send(DocumentIngress {
                    propagation_source: Some(peer),
                    notification: DocumentPublishedNotification {
                        key,
                        meta: request.meta,
                        ts: bus.ts()?,
                    },
                })
                .await?;
        }
    }
    // The same concentrated source must also survive early buffering before committee selection.
    for e3 in 1..=2 {
        publisher
            .send(
                bus.event_from(
                    CiphernodeSelected {
                        e3_id: E3id::new(e3.to_string(), 1),
                        threshold_m: 14,
                        threshold_n: 19,
                        ..CiphernodeSelected::default()
                    },
                    None,
                )?
                .into_sequenced(e3 as u64),
            )
            .await?;
    }
    assert_eq!(publisher.send(FetchBacklog).await?, (8, 100));
    let mut pending = std::collections::VecDeque::new();
    let mut requested = std::collections::HashSet::new();
    while requested.len() < values.len() || !pending.is_empty() {
        while pending.len() < 8 && requested.len() < values.len() {
            let Some(NetCommand::DhtGetRecord {
                key,
                correlation_id,
            }) = timeout(Duration::from_secs(2), commands.recv()).await?
            else {
                bail!("every retained document must receive a slot");
            };
            assert!(
                requested.insert(key.clone()),
                "do not fetch a document twice"
            );
            pending.push_back((key, correlation_id));
        }
        assert!(
            timeout(Duration::from_millis(10), commands.recv())
                .await
                .is_err(),
            "bounded active reads"
        );
        let (key, correlation_id) = pending.pop_front().unwrap();
        events.send(NetEvent::DhtGetRecordSucceeded {
            value: values[&key].clone(),
            key,
            correlation_id,
        })?;
    }
    timeout(Duration::from_secs(5), async {
        loop {
            let received: std::collections::HashSet<_> = history
                .send(GetEvents::<InterfoldEvent>::new())
                .await?
                .into_iter()
                .filter_map(|event| match event.get_data() {
                    InterfoldEventData::DocumentReceived(document) => {
                        Some(ContentHash::from_content(&document.value))
                    }
                    _ => None,
                })
                .collect();
            if received.len() == values.len() {
                assert_eq!(received, values.keys().cloned().collect());
                return anyhow::Ok(());
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}
