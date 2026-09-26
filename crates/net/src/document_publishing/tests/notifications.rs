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
    let (_guard, bus, _net_cmd_tx, mut commands, net_events, _, _, _, publisher) = setup_test()?;
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
    timeout(Duration::from_secs(1), publisher.send(notification.clone())).await??;
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

    timeout(Duration::from_secs(1), publisher.send(notification)).await??;
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
        timeout(Duration::from_secs(1), publisher.send(notification)).await??;
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
