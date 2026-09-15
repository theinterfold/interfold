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

#[actix::test]
async fn targeted_lbfv_fetch_publishes_validated_document() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _rx, history, _, _) = setup_test()?;
    let (document, _) = lbfv_documents();
    let request = lbfv_fetch_request(&document, 1);
    let value = ArcBytes::from_bytes(&document.to_bytes()?);

    bus.publish_without_context(request.clone())?;
    let Some(NetCommand::DhtGetRecord {
        correlation_id,
        key,
    }) = timeout(Duration::from_secs(1), net_cmd_rx.recv())
        .await
        .expect("did not receive targeted DhtGetRecord")
    else {
        bail!("msg not as expected");
    };
    assert_eq!(key.as_ref(), request.request().content_hash.as_slice());
    net_evt_tx.send(NetEvent::DhtGetRecordSucceeded {
        key,
        correlation_id,
        value,
    })?;

    sleep(Duration::from_millis(100)).await;
    let events = history.send(GetEvents::new()).await?;
    let received = events.iter().find_map(|event| match event.get_data() {
        InterfoldEventData::LbfvKeyShareDocumentReceived(received) => Some(received),
        _ => None,
    });
    let received = received.expect("targeted fetch did not publish the l-BFV document");
    assert_eq!(received.document, document);
    assert_eq!(received.content_hash, request.request().content_hash);
    assert!(!events.iter().any(|event| matches!(
        event.get_data(),
        InterfoldEventData::LbfvKeyShareDocumentFetchFailed(_)
    )));
    Ok(())
}

#[actix::test]
async fn targeted_lbfv_fetch_reports_unavailable_after_bounded_retries() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _rx, history, _, _) = setup_test()?;
    let (document, _) = lbfv_documents();
    let request = lbfv_fetch_request(&document, 2);

    bus.publish_without_context(request.clone())?;
    for _ in 0..4 {
        let Some(NetCommand::DhtGetRecord {
            correlation_id,
            key,
        }) = timeout(Duration::from_secs(15), net_cmd_rx.recv())
            .await
            .expect("did not receive targeted DhtGetRecord retry")
        else {
            bail!("msg not as expected");
        };
        net_evt_tx.send(NetEvent::DhtGetRecordError {
            correlation_id,
            error: GetRecordError::Timeout {
                key: RecordKey::new(&key),
            },
        })?;
    }

    sleep(Duration::from_millis(100)).await;
    let events = history.send(GetEvents::new()).await?;
    let failure = events.iter().find_map(|event| match event.get_data() {
        InterfoldEventData::LbfvKeyShareDocumentFetchFailed(failure) => Some(failure.failure()),
        _ => None,
    });
    let failure = failure.expect("targeted fetch did not publish an unavailable failure");
    assert_eq!(
        failure.failure_class,
        LbfvKeyShareDocumentFetchFailureClass::Unavailable
    );
    assert_eq!(failure.attempt, 2);
    assert!(failure.retry_at.is_some());
    assert!(!events.iter().any(|event| matches!(
        event.get_data(),
        InterfoldEventData::LbfvKeyShareDocumentReceived(_)
    )));
    Ok(())
}

#[actix::test]
async fn targeted_lbfv_fetch_rejects_malformed_and_wrong_role_documents() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _rx, history, _, _) = setup_test()?;
    let (public_key, relinearization_key) = lbfv_documents();

    let malformed = ArcBytes::from_bytes(b"not an l-BFV document");
    let mut malformed_request = lbfv_fetch_request(&public_key, 1);
    let LbfvKeyShareDocumentFetchRequested::V1(identity) = &mut malformed_request;
    identity.content_hash = e3_events::lbfv_document_hash(&malformed);
    bus.publish_without_context(malformed_request)?;
    let Some(NetCommand::DhtGetRecord {
        correlation_id,
        key,
    }) = timeout(Duration::from_secs(1), net_cmd_rx.recv())
        .await
        .expect("did not receive malformed-document fetch")
    else {
        bail!("msg not as expected");
    };
    net_evt_tx.send(NetEvent::DhtGetRecordSucceeded {
        correlation_id,
        key,
        value: malformed,
    })?;

    let mut wrong_role_request = lbfv_fetch_request(&relinearization_key, 1);
    let LbfvKeyShareDocumentFetchRequested::V1(identity) = &mut wrong_role_request;
    identity.role = LbfvKeyShareDocumentRole::PublicKey;
    let wrong_role_value = ArcBytes::from_bytes(&relinearization_key.to_bytes()?);
    bus.publish_without_context(wrong_role_request)?;
    let Some(NetCommand::DhtGetRecord {
        correlation_id,
        key,
    }) = timeout(Duration::from_secs(1), net_cmd_rx.recv())
        .await
        .expect("did not receive wrong-role fetch")
    else {
        bail!("msg not as expected");
    };
    net_evt_tx.send(NetEvent::DhtGetRecordSucceeded {
        correlation_id,
        key,
        value: wrong_role_value,
    })?;

    sleep(Duration::from_millis(100)).await;
    let events = history.send(GetEvents::new()).await?;
    let failures: Vec<_> = events
        .iter()
        .filter_map(|event| match event.get_data() {
            InterfoldEventData::LbfvKeyShareDocumentFetchFailed(failure) => Some(failure.failure()),
            _ => None,
        })
        .collect();
    assert_eq!(failures.len(), 2);
    assert!(failures.iter().all(|failure| {
        failure.failure_class == LbfvKeyShareDocumentFetchFailureClass::InvalidData
            && failure.retry_at.is_none()
    }));
    assert!(!events.iter().any(|event| matches!(
        event.get_data(),
        InterfoldEventData::LbfvKeyShareDocumentReceived(_)
    )));
    Ok(())
}
