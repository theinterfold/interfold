// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

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
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _rx, history, errors, _) =
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
    Ok(())
}

#[actix::test]
async fn generic_lbfv_notification_does_not_trigger_a_fetch() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _rx, history, _, _) = setup_test()?;
    let e3_id = E3id::new("9", 1);

    bus.publish_without_context(CiphernodeSelected {
        e3_id: e3_id.clone(),
        party_id: 1,
        threshold_m: 1,
        threshold_n: 2,
        ..CiphernodeSelected::default()
    })?;
    net_evt_tx.send(NetEvent::GossipData(
        GossipData::DocumentPublishedNotification(DocumentPublishedNotification {
            key: ContentHash::from_content(b"unsolicited l-BFV document"),
            meta: DocumentMeta::new(
                e3_id,
                DocumentKind::LbfvKeyShare,
                vec![],
                Some(Utc::now() + chrono::Duration::days(1)),
            ),
            ts: 100,
        }),
    ))?;

    assert!(timeout(Duration::from_millis(250), net_cmd_rx.recv())
        .await
        .is_err());
    let events = history.send(GetEvents::new()).await?;
    assert!(!events.iter().any(|event| matches!(
        event.get_data(),
        InterfoldEventData::LbfvKeyShareDocumentReceived(_)
    )));
    Ok(())
}
