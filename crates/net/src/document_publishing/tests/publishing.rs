// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::domain::event_conversion::ReceivableDocument;
use crate::events::GossipPublishFailure;
use crate::net_interface_handle::NetEventSubscriber;
use e3_events::{
    DecryptionKeyShared, E3StageChanged, EventConstructorWithTimestamp, EventSource, Proof,
    ProofPayload, ProofType, SignedProofPayload, Unsequenced,
};

fn decryption_publication(e3_id: E3id) -> Result<PublishDocumentRequested> {
    let proof_type = ProofType::C4aSkShareDecryption;
    let proof = SignedProofPayload {
        payload: ProofPayload {
            e3_id: e3_id.clone(),
            proof_type,
            proof: Proof::new(
                proof_type.circuit_names()[0],
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&[2]),
            ),
        },
        signature: ArcBytes::from_bytes(&[3; 65]),
    };
    let value = ReceivableDocument::DecryptionKeyShared(DecryptionKeyShared {
        e3_id: e3_id.clone(),
        party_id: 0,
        node: "test-node".to_string(),
        signed_sk_decryption_proof: proof,
        signed_e_sm_decryption_proofs: vec![],
        external: false,
        roster_hash: [0; 32],
    })
    .to_bytes()?;
    Ok(PublishDocumentRequested {
        meta: DocumentMeta::new(
            e3_id,
            DocumentKind::TrBFV,
            vec![],
            Some(Utc::now() + chrono::Duration::hours(1)),
        ),
        value: ArcBytes::from_bytes(&value),
    })
}

#[actix::test]
async fn canonical_dkg_end_suppresses_late_publication() -> Result<()> {
    let (_guard, _bus, _net_cmd_tx, mut commands, _net_events, _, _, _, publisher) = setup_test()?;
    let e3_id = E3id::new("closed", 1);
    let stage = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        E3StageChanged {
            e3_id: e3_id.clone(),
            previous_stage: E3Stage::CommitteeFinalized,
            new_stage: E3Stage::KeyPublished,
        }
        .into(),
        None,
        1,
        None,
        EventSource::Evm,
    )
    .into_sequenced(1);
    publisher.send(stage).await?;

    let late = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        PublishDocumentRequested {
            meta: DocumentMeta::new(
                e3_id,
                DocumentKind::TrBFV,
                vec![],
                Some(Utc::now() + chrono::Duration::hours(1)),
            ),
            value: ArcBytes::from_bytes(b"late document"),
        }
        .into(),
        None,
        2,
        None,
        EventSource::Local,
    )
    .into_sequenced(2);
    publisher.send(late).await?;

    assert!(timeout(Duration::from_millis(200), commands.recv())
        .await
        .is_err());
    Ok(())
}

#[actix::test]
async fn late_c4_document_is_rejected_after_key_published() -> Result<()> {
    let (_guard, _bus, _net_cmd_tx, mut commands, _net_events, _, _, _, publisher) = setup_test()?;
    let e3_id = E3id::new("decrypt", 1);
    let stage = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        E3StageChanged {
            e3_id: e3_id.clone(),
            previous_stage: E3Stage::CommitteeFinalized,
            new_stage: E3Stage::KeyPublished,
        }
        .into(),
        None,
        1,
        None,
        EventSource::Evm,
    )
    .into_sequenced(1);
    publisher.send(stage).await?;

    let publication = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        decryption_publication(e3_id)?.into(),
        None,
        2,
        None,
        EventSource::Local,
    )
    .into_sequenced(2);
    publisher.send(publication).await?;

    assert!(timeout(Duration::from_millis(200), commands.recv())
        .await
        .is_err());
    Ok(())
}

#[actix::test]
async fn key_publication_cancels_an_inflight_dkg_announcement() -> Result<()> {
    let (_guard, _bus, _net_cmd_tx, mut commands, net_events, _, _, _, publisher) = setup_test()?;
    let e3_id = E3id::new("inflight", 1);
    let value = ArcBytes::from_bytes(b"dkg document");
    let publication = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        PublishDocumentRequested {
            meta: DocumentMeta::new(
                e3_id.clone(),
                DocumentKind::TrBFV,
                vec![],
                Some(Utc::now() + chrono::Duration::hours(1)),
            ),
            value,
        }
        .into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);
    publisher.send(publication).await?;
    let Some(NetCommand::DhtPutRecord {
        correlation_id,
        key,
        ..
    }) = timeout(Duration::from_secs(1), commands.recv()).await?
    else {
        bail!("expected DHT put");
    };

    let stage = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        E3StageChanged {
            e3_id,
            previous_stage: E3Stage::CommitteeFinalized,
            new_stage: E3Stage::KeyPublished,
        }
        .into(),
        None,
        2,
        None,
        EventSource::Evm,
    )
    .into_sequenced(2);
    publisher.send(stage).await?;
    net_events.send(NetEvent::DhtPutRecordSucceeded {
        correlation_id,
        key: key.clone(),
    })?;

    assert!(matches!(
        timeout(Duration::from_secs(1), commands.recv()).await?,
        Some(NetCommand::DhtRemoveRecords { keys }) if keys.contains(&key)
    ));
    assert!(timeout(Duration::from_millis(200), commands.recv())
        .await
        .is_err());
    Ok(())
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
async fn unavailable_gossip_peer_does_not_lose_the_publication() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut commands, net_events, _, _, _, _) = setup_test()?;
    let value = ArcBytes::from_bytes(b"retryable document");
    let key = ContentHash::from_content(&value);
    bus.publish_without_context(PublishDocumentRequested {
        meta: DocumentMeta::new(
            E3id::new("retry", 1),
            DocumentKind::TrBFV,
            vec![],
            Some(Utc::now() + chrono::Duration::hours(1)),
        ),
        value,
    })?;

    let Some(NetCommand::DhtPutRecord { correlation_id, .. }) =
        timeout(Duration::from_secs(1), commands.recv()).await?
    else {
        bail!("expected DHT put");
    };
    net_events.send(NetEvent::DhtPutRecordSucceeded {
        correlation_id,
        key: key.clone(),
    })?;
    let Some(NetCommand::GossipPublish { correlation_id, .. }) =
        timeout(Duration::from_secs(1), commands.recv()).await?
    else {
        bail!("expected gossip announcement");
    };
    net_events.send(NetEvent::GossipPublishError {
        correlation_id,
        error: Arc::new(GossipPublishFailure::NoPeersSubscribed),
    })?;

    assert!(matches!(
        timeout(Duration::from_secs(20), commands.recv()).await?,
        Some(NetCommand::DhtPutRecord { key: next_key, .. }) if next_key == key
    ));
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
