// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::domain::event_conversion::ReceivableDocument;
use crate::events::GossipPublishFailure;
use crate::net_interface_handle::{NetEventChannel, NetEventSubscriber};
use e3_events::{
    DecryptionKeyShared, E3StageChanged, EffectsEnabled, EventConstructorWithTimestamp,
    EventSource, Proof, ProofPayload, ProofType, SignedProofPayload, SyncEnded, Unsequenced,
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

    assert!(matches!(
        commands.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    Ok(())
}

/// `KeyPublished` stops the announcement and the upload in flight: their late answers lead to
/// nothing. (Cancelling scheduled retries is not observable here: the timer of a removed
/// publication finds no publication and does nothing.)
#[actix::test]
async fn key_publication_stops_the_announcement_and_upload_in_flight() -> Result<()> {
    tokio::time::pause();
    let (_guard, _bus, net_cmd_tx, commands, net_events, _, _, _, publisher) = setup_test()?;
    let mut commands = Commands::new(commands);
    let e3_id = E3id::new("inflight", 1);
    let publication = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        publish_request("inflight", b"dkg document").into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);
    publisher.send(publication).await?;
    let store = commands.take(is_store_local).await?;
    let NetCommand::DhtPutRecord {
        correlation_id: upload,
        key,
        ..
    } = commands.take(is_upload).await?
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
    // A busy command queue delays the cleanup commands but does not drop them.
    while net_cmd_tx.try_send(NetCommand::Shutdown).is_ok() {}
    publisher.send(stage).await?;
    assert!(matches!(
        commands.take(|command| matches!(command, NetCommand::DhtRemoveRecords { .. })).await?,
        NetCommand::DhtRemoveRecords { keys } if keys.contains(&key)
    ));
    // The put in the swarm ends too, not only the future that waits for it.
    assert!(matches!(
        commands.take(|command| matches!(command, NetCommand::DhtCancelPut { .. })).await?,
        NetCommand::DhtCancelPut { key: cancelled } if cancelled == key
    ));

    // Late answers reach nothing: the announcement does not gossip after its local store, and
    // the failed upload makes no second attempt.
    net_events.send(NetEvent::DhtStoreLocalSucceeded {
        correlation_id: correlation(&store),
        key: key.clone(),
    })?;
    net_events.send(upload_failed(upload, &key))?;
    publisher.send(PublisherBarrier).await?;
    // Nor does anything run later: no retry, refresh or re-announcement.
    assert!(
        !commands
            .arrives_within(Duration::from_secs(3_600), |command| {
                is_store_local(command) || is_upload(command) || is_announcement(command)
            })
            .await
    );
    Ok(())
}

/// Startup publishes chain history between `EffectsEnabled` and `SyncEnded`. A recovered
/// publication waits for `SyncEnded`, so a document of an E3 that closed in that history never
/// reaches the network.
#[actix::test]
async fn recovered_publications_wait_for_the_end_of_the_sync() -> Result<()> {
    tokio::time::pause();
    let closed = publish_request("closed-in-history", b"closed document");
    let open = publish_request("open", b"open document");
    let open_key = ContentHash::from_content(&open.value);
    let recovered = RecoveredDocumentState {
        publications: vec![closed.clone(), open],
        ..RecoveredDocumentState::default()
    };
    let (_guard, _bus, _net_cmd_tx, commands, _net_events, _, _, _, publisher) =
        setup_startup_test(recovered)?;
    let mut commands = Commands::new(commands);
    let is_dht_write = |command: &NetCommand| is_store_local(command) || is_upload(command);

    publisher
        .send(startup_event(EffectsEnabled::new().into(), 1))
        .await?;
    assert!(
        !commands
            .arrives_within(Duration::from_secs(60), is_dht_write)
            .await,
        "no publication runs before the chain history arrives"
    );

    publisher.send(key_published(&closed.meta.e3_id, 2)).await?;
    publisher
        .send(startup_event(SyncEnded::new().into(), 3))
        .await?;

    for accept in [is_store_local, is_upload] {
        let command = commands.take(accept).await?;
        assert!(matches!(
            command,
            NetCommand::DhtStoreLocal { key, .. } | NetCommand::DhtPutRecord { key, .. }
                if key == open_key
        ));
    }
    assert!(
        !commands
            .arrives_within(Duration::from_secs(60), is_dht_write)
            .await,
        "the publication of the closed E3 never runs"
    );
    Ok(())
}

/// Replay brings back publication requests whose documents have expired, and startup holds
/// publications until `SyncEnded`. Expired requests must not fill the outbox, or a document that
/// the chain history creates in that window is refused and never published.
#[actix::test]
async fn expired_replay_does_not_block_fresh_publication() -> Result<()> {
    tokio::time::pause();
    let (_guard, _bus, _net_cmd_tx, commands, _net_events, _, _, _, publisher) =
        setup_startup_test(RecoveredDocumentState::default())?;
    let mut commands = Commands::new(commands);
    let is_dht_write = |command: &NetCommand| is_store_local(command) || is_upload(command);

    let mut seq = 0;
    for index in 0..MAX_PENDING_PUBLICATIONS {
        let mut expired =
            publish_request(&format!("expired-{index}"), index.to_string().as_bytes());
        expired.meta.expires_at = Utc::now() - chrono::Duration::seconds(1);
        seq += 1;
        publisher
            .send(startup_event(
                InterfoldEventData::PublishDocumentRequested(expired),
                seq,
            ))
            .await?;
    }
    publisher
        .send(startup_event(EffectsEnabled::new().into(), seq + 1))
        .await?;
    let fresh = publish_request("fresh", b"fresh document");
    let fresh_key = ContentHash::from_content(&fresh.value);
    publisher
        .send(startup_event(
            InterfoldEventData::PublishDocumentRequested(fresh),
            seq + 2,
        ))
        .await?;
    publisher.send(PublisherBarrier).await?;
    assert!(
        !commands
            .arrives_within(Duration::from_secs(60), is_dht_write)
            .await,
        "no publication runs before the chain history arrives"
    );

    publisher
        .send(startup_event(SyncEnded::new().into(), seq + 3))
        .await?;
    for accept in [is_store_local, is_upload] {
        let command = commands.take(accept).await?;
        assert!(matches!(
            command,
            NetCommand::DhtStoreLocal { key, .. } | NetCommand::DhtPutRecord { key, .. }
                if key == fresh_key
        ));
    }
    assert!(
        !commands
            .arrives_within(Duration::from_secs(60), is_dht_write)
            .await,
        "no expired document is written"
    );
    Ok(())
}

/// A busy network command queue holds the publisher's cleanup in one bounded queue with one
/// waiting send, not in a task per command. The cleanup that waits behind that send goes out
/// together once the queue has room.
#[actix::test]
async fn cleanup_waits_for_a_busy_command_queue_in_one_queue() -> Result<()> {
    tokio::time::pause();
    let closing: Vec<_> = ["first", "second", "third"]
        .into_iter()
        .map(|e3| publish_request(e3, e3.as_bytes()))
        .collect();
    let keys: Vec<_> = closing
        .iter()
        .map(|publication| ContentHash::from_content(&publication.value))
        .collect();
    let recovered = RecoveredDocumentState {
        publications: closing.clone(),
        ..RecoveredDocumentState::default()
    };
    let (_guard, _bus, net_cmd_tx, commands, _net_events, _, _, _, publisher) =
        setup_startup_test(recovered)?;
    let mut commands = Commands::new(commands);

    while net_cmd_tx.try_send(NetCommand::Shutdown).is_ok() {}
    for (seq, publication) in (1..).zip(&closing) {
        publisher
            .send(key_published(&publication.meta.e3_id, seq))
            .await?;
    }

    let is_removal = |command: &NetCommand| matches!(command, NetCommand::DhtRemoveRecords { .. });
    assert!(matches!(
        commands.take(is_removal).await?,
        NetCommand::DhtRemoveRecords { keys: removed } if removed == keys[..1]
    ));
    assert!(matches!(
        commands.take(is_removal).await?,
        NetCommand::DhtRemoveRecords { keys: removed } if removed == keys[1..]
    ));
    assert!(
        !commands
            .arrives_within(Duration::from_secs(60), is_removal)
            .await
    );
    Ok(())
}

/// The DHT store is in memory. At `SyncEnded` a restarted node stores the received documents of
/// open E3s in it again, so that it still serves them, and prunes them when their E3 closes.
#[actix::test]
async fn received_documents_are_stored_again_after_the_sync() -> Result<()> {
    tokio::time::pause();
    let received = |e3: &str, value: &[u8]| {
        let request = publish_request(e3, value);
        DocumentReceived {
            meta: request.meta,
            value: request.value,
        }
    };
    let closed = received("closed-in-history", b"closed document");
    let open = received("open", b"open document");
    let open_key = ContentHash::from_content(&open.value);
    let mut recovered = RecoveredDocumentState::default();
    recovered.restorable.push(closed.clone(), Utc::now());
    recovered.restorable.push(open.clone(), Utc::now());
    let (_guard, _bus, _net_cmd_tx, commands, net_events, _, _, _, publisher) =
        setup_startup_test(recovered)?;
    let mut commands = Commands::new(commands);

    publisher
        .send(startup_event(EffectsEnabled::new().into(), 1))
        .await?;
    publisher.send(key_published(&closed.meta.e3_id, 2)).await?;
    assert!(
        !commands
            .arrives_within(Duration::from_secs(60), is_store_local)
            .await,
        "nothing is stored before the chain history arrives"
    );
    publisher
        .send(startup_event(SyncEnded::new().into(), 3))
        .await?;

    let NetCommand::DhtStoreLocal {
        correlation_id,
        key,
        value,
        ..
    } = commands.take(is_store_local).await?
    else {
        bail!("expected a local store");
    };
    assert_eq!((&key, &value), (&open_key, &open.value));
    let is_removal = |command: &NetCommand| matches!(command, NetCommand::DhtRemoveRecords { .. });
    let removes_open_key = |command: NetCommand| match command {
        NetCommand::DhtRemoveRecords { keys } => keys == vec![open_key.clone()],
        _ => false,
    };

    // The open E3 closes while its document is being stored: the closure removes the record,
    // and the store's answer removes it once more, in case the store came after the removal.
    // A failed store can have stored the record too.
    publisher.send(key_published(&open.meta.e3_id, 4)).await?;
    assert!(removes_open_key(commands.take(is_removal).await?));
    // Many more E3s close before the store answers, so the list of closed E3s drops this one.
    for index in 0..1_024u64 {
        let e3_id = E3id::new(format!("later-{index}"), 1);
        publisher.send(key_published(&e3_id, 5 + index)).await?;
    }
    net_events.send(NetEvent::DhtStoreLocalError {
        correlation_id,
        error: libp2p::kad::store::Error::MaxRecords,
    })?;
    assert!(removes_open_key(commands.take(is_removal).await?));
    assert!(
        !commands
            .arrives_within(Duration::from_secs(60), is_store_local)
            .await,
        "the document of the closed E3 is not stored"
    );
    Ok(())
}

/// Recovery reads only the receipts of the E3s in the committee snapshot, which can predate a
/// selection that replay restores. A receipt that replay delivers before `SyncEnded` is stored
/// again too, unless its E3 closed; a receipt that recovery already read is stored once.
#[actix::test]
async fn receipts_that_replay_delivers_are_stored_again_once() -> Result<()> {
    tokio::time::pause();
    let received = |e3: &str, value: &[u8]| {
        let request = publish_request(e3, value);
        DocumentReceived {
            meta: request.meta,
            value: request.value,
        }
    };
    let recovered_receipt = received("in-snapshot", b"recovered document");
    let replayed_receipt = received("selected-after-snapshot", b"replayed document");
    let closed_receipt = received("closed", b"closed document");
    let mut recovered = RecoveredDocumentState::default();
    recovered.received.insert((
        recovered_receipt.meta.e3_id.clone(),
        ContentHash::from_content(&recovered_receipt.value),
    ));
    recovered
        .restorable
        .push(recovered_receipt.clone(), Utc::now());
    recovered
        .closed_e3s
        .push_back(closed_receipt.meta.e3_id.clone());
    let (_guard, _bus, _net_cmd_tx, commands, net_events, _, _, _, publisher) =
        setup_startup_test(recovered)?;
    let mut commands = Commands::new(commands);

    for (seq, receipt) in (1..).zip([&recovered_receipt, &replayed_receipt, &closed_receipt]) {
        publisher
            .send(startup_event(
                InterfoldEventData::DocumentReceived(receipt.clone()),
                seq,
            ))
            .await?;
    }
    publisher
        .send(startup_event(EffectsEnabled::new().into(), 4))
        .await?;
    assert!(
        !commands
            .arrives_within(Duration::from_secs(60), is_store_local)
            .await,
        "nothing is stored before the chain history arrives"
    );
    publisher
        .send(startup_event(SyncEnded::new().into(), 5))
        .await?;

    let mut stored = Vec::new();
    for _ in 0..2 {
        let NetCommand::DhtStoreLocal {
            correlation_id,
            key,
            ..
        } = commands.take(is_store_local).await?
        else {
            bail!("expected a local store");
        };
        stored.push(key.clone());
        net_events.send(NetEvent::DhtStoreLocalSucceeded {
            correlation_id,
            key,
        })?;
    }
    assert_eq!(
        stored,
        [&recovered_receipt, &replayed_receipt]
            .map(|receipt| ContentHash::from_content(&receipt.value))
    );
    assert!(
        !commands
            .arrives_within(Duration::from_secs(60), is_store_local)
            .await,
        "a receipt that recovery read is stored once, and the closed E3's receipt never"
    );
    Ok(())
}

fn key_published(e3_id: &E3id, seq: u64) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        E3StageChanged {
            e3_id: e3_id.clone(),
            previous_stage: E3Stage::CommitteeFinalized,
            new_stage: E3Stage::KeyPublished,
        }
        .into(),
        None,
        u128::from(seq),
        None,
        EventSource::Evm,
    )
    .into_sequenced(seq)
}

fn startup_event(data: InterfoldEventData, seq: u64) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        data,
        None,
        u128::from(seq),
        None,
        EventSource::Local,
    )
    .into_sequenced(seq)
}

#[actix::test]
async fn test_publishes_document() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, commands, net_evt_tx, _net_evt_rx, _, _, _) = setup_test()?;
    let mut commands = Commands::in_real_time(commands);
    let value = ArcBytes::from_bytes(b"I am a special document");
    let expires_at = Some(Utc::now() + chrono::Duration::days(1));
    let e3_id = E3id::new("1243", 1);

    // 1. Send a request to publish
    bus.publish_without_context(PublishDocumentRequested {
        meta: DocumentMeta::new(e3_id, DocumentKind::TrBFV, vec![], expires_at),
        value: value.clone(),
    })?;

    // 2. The publisher first stores the document in its own DHT store
    let NetCommand::DhtStoreLocal {
        correlation_id,
        expires,
        value: stored,
        key,
    } = commands.take(is_store_local).await?
    else {
        bail!("expected a local store");
    };
    assert_eq!(stored.extract_bytes(), b"I am a special document".to_vec());
    assert!(
        is_between(expires.unwrap(), days_from_now(0), days_from_now(1)),
        "Expiry was not set"
    );
    net_evt_tx.send(NetEvent::DhtStoreLocalSucceeded {
        correlation_id,
        key: key.clone(),
    })?;

    // 3. Then it announces the document over gossip
    let NetCommand::GossipPublish {
        topic,
        correlation_id,
        data: GossipData::DocumentPublishedNotification(notification),
        delivery_id: Some(_),
    } = commands.take(is_announcement).await?
    else {
        bail!("expected an announcement");
    };
    net_evt_tx.send(NetEvent::GossipPublished {
        correlation_id,
        message_id: libp2p::gossipsub::MessageId::new(&[1, 2, 3]),
    })?;
    assert_eq!(topic, "topic");
    assert_eq!(notification.meta.e3_id, E3id::new("1243", 1));
    assert_eq!(notification.key, key);

    // 4. And it uploads the document to the DHT on its own schedule
    let NetCommand::DhtPutRecord {
        correlation_id,
        expires,
        value: uploaded,
        key,
    } = commands.take(is_upload).await?
    else {
        bail!("expected a DHT put");
    };
    assert_eq!(key, notification.key);
    assert_eq!(
        uploaded.extract_bytes(),
        b"I am a special document".to_vec()
    );
    assert!(
        is_between(expires.unwrap(), days_from_now(0), days_from_now(1)),
        "Expiry was not set"
    );
    net_evt_tx.send(NetEvent::DhtPutRecordSucceeded {
        correlation_id,
        key,
    })?;
    Ok(())
}

fn publish_request(e3: &str, value: &[u8]) -> PublishDocumentRequested {
    PublishDocumentRequested {
        meta: DocumentMeta::new(
            E3id::new(e3, 1),
            DocumentKind::TrBFV,
            vec![],
            Some(Utc::now() + chrono::Duration::hours(1)),
        ),
        value: ArcBytes::from_bytes(value),
    }
}

/// Commands from the publisher. Announcements and uploads run at the same time, so a test takes
/// the next command of the kind it expects and keeps the others for later.
struct Commands {
    rx: mpsc::Receiver<NetCommand>,
    pending: VecDeque<NetCommand>,
    /// How long `take` waits for a matching command.
    wait: Duration,
}

impl Commands {
    /// For tests with paused time: the clock jumps through the publisher's retry delays.
    fn new(rx: mpsc::Receiver<NetCommand>) -> Self {
        Self {
            rx,
            pending: VecDeque::new(),
            wait: Duration::from_secs(600),
        }
    }

    /// For tests in real time, where the expected command comes at once.
    fn in_real_time(rx: mpsc::Receiver<NetCommand>) -> Self {
        Self {
            wait: Duration::from_secs(30),
            ..Self::new(rx)
        }
    }

    /// The next command that `accept` matches. Commands that it does not match stay pending.
    async fn take(&mut self, accept: impl Fn(&NetCommand) -> bool) -> Result<NetCommand> {
        if let Some(index) = self.pending.iter().position(&accept) {
            return self
                .pending
                .remove(index)
                .ok_or_else(|| anyhow::anyhow!("pending command disappeared"));
        }
        // One deadline for the whole wait: unrelated commands, such as upload retries, must not
        // keep a test waiting forever for a command that never comes.
        let deadline = tokio::time::Instant::now() + self.wait;
        loop {
            let command = tokio::time::timeout_at(deadline, self.rx.recv())
                .await
                .map_err(|_| anyhow::anyhow!("no matching command within {:?}", self.wait))?
                .ok_or_else(|| anyhow::anyhow!("command channel closed"))?;
            if accept(&command) {
                return Ok(command);
            }
            self.pending.push_back(command);
        }
    }

    /// Whether a command that `accept` matches is pending or arrives within `wait`.
    async fn arrives_within(
        &mut self,
        wait: Duration,
        accept: impl Fn(&NetCommand) -> bool,
    ) -> bool {
        if self.pending.iter().any(&accept) {
            return true;
        }
        let deadline = tokio::time::Instant::now() + wait;
        while let Ok(Some(command)) = tokio::time::timeout_at(deadline, self.rx.recv()).await {
            let matched = accept(&command);
            self.pending.push_back(command);
            if matched {
                return true;
            }
        }
        false
    }
}

fn is_store_local(command: &NetCommand) -> bool {
    matches!(command, NetCommand::DhtStoreLocal { .. })
}

fn is_upload(command: &NetCommand) -> bool {
    matches!(command, NetCommand::DhtPutRecord { .. })
}

fn is_announcement(command: &NetCommand) -> bool {
    matches!(
        command,
        NetCommand::GossipPublish {
            data: GossipData::DocumentPublishedNotification(_),
            ..
        }
    )
}

fn correlation(command: &NetCommand) -> CorrelationId {
    command
        .correlation_id()
        .expect("publisher commands carry a correlation id")
}

/// Answer the next local store with success.
async fn store_succeeds(commands: &mut Commands, net_events: &NetEventChannel) -> Result<()> {
    let NetCommand::DhtStoreLocal {
        correlation_id,
        key,
        ..
    } = commands.take(is_store_local).await?
    else {
        bail!("expected a local store");
    };
    net_events.send(NetEvent::DhtStoreLocalSucceeded {
        correlation_id,
        key,
    })?;
    Ok(())
}

fn upload_failed(correlation_id: CorrelationId, key: &ContentHash) -> NetEvent {
    NetEvent::DhtPutRecordError {
        correlation_id,
        error: crate::events::PutOrStoreError::PutRecordError(PutRecordError::QuorumFailed {
            key: RecordKey::new(key),
            success: vec![],
            quorum: NonZero::new(1).unwrap(),
        }),
    }
}

#[actix::test]
async fn failed_announcement_is_retried_without_another_upload() -> Result<()> {
    tokio::time::pause();
    let (_guard, bus, _net_cmd_tx, commands, net_events, _, _, _, _) = setup_test()?;
    let mut commands = Commands::new(commands);
    let request = publish_request("retry", b"retryable document");
    let key = ContentHash::from_content(&request.value);
    bus.publish_without_context(request)?;

    let upload = commands.take(is_upload).await?;
    net_events.send(NetEvent::DhtPutRecordSucceeded {
        correlation_id: correlation(&upload),
        key: key.clone(),
    })?;
    store_succeeds(&mut commands, &net_events).await?;
    let announcement = commands.take(is_announcement).await?;
    net_events.send(NetEvent::GossipPublishError {
        correlation_id: correlation(&announcement),
        error: Arc::new(GossipPublishFailure::NoPeersSubscribed),
    })?;

    store_succeeds(&mut commands, &net_events).await?;
    assert!(matches!(
        commands.take(is_announcement).await?,
        NetCommand::GossipPublish {
            data: GossipData::DocumentPublishedNotification(notification),
            ..
        } if notification.key == key
    ));
    assert!(
        !commands.pending.iter().any(is_upload),
        "the retried announcement uploaded the document again"
    );
    Ok(())
}

#[actix::test]
async fn replicated_document_is_announced_again_without_another_upload() -> Result<()> {
    tokio::time::pause();
    let (_guard, bus, _net_cmd_tx, commands, net_events, _, _, _, _) = setup_test()?;
    let mut commands = Commands::new(commands);
    let request = publish_request("announce", b"replicated document");
    let key = ContentHash::from_content(&request.value);
    bus.publish_without_context(request)?;

    let upload = commands.take(is_upload).await?;
    net_events.send(NetEvent::DhtPutRecordSucceeded {
        correlation_id: correlation(&upload),
        key: key.clone(),
    })?;
    for _ in 0..3 {
        store_succeeds(&mut commands, &net_events).await?;
        let NetCommand::GossipPublish {
            correlation_id,
            data: GossipData::DocumentPublishedNotification(notification),
            ..
        } = commands.take(is_announcement).await?
        else {
            bail!("expected an announcement");
        };
        assert_eq!(notification.key, key);
        net_events.send(NetEvent::GossipPublished {
            correlation_id,
            message_id: libp2p::gossipsub::MessageId::new(&[1]),
        })?;
    }
    assert!(
        !commands.pending.iter().any(is_upload),
        "an announcement uploaded the document again"
    );
    Ok(())
}

#[actix::test]
async fn only_one_document_replicates_at_a_time() -> Result<()> {
    tokio::time::pause();
    let (_guard, bus, _net_cmd_tx, commands, net_events, _, _, _, _) = setup_test()?;
    let mut commands = Commands::new(commands);
    let first = publish_request("queue", b"first document");
    let second = publish_request("queue", b"second document");
    let first_key = ContentHash::from_content(&first.value);
    let second_key = ContentHash::from_content(&second.value);
    bus.publish_without_context(first)?;
    bus.publish_without_context(second)?;

    let NetCommand::DhtPutRecord {
        correlation_id,
        key,
        ..
    } = commands.take(is_upload).await?
    else {
        bail!("expected DHT put");
    };
    let (active, waiting) = if key == first_key {
        (first_key, second_key)
    } else {
        (second_key, first_key)
    };
    assert_eq!(key, active);
    assert!(
        !commands
            .arrives_within(Duration::from_secs(60), is_upload)
            .await,
        "a second upload started while the first one was in flight"
    );

    net_events.send(NetEvent::DhtPutRecordSucceeded {
        correlation_id,
        key: active,
    })?;
    assert!(matches!(
        commands.take(is_upload).await?,
        NetCommand::DhtPutRecord { key, .. } if key == waiting
    ));
    Ok(())
}

#[actix::test]
async fn a_failing_upload_does_not_block_the_announcement() -> Result<()> {
    tokio::time::pause();
    let (_guard, bus, _net_cmd_tx, commands, net_events, _, _, errors, _) = setup_test()?;
    let mut commands = Commands::new(commands);
    let request = publish_request("unreachable", b"document whose upload fails");
    let key = ContentHash::from_content(&request.value);
    bus.publish_without_context(request)?;

    // The upload hangs, as on a dealer whose uplink cannot reach the closest peers in time.
    let upload = commands.take(is_upload).await?;
    store_succeeds(&mut commands, &net_events).await?;
    assert!(matches!(
        commands.take(is_announcement).await?,
        NetCommand::GossipPublish {
            data: GossipData::DocumentPublishedNotification(notification),
            ..
        } if notification.key == key
    ));

    // Every attempt of the upload then fails, and announcements continue.
    net_events.send(upload_failed(correlation(&upload), &key))?;
    for _ in 1..DHT_PUT_ATTEMPTS {
        let retry = commands.take(is_upload).await?;
        net_events.send(upload_failed(correlation(&retry), &key))?;
    }
    let failure = errors.send(TakeEvents::new(1)).await?;
    let failure: InterfoldError = failure.events.first().unwrap().try_into()?;
    assert!(failure.message.contains("DHT put record failed"));
    store_succeeds(&mut commands, &net_events).await?;
    commands.take(is_announcement).await?;
    Ok(())
}

#[actix::test]
async fn the_announcement_waits_for_the_local_store() -> Result<()> {
    tokio::time::pause();
    let (_guard, bus, _net_cmd_tx, commands, net_events, _, _, _, _) = setup_test()?;
    let mut commands = Commands::new(commands);
    let request = publish_request("ordered", b"document stored before it is announced");
    let key = ContentHash::from_content(&request.value);
    bus.publish_without_context(request)?;

    let store = commands.take(is_store_local).await?;
    assert!(
        !commands
            .arrives_within(Duration::from_secs(20), is_announcement)
            .await,
        "the document was announced before the local store held it"
    );
    net_events.send(NetEvent::DhtStoreLocalSucceeded {
        correlation_id: correlation(&store),
        key,
    })?;
    commands.take(is_announcement).await?;
    Ok(())
}

#[actix::test]
async fn a_failed_local_store_retries_without_an_announcement() -> Result<()> {
    tokio::time::pause();
    let (_guard, bus, _net_cmd_tx, commands, net_events, _, _, _, _) = setup_test()?;
    let mut commands = Commands::new(commands);
    let request = publish_request("full", b"document for a full store");
    let key = ContentHash::from_content(&request.value);
    bus.publish_without_context(request)?;

    let first = commands.take(is_store_local).await?;
    net_events.send(NetEvent::DhtStoreLocalError {
        correlation_id: correlation(&first),
        error: libp2p::kad::store::Error::MaxRecords,
    })?;
    let second = commands.take(is_store_local).await?;
    assert!(
        !commands.pending.iter().any(is_announcement),
        "the document was announced although the local store refused it"
    );
    net_events.send(NetEvent::DhtStoreLocalSucceeded {
        correlation_id: correlation(&second),
        key,
    })?;
    commands.take(is_announcement).await?;
    Ok(())
}

#[actix::test]
async fn expired_document_is_rejected_without_a_dht_write() -> Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("expired-document");
    let (net_cmd_tx, mut net_cmd_rx) = mpsc::channel(1);
    let net_evt_tx = NetEventChannel::new(1);
    let _net_evt_rx = net_evt_tx.subscribe();
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
async fn a_failed_read_releases_its_slot_before_retry_backoff() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, mut net_cmd_rx, net_evt_tx, _net_evt_rx, _, errors, publisher) =
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

    let Some(NetCommand::DhtGetRecord { correlation_id, .. }) =
        timeout(Duration::from_secs(2), net_cmd_rx.recv()).await?
    else {
        bail!("expected a DHT read");
    };
    net_evt_tx.send(NetEvent::DhtGetRecordError {
        correlation_id,
        error: GetRecordError::Timeout {
            key: RecordKey::new(&cid),
        },
    })?;
    let errors = timeout(Duration::from_secs(2), errors.send(TakeEvents::new(1))).await??;
    let error: InterfoldError = errors.events.first().unwrap().try_into()?;
    assert!(error.message.contains("DHT get record failed"));
    assert_eq!(publisher.send(FetchBacklog).await?, (0, 1));
    assert!(
        timeout(Duration::from_millis(100), net_cmd_rx.recv())
            .await
            .is_err(),
        "a failed read waits in the queue during backoff"
    );
    Ok(())
}

#[actix::test]
async fn test_publishes_document_fails_with_exponential_backoff() -> Result<()> {
    let (_guard, bus, _net_cmd_tx, net_cmd_rx, net_evt_tx, _net_evt_rx, _history, errors, _) =
        setup_test()?;
    let mut commands = Commands::in_real_time(net_cmd_rx);
    let value = ArcBytes::from_bytes(b"I am a special document");
    let expires_at = Some(Utc::now() + chrono::Duration::days(1));
    let e3_id = E3id::new("1243", 1);

    // Send a request to publish
    bus.publish_without_context(PublishDocumentRequested {
        meta: DocumentMeta::new(e3_id, DocumentKind::TrBFV, vec![], expires_at),
        value: value.clone(),
    })?;

    for _ in 0..2 {
        // Expect retry
        let upload = commands.take(is_upload).await?;

        // Report failure
        net_evt_tx.send(NetEvent::DhtPutRecordError {
            correlation_id: correlation(&upload),
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
            "Operation failed after 2 attempts. Last error: DHT put record failed: PutRecordError(QuorumFailed { key: Key(b\"I got the secret\"), success: [], quorum: 1 })"
        );

    Ok(())
}
