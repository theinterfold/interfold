// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::time::Duration;

use super::*;
use crate::events::{GossipData, NetEvent};
use crate::ProtocolSigner;
use alloy::signers::local::PrivateKeySigner;
use e3_ciphernode_builder::EventSystem;
use e3_events::{
    Committee, E3id, EventConstructorWithTimestamp, EventContextAccessors, EventPublisher,
    EventSource, PlaintextAggregated, SyncEnded, Unsequenced,
};
use e3_utils::ArcBytes;
use libp2p::{gossipsub::MessageId, PeerId};
use std::collections::HashMap;
use tokio::{
    sync::broadcast,
    time::{sleep, timeout},
};

fn buffer_dependencies() -> (mpsc::Sender<NetCommand>, mpsc::Receiver<NetCommand>) {
    mpsc::channel(16)
}

#[actix::test]
async fn test_buffers_until_sync_ended() -> Result<()> {
    // Setup
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test");
    let (input_tx, input_rx) = broadcast::channel(16);
    let (net_commands, _net_command_rx) = buffer_dependencies();
    let (mut output_rx, handle) = NetEventBuffer::setup_with_limits(
        &bus,
        &input_rx,
        net_commands,
        NetworkAuthorizationState::default(),
        NetworkStatus::default(),
        DEFAULT_MAX_BUFFERED_NET_EVENTS,
        DEFAULT_MAX_BUFFERED_NET_BYTES,
    );

    // Send events while syncing - should be buffered
    let event1 = NetEvent::GossipData(GossipData::GossipBytes(vec![1, 2, 3]));
    let event2 = NetEvent::GossipData(GossipData::GossipBytes(vec![4, 5, 6]));
    input_tx.send(event1.clone()).unwrap();
    input_tx.send(event2.clone()).unwrap();

    // Give actor time to process
    sleep(Duration::from_millis(10)).await;

    // Verify no events forwarded yet (should timeout)
    assert!(
        timeout(Duration::from_millis(50), output_rx.recv())
            .await
            .is_err(),
        "Events should be buffered, not forwarded during sync"
    );

    // Send SyncEnded event
    bus.publish_without_context(SyncEnded::new()).unwrap();
    handle.wait_until_running().await?;

    // Now buffered events should be forwarded
    let received1 = output_rx.recv().await.unwrap();
    let received2 = output_rx.recv().await.unwrap();

    assert!(
        matches!(received1, NetEvent::GossipData(GossipData::GossipBytes(ref bytes)) if bytes == &vec![1, 2, 3])
    );
    assert!(
        matches!(received2, NetEvent::GossipData(GossipData::GossipBytes(ref bytes)) if bytes == &vec![4, 5, 6])
    );

    // Send new event after sync - should forward immediately
    let event3 = NetEvent::GossipData(GossipData::GossipBytes(vec![7, 8, 9]));
    input_tx.send(event3.clone()).unwrap();

    let received3 = tokio::time::timeout(tokio::time::Duration::from_millis(100), output_rx.recv())
        .await
        .expect("Event should be forwarded immediately after sync")
        .unwrap();

    assert!(
        matches!(received3, NetEvent::GossipData(GossipData::GossipBytes(ref bytes)) if bytes == &vec![7, 8, 9])
    );

    Ok(())
}

#[actix::test]
async fn startup_buffer_overflow_fails_readiness_without_dropping_oldest() -> Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-overflow");
    let (input_tx, input_rx) = broadcast::channel(16);
    let (net_commands, _net_command_rx) = buffer_dependencies();
    let (_output_rx, handle) = NetEventBuffer::setup_with_limits(
        &bus,
        &input_rx,
        net_commands,
        NetworkAuthorizationState::default(),
        NetworkStatus::default(),
        1,
        DEFAULT_MAX_BUFFERED_NET_BYTES,
    );

    input_tx.send(NetEvent::GossipData(GossipData::GossipBytes(vec![1])))?;
    input_tx.send(NetEvent::GossipData(GossipData::GossipBytes(vec![2])))?;

    let error = timeout(Duration::from_secs(1), handle.wait_until_running())
        .await
        .context("network buffer did not report overflow")?
        .expect_err("overflow must fail startup readiness")
        .to_string();
    assert!(error.contains("events=1/1"), "{error}");
    assert!(
        error.contains("startup will stop rather than drop"),
        "{error}"
    );
    Ok(())
}

#[actix::test]
async fn startup_buffer_enforces_estimated_payload_bytes() -> Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-byte-overflow");
    let (input_tx, input_rx) = broadcast::channel(16);
    let event = NetEvent::GossipData(GossipData::GossipBytes(vec![0; 32]));
    let estimated_bytes = event.buffered_size_bytes();
    let (net_commands, _net_command_rx) = buffer_dependencies();
    let (_output_rx, handle) = NetEventBuffer::setup_with_limits(
        &bus,
        &input_rx,
        net_commands,
        NetworkAuthorizationState::default(),
        NetworkStatus::default(),
        16,
        estimated_bytes - 1,
    );

    input_tx.send(event)?;

    let error = timeout(Duration::from_secs(1), handle.wait_until_running())
        .await
        .context("network buffer did not report byte overflow")?
        .expect_err("byte overflow must fail startup readiness")
        .to_string();
    assert!(
        error.contains(&format!("next_event_bytes={estimated_bytes}")),
        "{error}"
    );
    Ok(())
}

#[actix::test]
async fn unauthorized_gossip_is_rejected_before_startup_buffering() -> Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-auth-before-buffer");
    let (input_tx, input_rx) = broadcast::channel(16);
    let (net_commands, mut net_command_rx) = buffer_dependencies();

    let e3_id = E3id::new("7", 42);
    let member = PrivateKeySigner::random();
    let member_signer = ProtocolSigner::new(member.clone(), PeerId::random());
    let outsider_signer = ProtocolSigner::new(PrivateKeySigner::random(), PeerId::random());
    let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        PlaintextAggregated {
            e3_id: e3_id.clone(),
            decrypted_output: vec![ArcBytes::from_bytes(&[1, 2, 3])],
            decryption_aggregator_proofs: vec![],
        }
        .into(),
        None,
        42,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);
    let authorization = NetworkAuthorizationState::new(
        HashMap::from([(e3_id, Committee::new(vec![member.address().to_string()]))]),
        HashMap::new(),
    );
    let network_status = NetworkStatus::new(1);
    network_status.connected(
        member_signer.peer_id().to_string(),
        "/ip4/127.0.0.1",
        "inbound",
        1,
    );
    let (mut output_rx, handle) = NetEventBuffer::setup_with_limits(
        &bus,
        &input_rx,
        net_commands,
        authorization,
        network_status.clone(),
        1,
        DEFAULT_MAX_BUFFERED_NET_BYTES,
    );

    input_tx.send(NetEvent::AuthenticatedGossip {
        author: outsider_signer.peer_id(),
        propagation_source: outsider_signer.peer_id(),
        message_id: MessageId::new(b"outsider"),
        data: GossipData::ProtocolEvent(outsider_signer.sign_event(event.clone())?),
    })?;
    input_tx.send(NetEvent::AuthenticatedGossip {
        author: member_signer.peer_id(),
        propagation_source: member_signer.peer_id(),
        message_id: MessageId::new(b"member"),
        data: GossipData::ProtocolEvent(member_signer.sign_event(event.clone())?),
    })?;

    assert!(matches!(
        timeout(Duration::from_secs(1), net_command_rx.recv()).await?,
        Some(NetCommand::GossipValidation {
            acceptance: GossipAcceptance::Reject,
            ..
        })
    ));
    assert!(matches!(
        timeout(Duration::from_secs(1), net_command_rx.recv()).await?,
        Some(NetCommand::GossipValidation {
            acceptance: GossipAcceptance::Accept,
            ..
        })
    ));
    let authenticated = network_status.snapshot().authenticated_peers;
    assert_eq!(authenticated.len(), 1);
    assert_eq!(
        authenticated[0].peer_id,
        member_signer.peer_id().to_string()
    );
    assert!(timeout(Duration::from_millis(20), output_rx.recv())
        .await
        .is_err());

    bus.publish_without_context(SyncEnded::new())?;
    handle.wait_until_running().await?;
    assert!(matches!(
        timeout(Duration::from_secs(1), output_rx.recv()).await??,
        NetEvent::AuthorizedGossip(received) if received.id() == event.id()
    ));
    Ok(())
}
