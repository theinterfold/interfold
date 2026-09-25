// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::net_interface_handle::NetEventSubscriber;
use std::{sync::Arc, time::Duration};

use super::*;
use crate::{
    direct_responder::{ChannelType, DirectResponder},
    events::{
        GossipData, IncomingRequest, NetEvent, OutgoingRequestFailed, OutgoingRequestSucceeded,
        PeerRejectionKind, ProtocolResponse,
    },
    net_interface::EVENT_CHANNEL_SIZE,
    NetEventSender,
};
use e3_ciphernode_builder::EventSystem;
use e3_events::{CorrelationId, EventPublisher, SyncEnded};
use libp2p::{
    gossipsub::TopicHash,
    swarm::{ConnectionId, DialError},
    PeerId,
};
use tokio::{
    sync::{broadcast, mpsc},
    time::timeout,
};

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Message)]
#[rtype(result = "usize")]
struct BufferedEventCount;

impl Handler<BufferedEventCount> for NetEventBuffer {
    type Result = usize;

    fn handle(&mut self, _: BufferedEventCount, _: &mut actix::Context<Self>) -> usize {
        match &self.state {
            NetEventBufferState::Syncing { events, .. } => events.len(),
            state => panic!("expected startup buffering, got {state:?}"),
        }
    }
}

fn sync_and_connection_control_events() -> Vec<NetEvent> {
    let (command_tx, _command_rx) = mpsc::channel(1);
    vec![
        NetEvent::DialError {
            error: Arc::new(DialError::NoAddresses),
        },
        NetEvent::ConnectionEstablished {
            connection_id: ConnectionId::new_unchecked(1),
        },
        NetEvent::PeerRejected {
            connection_id: ConnectionId::new_unchecked(2),
            kind: PeerRejectionKind::Transient,
            reason: "test rejection".to_owned(),
        },
        NetEvent::OutgoingConnectionError {
            connection_id: ConnectionId::new_unchecked(3),
            error: Arc::new(DialError::NoAddresses),
        },
        NetEvent::GossipSubscribed {
            count: 1,
            topic: TopicHash::from_raw("test-topic"),
        },
        NetEvent::IncomingRequest(IncomingRequest {
            peer: PeerId::random(),
            responder: DirectResponder::new(
                1_u64,
                ChannelType::Test("test-request".to_owned()),
                &command_tx,
            )
            .with_request(vec![1, 2, 3]),
        }),
        NetEvent::OutgoingRequestSucceeded(OutgoingRequestSucceeded {
            payload: ProtocolResponse::Ok(Vec::new()),
            correlation_id: CorrelationId::new(),
        }),
        NetEvent::OutgoingRequestFailed(OutgoingRequestFailed {
            correlation_id: CorrelationId::new(),
            error: "test request failure".to_owned(),
        }),
        NetEvent::AllPeersDialed {
            connected: 1,
            total: 1,
        },
    ]
}

#[actix::test]
async fn test_buffers_until_sync_ended() -> Result<()> {
    // Setup
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test");
    let (input_tx, _input_rx) = broadcast::channel(16);
    let input = NetEventSubscriber::from(&input_tx);
    let (output, handle) = NetEventBuffer::setup_with_limits(
        &bus,
        &input,
        DEFAULT_MAX_BUFFERED_NET_EVENTS,
        DEFAULT_MAX_BUFFERED_NET_BYTES,
    );
    let mut output_rx = output.subscribe();

    // Send events while syncing - should be buffered
    let event1 = NetEvent::GossipData(GossipData::GossipBytes(vec![1, 2, 3]));
    let event2 = NetEvent::GossipData(GossipData::GossipBytes(vec![4, 5, 6]));
    input_tx.send(event1.clone()).unwrap();
    input_tx.send(event2.clone()).unwrap();

    // Wait for observable actor progress, then check that no event was forwarded.
    timeout(DELIVERY_TIMEOUT, async {
        while handle.actor.send(BufferedEventCount).await? != 2 {
            tokio::task::yield_now().await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("network events did not reach the startup buffer")??;
    assert!(
        matches!(
            output_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ),
        "Events should be buffered, not forwarded during sync"
    );

    // Send SyncEnded event
    bus.publish_without_context(SyncEnded::new()).unwrap();
    timeout(DELIVERY_TIMEOUT, handle.wait_until_running()).await??;

    // Now buffered events should be forwarded
    let received1 = timeout(DELIVERY_TIMEOUT, output_rx.recv()).await??;
    let received2 = timeout(DELIVERY_TIMEOUT, output_rx.recv()).await??;

    assert!(
        matches!(received1, NetEvent::GossipData(GossipData::GossipBytes(ref bytes)) if bytes == &vec![1, 2, 3])
    );
    assert!(
        matches!(received2, NetEvent::GossipData(GossipData::GossipBytes(ref bytes)) if bytes == &vec![4, 5, 6])
    );

    // Send new event after sync - should forward immediately
    let event3 = NetEvent::GossipData(GossipData::GossipBytes(vec![7, 8, 9]));
    input_tx.send(event3.clone()).unwrap();

    let received3 = timeout(DELIVERY_TIMEOUT, output_rx.recv())
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
    let (input_tx, _input_rx) = broadcast::channel(16);
    let input = NetEventSubscriber::from(&input_tx);
    let (_output_rx, handle) =
        NetEventBuffer::setup_with_limits(&bus, &input, 1, DEFAULT_MAX_BUFFERED_NET_BYTES);

    input_tx.send(NetEvent::GossipData(GossipData::GossipBytes(vec![1])))?;
    input_tx.send(NetEvent::GossipData(GossipData::GossipBytes(vec![2])))?;

    let error = timeout(DELIVERY_TIMEOUT, handle.wait_until_running())
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
    let (input_tx, _input_rx) = broadcast::channel(16);
    let input = NetEventSubscriber::from(&input_tx);
    let event = NetEvent::GossipData(GossipData::GossipBytes(vec![0; 32]));
    let estimated_bytes = event.buffered_size_bytes();
    let (_output_rx, handle) =
        NetEventBuffer::setup_with_limits(&bus, &input, 16, estimated_bytes - 1);

    input_tx.send(event)?;

    let error = timeout(DELIVERY_TIMEOUT, handle.wait_until_running())
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
async fn sync_control_burst_does_not_lag_or_consume_the_application_buffer() -> Result<()> {
    const CONTROL_EVENTS: usize = 100_000;

    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("net-control-flood");
    let event_tx = NetEventSender::new(EVENT_CHANNEL_SIZE, 1);
    let _raw_rx = event_tx.subscribe();
    let input = event_tx.application_subscriber();
    let (output, handle) =
        NetEventBuffer::setup_with_limits(&bus, &input, 1, DEFAULT_MAX_BUFFERED_NET_BYTES);
    let mut output_rx = output.subscribe();

    let control_events = sync_and_connection_control_events();
    assert!(control_events
        .iter()
        .all(|event| !event.requires_application_delivery()));

    for index in 0..CONTROL_EVENTS {
        event_tx.send(control_events[index % control_events.len()].clone())?;
    }
    event_tx.send(NetEvent::GossipData(GossipData::GossipBytes(vec![7])))?;
    bus.publish_without_context(SyncEnded::new())?;

    timeout(DELIVERY_TIMEOUT, handle.wait_until_running()).await??;
    let forwarded = timeout(DELIVERY_TIMEOUT, output_rx.recv()).await??;
    assert!(matches!(
        forwarded,
        NetEvent::GossipData(GossipData::GossipBytes(bytes)) if bytes == vec![7]
    ));
    assert!(matches!(
        output_rx.try_recv(),
        Err(broadcast::error::TryRecvError::Empty)
    ));
    Ok(())
}
