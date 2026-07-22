// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{EvmEvent, EvmLogRejected};

use super::*;
use e3_ciphernode_builder::EventSystem;

use e3_events::{
    CorrelationId, EventPublisher, EvmEventConfig, EvmEventConfigChain, TakeEvents, TestEvent,
};
use tokio::sync::mpsc;
use tracing_subscriber::{fmt, EnvFilter};

struct SyncEventCollector {
    tx: mpsc::UnboundedSender<HistoricalEvmEventsReceived>,
}

#[actix::test]
async fn rejected_log_fails_gateway_readiness() -> Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-rejected-log");
    let gateway = EvmChainGateway::setup_with_readiness(&bus);

    gateway
        .addr()
        .send(InterfoldEvmEvent::Rejected(EvmLogRejected::new(
            CorrelationId::new(),
            1,
            "malformed historical log",
        )))
        .await?;

    let error = gateway.wait_until_live().await.unwrap_err();
    assert!(error.to_string().contains("malformed historical log"));
    Ok(())
}

impl Actor for SyncEventCollector {
    type Context = actix::Context<Self>;
}

impl Handler<HistoricalEvmEventsReceived> for SyncEventCollector {
    type Result = ();
    fn handle(&mut self, msg: HistoricalEvmEventsReceived, _: &mut Self::Context) {
        let _ = self.tx.send(msg);
    }
}

#[actix::test]
async fn test_evm_chain_gateway() -> Result<()> {
    let _foo = tracing::subscriber::set_default(
        fmt()
            .with_env_filter(EnvFilter::new("info"))
            .with_test_writer()
            .finish(),
    );

    let system = EventSystem::new().with_fresh_bus();
    let bus: BusHandle = system.handle()?.enable("test");

    let history_collector = bus.history();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let collector = SyncEventCollector { tx }.start();

    let gateway = EvmChainGateway::setup_with_readiness(&bus);
    let addr = gateway.addr();

    let chain_id = 1u64;

    // HistoricalEvmSyncStart: Init -> ForwardToSyncActor
    let mut evm_config = EvmEventConfig::new();
    evm_config.insert(chain_id, EvmEventConfigChain::new(0));
    bus.publish_without_context(HistoricalEvmSyncStart::new(collector.clone(), evm_config))
        .unwrap();

    // Send EVM event while forwarding - should reach collector
    let evm_event = EvmEvent::new(
        CorrelationId::new(),
        TestEvent::new("Before Complete", 1).into(),
        100,
        12345,
        chain_id,
    );

    // This will actually arrive earlier than HistoricalEvmSyncStart but aught to be buffered
    addr.send(InterfoldEvmEvent::Event(evm_event)).await?;

    // HistoricalSyncComplete: ForwardToSyncActor -> BufferUntilLive
    addr.send(InterfoldEvmEvent::HistoricalSyncComplete(
        HistoricalSyncComplete::new(chain_id, None),
    ))
    .await?;

    // Normal Synchronizer will take this and wait for other events before flushing events to
    // the bus here we simulate it
    let received = rx.recv().await.unwrap();
    for event in received.events {
        bus.naked_dispatch(event);
    }

    // Send EVM event while buffering - should be buffered (not received)
    let buffered_event = EvmEvent::new(
        CorrelationId::new(),
        TestEvent::new("Before SyncEnded", 2).into(),
        101,
        12346,
        chain_id,
    );
    addr.send(InterfoldEvmEvent::Event(buffered_event)).await?;

    // The Synchronizer will publish the SyncEnded event when it has all the information it needs
    // and has published everything to the bus
    bus.publish_without_context(SyncEnded::new())?;
    gateway.wait_until_live().await?;

    let after_event = EvmEvent::new(
        CorrelationId::new(),
        TestEvent::new("After SyncEnded", 2).into(),
        101,
        12346,
        chain_id,
    );

    addr.send(InterfoldEvmEvent::Event(after_event)).await?;

    let full = history_collector.send(TakeEvents::new(5)).await?;

    let test_events: Vec<String> = full
        .events
        .iter()
        .filter_map(|e| {
            if let InterfoldEventData::TestEvent(TestEvent { msg, .. }) = e.get_data() {
                Some(msg.to_string())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        test_events,
        vec!["Before Complete", "Before SyncEnded", "After SyncEnded"]
    );

    let event_types: Vec<String> = full.events.iter().map(|e| e.event_type()).collect();

    assert_eq!(
        event_types,
        vec![
            "HistoricalEvmSyncStart",
            "TestEvent",
            "SyncEnded",
            "TestEvent",
            "TestEvent"
        ]
    );
    Ok(())
}

#[actix::test]
async fn overflow_emits_actionable_error_stops_and_fails_readiness() -> Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus: BusHandle = system.handle()?.enable("test-overflow");
    let errors = bus.errors();
    let gateway = EvmChainGateway::setup_with_readiness_and_limit(&bus, 1);
    let addr = gateway.addr();

    for entropy in [1, 2] {
        let event = EvmEvent::new(
            CorrelationId::new(),
            TestEvent::new("overflow", entropy).into(),
            100,
            u128::from(entropy),
            1,
        );
        addr.send(InterfoldEvmEvent::Event(event)).await?;
    }

    let startup_error = gateway
        .wait_until_live()
        .await
        .expect_err("overflow must fail gateway readiness")
        .to_string();
    assert!(startup_error.contains("Init buffer reached its limit of 1 events"));
    assert!(startup_error.contains("will not process further chain events"));
    assert!(startup_error.contains("restart the node to replay chain history"));

    let received = errors.send(TakeEvents::new(1)).await?;
    assert!(!received.timed_out, "overflow error should be observable");
    let InterfoldEventData::InterfoldError(error) = received.events[0].get_data() else {
        panic!("expected an InterfoldError event");
    };
    assert!(error
        .message
        .contains("Init buffer reached its limit of 1 events"));
    assert!(error.message.contains("snapshot/deploy block"));

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while addr.connected() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("overflowed gateway did not stop")?;
    assert!(!addr.connected(), "overflowed gateway must stop");
    Ok(())
}
