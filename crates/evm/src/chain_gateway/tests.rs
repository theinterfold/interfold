// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{EvmEvent, EvmLogRejected};

use super::*;
use e3_ciphernode_builder::EventSystem;

use e3_events::{CorrelationId, EvmEventConfig, EvmEventConfigChain, TakeEvents, TestEvent};
use tokio::sync::mpsc;
use tracing_subscriber::{fmt, EnvFilter};

struct SyncEventCollector {
    tx: mpsc::UnboundedSender<HistoricalEvmEventsReceived>,
}

#[actix::test]
async fn owner_checkpoint_keeps_chain_time_when_the_event_clock_advances() -> Result<()> {
    use e3_events::{hlc::HlcTimestamp, BondOwnerSet, Event, EventContextAccessors};

    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("historical-owner-time");
    let owner = BondOwnerSet {
        operator: alloy::primitives::Address::from([1; 20]).to_string(),
        bond_owner: alloy::primitives::Address::from([2; 20]).to_string(),
        chain_id: 1,
    };
    for seconds in [10, 1_700_000_000] {
        let raw = EvmEvent::new(
            CorrelationId::new(),
            owner.clone().into(),
            42,
            crate::domain::log_timestamp::from_log_chain_id_to_ts(seconds, 3, 1),
            1,
        );
        let event = raw.into_interfold_event(&bus)?;
        assert!(HlcTimestamp::wall_time(event.ts()) / 1_000_000 > seconds);
        let InterfoldEventData::BondOwnerSetAt(checkpoint) = event.get_data() else {
            panic!("owner events must retain the source block timestamp");
        };
        assert_eq!(checkpoint.timepoint, seconds);
        assert_eq!(checkpoint.owner, owner);
        let restored: InterfoldEvent<Unsequenced> =
            bincode::deserialize(&bincode::serialize(&event)?)?;
        assert_eq!(restored, event);
    }
    Ok(())
}

#[actix::test]
async fn eligibility_source_time_survives_delayed_ingestion_and_snapshot_replay() -> Result<()> {
    use alloy::primitives::{Address, FixedBytes, I256, U256};
    use e3_data::{AutoPersist, DataStore, InMemStore, Persistable, Repository};
    use e3_events::{
        hlc::HlcTimestamp, ConfigurationUpdated, Event, EventContextAccessors,
        OperatorActivationChanged, TicketBalanceUpdated,
    };
    use e3_sortition::{CiphernodeSelector, NodeStateStore, Sortition, SortitionParams};
    use std::collections::HashMap;

    fn memory<T>(value: T) -> (Persistable<T>, Repository<T>)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + Sync + 'static,
    {
        let store = InMemStore::new(false).start();
        let repository = Repository::new(DataStore::from_in_mem(&store));
        (repository.send(Some(value)), repository)
    }
    fn sortition(
        bus: &BusHandle,
        state: HashMap<u64, NodeStateStore>,
    ) -> (Addr<Sortition>, Repository<HashMap<u64, NodeStateStore>>) {
        let selector = CiphernodeSelector::new(
            bus,
            memory(Default::default()).0,
            memory(Default::default()).0,
            "0x1",
        )
        .start();
        let (node_state, repository) = memory(state);
        (
            Sortition::new(SortitionParams {
                bus: bus.clone(),
                node_state,
                backends: memory(Default::default()).0,
                bond_owners: memory(Default::default()).0,
                admission: memory(Default::default()).0,
                finalized_committees: memory(Default::default()).0,
                recovery: memory(Default::default()).0,
                ciphernode_selector: selector,
                address: "0x1".into(),
                submitted_e3s: Default::default(),
            })
            .start(),
            repository,
        )
    }

    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("eligibility-source-time");
    let address = Address::repeat_byte(1).to_string();
    let price = |value| ConfigurationUpdated {
        parameter: "ticketPrice".into(),
        old_value: U256::ZERO,
        new_value: U256::from(value),
        chain_id: 1,
    };
    let balance = |value| TicketBalanceUpdated {
        operator: address.clone(),
        delta: I256::ZERO,
        new_balance: U256::from(value),
        reason: FixedBytes::ZERO,
        chain_id: 1,
    };
    let active = || OperatorActivationChanged {
        operator: address.clone(),
        active: true,
        chain_id: 1,
    };
    let request_time = 1_700_000_010;
    let facts: Vec<(u64, InterfoldEventData)> = vec![
        (request_time - 2, price(10u64).into()),
        (request_time - 2, balance(20u64).into()),
        (request_time - 2, active().into()),
        (request_time, balance(1_000u64).into()),
        (request_time, balance(1_500u64).into()),
        (request_time, price(25u64).into()),
        (request_time, active().into()),
        (request_time, price(30u64).into()),
        (request_time, active().into()),
    ];
    let mut events = Vec::new();
    for (index, (seconds, data)) in facts.iter().cloned().enumerate() {
        let event = EvmEvent::new(
            CorrelationId::new(),
            data,
            42 + u64::from(seconds >= request_time),
            crate::domain::log_timestamp::from_log_chain_id_to_ts(seconds, index as u64, 1),
            1,
        )
        .into_interfold_event(&bus)?
        .into_sequenced(index as u64 + 1);
        assert!(HlcTimestamp::wall_time(event.ts()) / 1_000_000 > seconds);
        let checkpoint_time = match event.get_data() {
            InterfoldEventData::TicketBalanceUpdatedAt(data) => data.position.timepoint,
            InterfoldEventData::OperatorActivationChangedAt(data) => data.position.timepoint,
            InterfoldEventData::ConfigurationUpdatedAt(data) => data.position.timepoint,
            _ => panic!("eligibility events must retain source block time"),
        };
        assert_eq!(checkpoint_time, seconds);
        let restored: InterfoldEvent = bincode::deserialize(&bincode::serialize(&event)?)?;
        assert_eq!(restored, event);
        events.push(restored);
    }

    let (live, live_repository) = sortition(&bus, Default::default());
    for event in &events {
        live.send(event.clone()).await?;
    }
    let expected = live_repository.read().await?.unwrap();
    let node = &expected[&1].nodes[&address];
    assert_eq!(node.ticket_balance_at(request_time - 1), U256::from(20));
    assert!(node.active_at(request_time - 1));
    assert_eq!(node.ticket_balance_at(request_time), U256::from(1_500));
    assert!(node.active_at(request_time));
    assert_eq!(expected[&1].ticket_price, U256::from(30));
    assert_eq!(node.active_history.len(), 2); // Invalidation and refresh share a block.
    assert_eq!(node.active_history[1].timepoint, request_time);

    for split in 0..=events.len() {
        let (before, repository) = sortition(&bus, Default::default());
        for event in &events[..split] {
            before.send(event.clone()).await?;
        }
        let checkpoint = bincode::serialize(&repository.read().await?.unwrap())?;
        let (after, repository) = sortition(&bus, bincode::deserialize(&checkpoint)?);
        for event in &events[split..] {
            after.send(event.clone()).await?;
        }
        assert_eq!(
            bincode::serialize(&repository.read().await?.unwrap())?,
            bincode::serialize(&expected)?
        );
    }

    // Restart backfill overlaps the restored snapshot and the replayed EventStore suffix.
    let (recovered, repository) = sortition(&bus, expected.clone());
    for (index, (seconds, data)) in facts.into_iter().enumerate() {
        let duplicate = EvmEvent::new(
            CorrelationId::new(),
            data,
            42 + u64::from(seconds >= request_time),
            crate::domain::log_timestamp::from_log_chain_id_to_ts(seconds, index as u64, 1),
            1,
        )
        .into_interfold_event(&bus)?
        .into_sequenced((events.len() + index + 1) as u64);
        assert_ne!(duplicate.ts(), events[index].ts());
        recovered.send(duplicate).await?;
        assert_eq!(
            bincode::serialize(&repository.read().await?.unwrap())?,
            bincode::serialize(&expected)?
        );
    }

    for (index, data) in [
        price(40u64).into(),
        balance(2_000u64).into(),
        active().into(),
    ]
    .into_iter()
    .enumerate()
    {
        let next = EvmEvent::new(
            CorrelationId::new(),
            data,
            44,
            crate::domain::log_timestamp::from_log_chain_id_to_ts(
                request_time + 1,
                index as u64,
                1,
            ),
            1,
        )
        .into_interfold_event(&bus)?
        .into_sequenced((2 * events.len() + index + 1) as u64);
        recovered.send(next).await?;
    }
    let advanced = repository.read().await?.unwrap();
    assert_eq!(
        advanced[&1].nodes[&address].ticket_balance,
        U256::from(2_000)
    );
    assert!(advanced[&1].nodes[&address].active);
    assert_eq!(advanced[&1].ticket_price, U256::from(40));
    Ok(())
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

#[actix::test]
async fn post_startup_failure_is_reported() -> Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-post-startup-failure");
    let gateway = EvmChainGateway::setup_with_readiness(&bus);
    let mut failure = gateway.failure_receiver();
    let addr = gateway.addr();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let collector = SyncEventCollector { tx }.start();
    let mut evm_config = EvmEventConfig::new();
    evm_config.insert(1, EvmEventConfigChain::new(0));
    bus.publish_without_context(HistoricalEvmSyncStart::new(collector, evm_config))?;
    addr.send(InterfoldEvmEvent::HistoricalSyncComplete(
        HistoricalSyncComplete::new(1, None),
    ))
    .await?;
    rx.recv()
        .await
        .expect("the gateway must forward its historical batch");
    bus.publish_without_context(SyncEnded::new())?;
    gateway.wait_until_live().await?;

    assert!(failure.borrow().is_none());
    addr.send(InterfoldEvmEvent::Rejected(EvmLogRejected::new(
        CorrelationId::new(),
        1,
        "backend connection task has stopped",
    )))
    .await?;

    let reason = failure
        .wait_for(|reason| reason.is_some())
        .await
        .expect("the gateway must report its failure before it stops")
        .clone()
        .unwrap();
    assert!(reason.contains("EVM chain gateway failed closed"));
    assert!(reason.contains("backend connection task has stopped"));
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
