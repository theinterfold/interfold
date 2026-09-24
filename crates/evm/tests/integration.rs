// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, Addr, Handler};
use alloy::{
    node_bindings::Anvil,
    primitives::{FixedBytes, LogData},
    providers::{ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent,
};
use anyhow::Result;
use e3_ciphernode_builder::{EventSystem, EvmSystemChainBuilder};
use e3_events::{
    prelude::*, trap, BusHandle, EType, EvmEventConfig, EvmEventConfigChain, GetEvents,
    HistoricalEvmEventsReceived, HistoricalEvmSyncStart, InterfoldEvent, InterfoldEventData,
    SyncEnded, TestEvent,
};
use e3_evm::{helpers::EthProvider, EvmEventProcessor, EvmParser};
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;

sol!(
    #[sol(rpc)]
    EmitLogs,
    "tests/fixtures/emit_logs.json"
);

fn test_event_extractor(
    data: &LogData,
    topics: &[FixedBytes<32>],
    _chain_id: u64,
) -> Option<InterfoldEventData> {
    match topics.first() {
        Some(&EmitLogs::ValueChanged::SIGNATURE_HASH) => {
            let Ok(event) = EmitLogs::ValueChanged::decode_log_data(data) else {
                return None;
            };
            Some(
                TestEvent::new(
                    &event.value,
                    event.count.try_into().unwrap(), // This prevents de-duplication in tests
                )
                .into(),
            )
        }
        _ => None,
    }
}

struct TestEventParser;

#[actix::test]
async fn historical_owner_logs_restore_the_shortlist_after_resync() -> Result<()> {
    use alloy::{primitives::Address, providers::Provider};
    use e3_events::{E3id, Seed};
    use e3_evm::BondingRegistrySolReader;
    use e3_sortition::{BondOwnerState, RegisteredNode, ScoreSortition, Ticket};
    use std::collections::{HashMap, HashSet};

    let anvil = Anvil::new().try_spawn()?;
    let provider = Arc::new(
        EthProvider::new(
            ProviderBuilder::new()
                .wallet(PrivateKeySigner::from_slice(&anvil.keys()[0].to_bytes())?)
                .connect_ws(WsConnect::new(anvil.ws_endpoint()))
                .await?,
        )
        .await?,
    );
    let contract = EmitLogs::deploy(provider.provider()).await?;
    let operators = (1..=68).map(Address::repeat_byte).collect::<Vec<_>>();
    let owners = operators
        .iter()
        .enumerate()
        .map(|(index, operator)| {
            if index < 28 {
                Address::repeat_byte(200)
            } else {
                *operator
            }
        })
        .collect::<Vec<_>>();
    let receipt = contract
        .emitBondOwners(operators.clone(), owners.clone())
        .send()
        .await?
        .get_receipt()
        .await?;
    let block = provider
        .provider()
        .get_block_by_number(receipt.block_number.expect("mined receipt").into())
        .await?
        .expect("mined block");
    let timestamp = block.header.timestamp;

    // Start ingestion after the logs exist. A fresh store must scan from the deploy range.
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("owner-resync-integration");
    let history = bus.history();
    let sync = FakeSyncActor::setup(&bus);
    EvmSystemChainBuilder::new(&bus, &provider)
        .with_contract(*contract.address(), |upstream| {
            BondingRegistrySolReader::setup(&upstream).recipient()
        })
        .build();
    let mut config = EvmEventConfig::new();
    config.insert(provider.chain_id(), EvmEventConfigChain::new(0));
    bus.publish_without_context(HistoricalEvmSyncStart::new(sync, config))?;
    let checkpoints = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let checkpoints = history
                .send(GetEvents::<InterfoldEvent>::new())
                .await?
                .into_iter()
                .filter_map(|event| match event.into_data() {
                    InterfoldEventData::BondOwnerSetAt(checkpoint) => Some(checkpoint),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if checkpoints.len() == operators.len() {
                break Ok::<_, anyhow::Error>(checkpoints);
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let mut state = BondOwnerState::default();
    for checkpoint in checkpoints {
        assert_eq!(checkpoint.timepoint, timestamp);
        state.record(&checkpoint.owner, checkpoint.timepoint)?;
    }
    let restored: BondOwnerState = bincode::deserialize(&bincode::serialize(&state)?)?;
    restored.validate()?;
    let request_owners = operators
        .iter()
        .map(|operator| {
            (
                *operator,
                restored
                    .owner_at(provider.chain_id(), *operator, timestamp)
                    .unwrap(),
            )
        })
        .collect::<HashMap<_, _>>();
    assert_eq!(
        request_owners,
        operators.iter().copied().zip(owners).collect()
    );
    assert!(operators.iter().all(|operator| restored
        .owner_at(provider.chain_id(), *operator, timestamp - 1)
        .is_none()));
    let nodes = operators
        .iter()
        .map(|operator| RegisteredNode {
            address: *operator,
            tickets: vec![Ticket { ticket_id: 1 }],
        })
        .collect::<Vec<_>>();
    let candidates = ScoreSortition::new(30).get_owner_candidates(
        E3id::new("1", provider.chain_id()),
        Seed([42; 32]),
        &nodes,
        &request_owners,
    )?;
    assert!(
        candidates.len() < nodes.len(),
        "complete history must restore the shortlist"
    );
    assert_eq!(
        candidates[..30]
            .iter()
            .map(|candidate| request_owners[&candidate.address])
            .collect::<HashSet<_>>()
            .len(),
        30
    );
    Ok(())
}

#[actix::test]
async fn admission_chain_logs_filter_sortition_after_restart() -> Result<()> {
    use alloy::primitives::Address;
    use e3_evm::BondingRegistrySolReader;
    use e3_sortition::{AdmissionState, NodeState, NodeStateStore};
    use std::collections::HashMap;

    let anvil = Anvil::new().block_time(1).try_spawn()?;
    let provider = Arc::new(
        EthProvider::new(
            ProviderBuilder::new()
                .wallet(PrivateKeySigner::from_slice(&anvil.keys()[0].to_bytes())?)
                .connect_ws(WsConnect::new(anvil.ws_endpoint()))
                .await?,
        )
        .await?,
    );
    let contract = EmitLogs::deploy(provider.provider()).await?;
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("admission-integration");
    let history = bus.history();
    let sync = FakeSyncActor::setup(&bus);
    EvmSystemChainBuilder::new(&bus, &provider)
        .with_contract(*contract.address(), move |upstream| {
            BondingRegistrySolReader::setup(&upstream).recipient()
        })
        .build();
    let mut config = EvmEventConfig::new();
    config.insert(provider.chain_id(), EvmEventConfigChain::new(0));
    bus.publish_without_context(HistoricalEvmSyncStart::new(sync, config))?;
    let operator = Address::repeat_byte(7);
    let enabled = EmitLogs::AdmissionPolicy {
        cooldownEnabled: true,
        cooldownDuration: 100.try_into()?,
        admissionsPaused: false,
        pauseTimepoint: 0.try_into()?,
        pauseCooldownEnabled: false,
        pauseCooldownDuration: 0.try_into()?,
    };
    let disabled = EmitLogs::AdmissionPolicy {
        cooldownEnabled: false,
        ..enabled.clone()
    };
    contract
        .emitAdmissionPolicies(operator, vec![enabled.clone(), disabled, enabled])
        .send()
        .await?
        .watch()
        .await?;
    let updates = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let updates = history
                .send(GetEvents::<InterfoldEvent>::new())
                .await?
                .into_iter()
                .filter_map(|e| match e.into_data() {
                    InterfoldEventData::AdmissionUpdated(update) => Some(update),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if updates.len() == 4 {
                break Ok::<_, anyhow::Error>(updates);
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    let timepoint = updates[0].timepoint;
    let mut state = AdmissionState::default();
    for update in updates {
        state.record(&update)?;
    }
    let state: AdmissionState = bincode::deserialize(&bincode::serialize(&state)?)?;
    state.validate()?;
    let nodes = NodeStateStore {
        nodes: HashMap::from([(operator.to_string(), NodeState::default())]),
        ..Default::default()
    };
    assert_eq!(
        state
            .filter(provider.chain_id(), timepoint + 99, &nodes)
            .nodes
            .len(),
        0
    );
    assert_eq!(
        state
            .filter(provider.chain_id(), timepoint + 100, &nodes)
            .nodes
            .len(),
        1
    );
    Ok(())
}

impl TestEventParser {
    pub fn setup(next: &EvmEventProcessor) -> Addr<EvmParser> {
        EvmParser::new(next, test_event_extractor).start()
    }
}

struct FakeSyncActor {
    bus: BusHandle,
}

impl Actor for FakeSyncActor {
    type Context = actix::Context<Self>;
}

impl FakeSyncActor {
    pub fn setup(bus: &BusHandle) -> Addr<Self> {
        Self { bus: bus.clone() }.start()
    }
}

impl Handler<HistoricalEvmEventsReceived> for FakeSyncActor {
    type Result = ();
    fn handle(
        &mut self,
        mut msg: HistoricalEvmEventsReceived,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sync, &self.bus.clone(), || {
            for evt in msg.events.drain(..) {
                self.bus.naked_dispatch(evt);
            }
            self.bus.publish_without_context(SyncEnded::new())?;
            Ok(())
        })
    }
}

#[actix::test]
async fn evm_reader() -> Result<()> {
    let _guard = e3_test_helpers::with_tracing("info");

    // Create a WS provider
    // NOTE: Anvil must be available on $PATH
    let anvil = Anvil::new().block_time(1).try_spawn()?;
    let rpc_url = anvil.ws_endpoint(); // Get RPC URL
    let provider = Arc::new(
        EthProvider::new(
            ProviderBuilder::new()
                .wallet(PrivateKeySigner::from_slice(&anvil.keys()[0].to_bytes())?)
                .connect_ws(WsConnect::new(rpc_url.clone())) // Use RPC URL
                .await?,
        )
        .await?,
    );
    let contract = EmitLogs::deploy(provider.provider()).await?;
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test");
    let history_collector = bus.history();

    let chain_id = provider.chain_id();
    let contract_address = *contract.address();
    let sync = FakeSyncActor::setup(&bus);
    EvmSystemChainBuilder::new(&bus, &provider)
        .with_contract(contract_address, move |upstream| {
            TestEventParser::setup(&upstream).recipient()
        })
        .build();

    // HistoricalEvmSyncStart holds initialization information such as start block and earliest event
    // This should trigger all chains to start to sync
    let mut evm_info = EvmEventConfig::new();
    evm_info.insert(chain_id, EvmEventConfigChain::new(0));
    bus.publish_without_context(HistoricalEvmSyncStart::new(sync, evm_info))?;

    sleep(Duration::from_secs(1)).await;
    contract
        .setValue("hello".to_string())
        .send()
        .await?
        .watch()
        .await?;

    contract
        .setValue("world!".to_string())
        .send()
        .await?
        .watch()
        .await?;

    sleep(Duration::from_secs(1)).await;

    let history = history_collector
        .send(GetEvents::<InterfoldEvent>::new())
        .await?;

    let msgs: Vec<_> = history
        .into_iter()
        .filter_map(|evt| match evt.into_data() {
            InterfoldEventData::TestEvent(data) => Some(data.msg),
            _ => None,
        })
        .collect();

    assert_eq!(msgs, vec!["hello", "world!"]);

    Ok(())
}
#[actix::test]
async fn ensure_historical_events() -> Result<()> {
    let _guard = e3_test_helpers::with_tracing("info");

    // Create a WS provider
    // NOTE: Anvil must be available on $PATH
    let anvil = Anvil::new().block_time(1).try_spawn()?;
    let rpc_url = anvil.ws_endpoint(); // Get RPC URL
    let provider = EthProvider::new(
        ProviderBuilder::new()
            .wallet(PrivateKeySigner::from_slice(&anvil.keys()[0].to_bytes())?)
            .connect_ws(WsConnect::new(rpc_url.clone())) // Use RPC URL
            .await?,
    )
    .await?;
    let contract = EmitLogs::deploy(provider.provider()).await?;
    let contract_address = *contract.address();
    let chain_id = provider.chain_id();
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test");
    let history_collector = bus.history();
    let historical_msgs = vec!["these", "are", "historical", "events"];
    let live_events = vec!["these", "events", "are", "live"];

    for msg in historical_msgs.clone() {
        contract
            .setValue(msg.to_string())
            .send()
            .await?
            .watch()
            .await?;
    }

    sleep(Duration::from_millis(1)).await;

    let sync = FakeSyncActor::setup(&bus);
    EvmSystemChainBuilder::new(&bus, &provider)
        .with_contract(contract_address, move |upstream| {
            TestEventParser::setup(&upstream).recipient()
        })
        .build();
    let mut evm_info = EvmEventConfig::new();
    evm_info.insert(chain_id, EvmEventConfigChain::new(0));
    bus.publish_without_context(HistoricalEvmSyncStart::new(sync, evm_info))?;

    for msg in live_events.clone() {
        contract
            .setValue(msg.to_string())
            .send()
            .await?
            .watch()
            .await?;
    }

    sleep(Duration::from_millis(1)).await;

    let expected: Vec<_> = historical_msgs.into_iter().chain(live_events).collect();

    let history = history_collector
        .send(GetEvents::<InterfoldEvent>::new())
        .await?;

    let msgs: Vec<_> = history
        .into_iter()
        .filter_map(|evt| match evt.into_data() {
            InterfoldEventData::TestEvent(data) => Some(data.msg),
            _ => None,
        })
        .collect();

    assert_eq!(msgs, expected);

    Ok(())
}
