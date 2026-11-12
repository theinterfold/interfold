// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod ciphernode_system;
mod common;
mod trbfv;

use actix::Actor;
use anyhow::Result;
use e3_event_system::EventSystem;
use e3_events::{
    prelude::*, AggregateConfig, AggregateId, E3id, InterfoldEvent, InterfoldEventData, TakeEvents,
};
use e3_net::events::{GossipData, NetEvent};
use e3_net::NetEventTranslator;
use e3_utils::utility_types::ArcBytes;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use trbfv::{run_and_check, scenario::Scenario};

// ============================================================================
// Full-proof trBFV scenarios
//
// Each scenario runs a whole E3 on real ciphernodes with real proofs and asserts its outcome:
// the key, the plaintext, the DKG roster, and the absence of faults. `run_and_check` runs the
// scenario, then checks the observations against what the scenario expects. It does not assert how
// the nodes order their events, and its frozen DKG window is far longer than a run's DKG, so no
// scenario here waits for a progress deadline.
//
// Proof-system and timeout settings come from the environment (`CIPHERNODE_SKIP_PROOF_AGGREGATION`,
// `E3_*_COLLECTION_TIMEOUT_SECS`, `E3_CUSTOM_BB`).
// ============================================================================

/// The committee has a standby party (N > H): the run completes with every party online.
#[actix::test]
#[serial_test::serial]
async fn trbfv_scenario_standby_node() -> Result<()> {
    run_and_check(&Scenario::standby_node()).await?;
    Ok(())
}

/// Party 1 goes offline after publishing C0; the aggregator selects a roster without it.
#[actix::test]
#[serial_test::serial]
async fn trbfv_scenario_party_offline_after_c0() -> Result<()> {
    run_and_check(&Scenario::offline_after_c0(1)).await?;
    Ok(())
}

/// Party 1 restarts from its persisted stores while its C4 proof is pending, and shares it.
#[actix::test]
#[serial_test::serial]
#[ignore = "full-proof restart run, not in CI; select it with --ignored"]
async fn trbfv_scenario_restart_during_c4() -> Result<()> {
    run_and_check(&Scenario::restart_during_c4(1)).await?;
    Ok(())
}

/// Party 1 restarts from its persisted stores while its C6 proof is pending, and decrypts.
#[actix::test]
#[serial_test::serial]
#[ignore = "full-proof restart run, not in CI; select it with --ignored"]
async fn trbfv_scenario_restart_during_c6() -> Result<()> {
    run_and_check(&Scenario::restart_during_c6(1)).await?;
    Ok(())
}

/// The circuit benchmark's entry (`crates/zk/benchmarks`): the all-online run, reported as JSON.
/// Ignored because it only means something in the benchmark's environment.
#[actix::test]
#[serial_test::serial]
#[ignore = "benchmark entry; run by the circuit benchmark tool"]
async fn benchmark_trbfv_actor() -> Result<()> {
    trbfv::benchmark::run_from_env().await
}

// ============================================================================
// Networking and P2P Tests
// ============================================================================

#[actix::test]
async fn test_p2p_actor_forwards_events_to_network() -> Result<()> {
    use e3_events::{
        CiphernodeSelected, E3Requested, InterfoldEvent, KeyshareCreated, TakeEvents, Unsequenced,
    };
    use e3_net::events::GossipData;
    use e3_net::{events::NetEvent, NetEventTranslator};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio::sync::Mutex;

    // Setup elements in test
    let (cmd_tx, mut cmd_rx) = mpsc::channel(100); // Transmit byte events to the network
    let event_tx = e3_net::NetEventChannel::new(100); // Receive byte events from the network
    let aggregate_config =
        AggregateConfig::new(HashMap::from([(AggregateId::new(1), Duration::ZERO)]));
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(aggregate_config);
    let bus = system.handle()?.enable("test");
    let history_collector = bus.history();
    let event_rx = e3_net::NetEventSubscriber::from(&event_tx);
    // Pas cmd and event channels to NetEventTranslator
    NetEventTranslator::setup(
        &bus,
        &cmd_tx,
        &event_rx,
        "my-topic",
        e3_net::NetworkPolicy::local_unrestricted(),
        e3_net::LiveHistory::default(),
    );

    // Capture messages from output on msgs vec
    let msgs: Arc<Mutex<Vec<InterfoldEventData>>> = Arc::new(Mutex::new(Vec::new()));

    let msgs_loop = msgs.clone();

    tokio::spawn(async move {
        // Pull events from command channel
        while let Some(cmd) = cmd_rx.recv().await {
            // If the command is a GossipPublish then extract it and save it whilst sending it to
            // the event bus as if it was gossiped from the network and ended up as an external
            // message this simulates a rebroadcast message
            if let Some(msg) = match cmd {
                e3_net::events::NetCommand::GossipPublish { data, .. } => Some(data),
                _ => None,
            } {
                if let GossipData::GossipBytes(_) = msg {
                    let event: InterfoldEvent<Unsequenced> = msg.clone().try_into().unwrap();
                    let (data, _) = event.split();
                    msgs_loop.lock().await.push(data);
                    event_tx.send(NetEvent::GossipData(msg)).unwrap();
                }
            }
            // if this  manages to broadcast an event to the
            // event bus we will expect to see an extra event on
            // the bus but we don't because we handle this
        }
        anyhow::Ok(())
    });

    let evt_1 = KeyshareCreated {
        e3_id: E3id::new("1235", 1),
        pubkey: ArcBytes::from_bytes(&[1, 2, 3, 4]),
        node: "node-1".to_string(),
        party_id: 0,
        signed_pk_generation_proof: None,
    };

    let evt_2 = KeyshareCreated {
        e3_id: E3id::new("1236", 1),
        pubkey: ArcBytes::from_bytes(&[1, 2, 3, 4]),
        node: "node-2".to_string(),
        party_id: 1,
        signed_pk_generation_proof: None,
    };

    let local_evt_3 = CiphernodeSelected {
        e3_id: E3id::new("1235", 1),
        threshold_m: 2,
        threshold_n: 5,
        params_profile: e3_fhe_params::BfvProfile::SsSecure8192,
        crypto_config_id: [42; 32],
        ..CiphernodeSelected::default()
    };
    let local_evt_4 = E3Requested {
        e3_id: local_evt_3.e3_id.clone(),
        params_profile: local_evt_3.params_profile,
        crypto_config_id: local_evt_3.crypto_config_id,
        ..Default::default()
    };

    bus.publish_without_context(evt_1.clone())?;
    bus.publish_without_context(evt_2.clone())?;
    bus.publish_without_context(local_evt_3.clone())?; // This is a local event which should not be broadcast to the network
    bus.publish_without_context(local_evt_4.clone())?;

    // check the history of the event bus
    let history = history_collector
        .send(TakeEvents::<InterfoldEvent>::new(4))
        .await?;

    // The bus dispatches one event at a time and waits until every subscriber has handled it.
    // The history already holds the events above, so the translator handles this event after
    // them and gossips it after any of them that it forwards.
    let sentinel = KeyshareCreated {
        e3_id: E3id::new("1237", 1),
        pubkey: ArcBytes::from_bytes(&[1, 2, 3, 4]),
        node: "node-3".to_string(),
        party_id: 2,
        signed_pk_generation_proof: None,
    };
    bus.publish_without_context(sentinel.clone())?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while msgs.lock().await.len() < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("the translator did not forward the sentinel event"))?;

    assert_eq!(
        *msgs.lock().await,
        vec![evt_1.clone().into(), evt_2.clone().into(), sentinel.into()], // notice no local events
        "NetEventTranslator did not transmit correct events to the network"
    );

    // Historical sync uses the same rule: it neither serves these events nor accepts them from a
    // peer.
    for event in &history.events[2..] {
        assert!(
            !NetEventTranslator::is_forwardable_event(event),
            "{} must stay local",
            event.event_type()
        );
    }

    assert_eq!(
        history
            .events
            .into_iter()
            .map(|e| e.into_data())
            .collect::<Vec<_>>(),
        vec![
            evt_1.into(),
            evt_2.into(),
            local_evt_3.into(),
            local_evt_4.into()
        ], // all local events that have been broadcast but no
        // events from the loopback
        "NetEventTranslator must not retransmit forwarded event to event bus"
    );

    Ok(())
}

#[actix::test]
async fn test_p2p_actor_stores_a_repeated_gossip_event_once() -> Result<()> {
    use e3_events::{EventBus, EventBusConfig, KeyshareCreated};

    // With delivery dedup off, the bus history shows every stored copy of an event.
    let (cmd_tx, _) = mpsc::channel(100);
    let event_tx = e3_net::NetEventChannel::new(100);
    let _event_rx = event_tx.subscribe();
    let aggregate_config =
        AggregateConfig::new(HashMap::from([(AggregateId::new(1), Duration::ZERO)]));
    let system = EventSystem::new()
        .with_event_bus(EventBus::new(EventBusConfig { deduplicate: false }).start())
        .with_aggregate_config(aggregate_config);
    let bus = system.handle()?.enable("test");
    let history_collector = bus.history();

    NetEventTranslator::setup(
        &bus,
        &cmd_tx,
        &e3_net::NetEventSubscriber::from(&event_tx),
        "mytopic",
        e3_net::NetworkPolicy::local_unrestricted(),
        e3_net::LiveHistory::default(),
    );

    let keyshare = |party_id: u64| KeyshareCreated {
        e3_id: E3id::new("1235", 1),
        pubkey: ArcBytes::from_bytes(&[1, 2, 3, 4]),
        node: format!("node-{party_id}"),
        party_id,
        signed_pk_generation_proof: None,
    };
    let gossip = |event: KeyshareCreated| -> Result<NetEvent> {
        Ok(NetEvent::GossipData(GossipData::GossipBytes(
            bus.event_from(event, None)?.to_bytes()?,
        )))
    };

    event_tx.send(gossip(keyshare(0))?)?;
    let first = history_collector
        .send(TakeEvents::<InterfoldEvent>::new(1))
        .await?;
    assert_eq!(first.events.len(), 1, "the first copy must be stored");

    // A peer re-sends the same event in a new gossip message, then sends another event.
    event_tx.send(gossip(keyshare(0))?)?;
    event_tx.send(gossip(keyshare(1))?)?;
    let next = history_collector
        .send(TakeEvents::<InterfoldEvent>::new(1))
        .await?;

    assert_eq!(
        next.events
            .into_iter()
            .map(|e| e.into_data())
            .collect::<Vec<InterfoldEventData>>(),
        vec![keyshare(1).into()],
        "the repeated copy must not be stored again"
    );

    Ok(())
}

/// Collects the response of one event-store query.
struct StoredEvents(Option<tokio::sync::oneshot::Sender<Vec<InterfoldEvent>>>);

impl actix::Actor for StoredEvents {
    type Context = actix::Context<Self>;
}

impl actix::Handler<e3_events::EventStoreQueryResponse> for StoredEvents {
    type Result = ();
    fn handle(&mut self, msg: e3_events::EventStoreQueryResponse, _: &mut Self::Context) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(msg.into_events().expect("event-store query failed"));
        }
    }
}

#[actix::test]
async fn test_p2p_actor_stores_a_replayed_event_at_most_once_more() -> Result<()> {
    use e3_events::{CorrelationId, EventSource, EventStoreQueryBy, KeyshareCreated, TsAgg};

    // The default bus: it does not deliver an event ID twice, as after replay.
    let (cmd_tx, _) = mpsc::channel(100);
    let event_tx = e3_net::NetEventChannel::new(100);
    let _event_rx = event_tx.subscribe();
    let aggregate_config =
        AggregateConfig::new(HashMap::from([(AggregateId::new(1), Duration::ZERO)]));
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(aggregate_config);
    let bus = system.handle()?.enable("test");

    let keyshare = |party_id: u64| KeyshareCreated {
        e3_id: E3id::new("1235", 1),
        pubkey: ArcBytes::from_bytes(&[1, 2, 3, 4]),
        node: format!("node-{party_id}"),
        party_id,
        signed_pk_generation_proof: None,
    };
    let gossip = |event: KeyshareCreated| -> Result<NetEvent> {
        Ok(NetEvent::GossipData(GossipData::GossipBytes(
            bus.event_from(event, None)?.to_bytes()?,
        )))
    };

    // The event is already stored and known to the bus before the translator starts.
    bus.publish_from_remote(keyshare(0), 1, None, EventSource::Net)?;
    bus.flush_event_pipeline().await?;
    let history_collector = bus.history();
    NetEventTranslator::setup(
        &bus,
        &cmd_tx,
        &e3_net::NetEventSubscriber::from(&event_tx),
        "mytopic",
        e3_net::NetworkPolicy::local_unrestricted(),
        e3_net::LiveHistory::default(),
    );

    // A peer re-sends it three times, then sends another event.
    for _ in 0..3 {
        event_tx.send(gossip(keyshare(0))?)?;
    }
    event_tx.send(gossip(keyshare(1))?)?;
    let next = history_collector
        .send(TakeEvents::<InterfoldEvent>::new(1))
        .await?;
    assert_eq!(next.events.len(), 1, "the other event must be delivered");
    bus.flush_event_pipeline().await?;

    let (tx, rx) = tokio::sync::oneshot::channel();
    let collector = StoredEvents(Some(tx)).start();
    system
        .eventstore_reader()?
        .ts()
        .send(EventStoreQueryBy::<TsAgg>::new(
            CorrelationId::new(),
            HashMap::from([(AggregateId::new(1), 0)]),
            collector.recipient(),
        ))
        .await?;
    let stored = tokio::time::timeout(Duration::from_secs(5), rx).await??;
    let copies = stored
        .iter()
        .filter(|event| event.get_data() == &InterfoldEventData::from(keyshare(0)))
        .count();
    assert_eq!(
        copies, 2,
        "one copy from before the translator started and one re-sent copy"
    );

    Ok(())
}

#[actix::test]
async fn test_p2p_actor_mislabeled_event_does_not_suppress_the_real_one() -> Result<()> {
    use e3_events::{EventContext, EventSource, KeyshareCreated, Unsequenced};

    let (cmd_tx, _) = mpsc::channel(100);
    let event_tx = e3_net::NetEventChannel::new(100);
    let _event_rx = event_tx.subscribe();
    let aggregate_config =
        AggregateConfig::new(HashMap::from([(AggregateId::new(1), Duration::ZERO)]));
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(aggregate_config);
    let bus = system.handle()?.enable("test");
    let history_collector = bus.history();
    NetEventTranslator::setup(
        &bus,
        &cmd_tx,
        &e3_net::NetEventSubscriber::from(&event_tx),
        "mytopic",
        e3_net::NetworkPolicy::local_unrestricted(),
        e3_net::LiveHistory::default(),
    );

    let keyshare = |party_id: u64| KeyshareCreated {
        e3_id: E3id::new("1235", 1),
        pubkey: ArcBytes::from_bytes(&[1, 2, 3, 4]),
        node: format!("node-{party_id}"),
        party_id,
        signed_pk_generation_proof: None,
    };
    let genuine = bus.event_from(keyshare(0), None)?;

    // A peer sends party 1's keyshare labeled with the ID of party 0's keyshare.
    let payload: InterfoldEventData = keyshare(1).into();
    let context = EventContext::<Unsequenced>::new_origin(
        genuine.id(),
        1,
        AggregateId::new(1),
        None,
        EventSource::Local,
    );
    let forged = bincode::serialize(&(payload, context))?;
    event_tx.send(NetEvent::GossipData(GossipData::GossipBytes(forged)))?;
    event_tx.send(NetEvent::GossipData(GossipData::GossipBytes(
        genuine.to_bytes()?,
    )))?;

    let history = history_collector
        .send(TakeEvents::<InterfoldEvent>::new(2))
        .await?;
    assert_eq!(
        history
            .events
            .into_iter()
            .map(|e| e.into_data())
            .collect::<Vec<InterfoldEventData>>(),
        vec![keyshare(1).into(), keyshare(0).into()],
        "the genuine event must still be stored after a mislabeled one"
    );

    Ok(())
}
