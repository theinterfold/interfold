// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::replay_spool::ReplaySpool;
use actix::{Actor, Handler, ResponseFuture};
use e3_events::{EventContextSeq, Subscribe};
use std::{
    collections::HashMap,
    future::{poll_fn, Future},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::Poll,
    time::Duration,
};
use tokio::sync::oneshot;

async fn load_replay_fixture(events: Vec<InterfoldEvent>) -> anyhow::Result<ReplaySpool> {
    let cursors: HashMap<_, _> = events
        .iter()
        .map(|event| (event.aggregate_id(), 0))
        .collect();
    let config = cursors.keys().map(|id| (*id, Duration::ZERO)).collect();
    // Keep fixture ingestion separate from the destination's clock, deduplication, and history.
    let source = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(e3_events::AggregateConfig::new(config));
    let source_bus = source.handle()?.enable("replay-fixture-source");
    for event in &events {
        source_bus
            .naked_dispatch_async(event.clone_unsequenced())
            .await?;
    }
    source_bus.flush_event_pipeline().await?;

    let spool = ReplaySpool::load(&source.eventstore_reader()?.seq(), cursors).await?;
    assert_eq!(
        spool.total_events(),
        events.len(),
        "Load every fixture event from EventStore"
    );
    Ok(spool)
}

#[actix::test]
async fn router_checkpoint_advances_without_losing_state() -> anyhow::Result<()> {
    let system =
        EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(e3_events::AggregateConfig::new(
                std::collections::HashMap::from([(AggregateId::new(1), std::time::Duration::ZERO)]),
            ));
    let bus = system.handle()?.enable("test-router-checkpoint-advance");
    let aggregate_id = AggregateId::new(1);
    let active_e3 = E3id::new("7", 1);
    bus.naked_dispatch_async(
        InterfoldEvent::<Unsequenced>::test_event("stored first")
            .id(1)
            .aggregate_id(1)
            .ts(200)
            .build(),
    )
    .await?;
    bus.naked_dispatch_async(
        InterfoldEvent::<Unsequenced>::test_event("stored second")
            .id(2)
            .aggregate_id(1)
            .ts(100)
            .build(),
    )
    .await?;
    bus.flush_event_pipeline().await?;

    let store = system.store()?;
    let repositories = Repositories::from(&store);
    repositories
        .aggregate_seq(aggregate_id)
        .write_sync(&2)
        .await?;
    repositories
        .request_router_checkpoint()
        .write_sync(&RequestRouterCheckpoint {
            contexts: vec![active_e3.clone()],
            replay_cursors: std::collections::HashMap::from([(aggregate_id, 1)]),
            ..Default::default()
        })
        .await?;

    reconcile_request_router_checkpoint(
        &repositories,
        [aggregate_id],
        &system.eventstore_reader()?.seq(),
    )
    .await?;

    let checkpoint = repositories
        .request_router_checkpoint()
        .read()
        .await?
        .expect("the advanced checkpoint should exist");
    assert_eq!(checkpoint.replay_cursors.get(&aggregate_id), Some(&2));
    assert!(checkpoint.contexts.contains(&active_e3));
    Ok(())
}

#[actix::test]
async fn infrastructure_events_are_filtered_during_replay() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-sync-replay");
    let history = bus.history();

    let events: Vec<InterfoldEvent> = vec![
        InterfoldEvent::<Unsequenced>::test_event("before")
            .id(1)
            .ts(1)
            .seq(1)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("sync")
            .data(SyncEnded::new())
            .ts(2)
            .seq(2)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("fx")
            .data(EffectsEnabled::new())
            .ts(3)
            .seq(3)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("evm")
            .data(make_historical_evm_sync_start())
            .ts(4)
            .seq(4)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("net-start")
            .data(HistoricalNetSyncStart::new(BTreeMap::new()))
            .ts(5)
            .seq(5)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("net-complete")
            .data(HistoricalNetSyncEventsReceived::new(Vec::new()))
            .ts(6)
            .seq(6)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("sync-effect")
            .data(SyncEffect::new())
            .ts(7)
            .seq(7)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("net-ready")
            .data(NetReady::new())
            .ts(8)
            .seq(8)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("after")
            .id(2)
            .ts(9)
            .seq(9)
            .build(),
    ];

    let replayed = load_replay_fixture(events).await?.replay(&bus).await?;
    assert_eq!(replayed, 2);

    let received = history.send(TakeEvents::new(2)).await?;

    let event_types: Vec<&'static str> = received
        .events
        .iter()
        .map(|e| match e.get_data() {
            InterfoldEventData::TestEvent(_) => "TestEvent",
            InterfoldEventData::SyncEnded(_) => "SyncEnded",
            InterfoldEventData::EffectsEnabled(_) => "EffectsEnabled",
            InterfoldEventData::HistoricalEvmSyncStart(_) => "HistoricalEvmSyncStart",
            _ => "other",
        })
        .collect();

    assert_eq!(event_types, vec!["TestEvent", "TestEvent"]);

    let msgs: Vec<String> = received
        .events
        .iter()
        .filter_map(|e| {
            if let InterfoldEventData::TestEvent(t) = e.get_data() {
                Some(t.msg.clone())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(msgs, vec!["before", "after"]);
    Ok(())
}

#[actix::test]
async fn empty_net_sync_completes_after_restart() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-empty-net-sync-restart");
    let stale_completion = InterfoldEvent::<Unsequenced>::test_event("stale-net-complete")
        .data(HistoricalNetSyncEventsReceived::new(Vec::new()))
        .seq(1)
        .build();
    let stale_event_id = stale_completion.id();

    let replayed = load_replay_fixture(vec![stale_completion])
        .await?
        .replay(&bus)
        .await?;
    assert_eq!(replayed, 0);

    let completion = bus.wait_for(EventType::HistoricalNetSyncEventsReceived);
    bus.publish_without_context(HistoricalNetSyncEventsReceived::new(Vec::new()))?;
    let received = tokio::time::timeout(std::time::Duration::from_secs(1), completion).await??;

    assert!(matches!(
        received.get_data(),
        InterfoldEventData::HistoricalNetSyncEventsReceived(event) if event.events.is_empty()
    ));
    assert_eq!(received.id(), stale_event_id);
    Ok(())
}

#[actix::test]
async fn backfill_recovers_committee_inputs() -> anyhow::Result<()> {
    let aggregate_id = AggregateId::from_chain_id(Some(1));
    let system =
        EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(e3_events::AggregateConfig::new(
                std::collections::HashMap::from([(aggregate_id, std::time::Duration::ZERO)]),
            ));
    let bus = system.handle()?.enable("test-sortition-seed-recovery");
    let e3_id = E3id::new("7", 1);
    let seed = Seed([0x42; 32]);
    bus.publish_without_context(E3Requested {
        e3_id: e3_id.clone(),
        request_block: 10,
        threshold_m: 1,
        threshold_n: 3,
        ..Default::default()
    })?;
    bus.publish_without_context(CommitteeRequested {
        e3_id: e3_id.clone(),
        seed,
        threshold: [1, 3],
        request_block: 10,
        committee_deadline: 20,
        ticket_price: Default::default(),
        chain_id: 1,
    })?;
    bus.publish_without_context(TicketGenerated {
        e3_id: e3_id.clone(),
        ticket_id: TicketId::Score(9),
        node: "0x1111111111111111111111111111111111111111".to_string(),
        party_index: Some(2),
    })?;
    bus.flush_event_pipeline().await?;

    let recovered = project_restart_state_backfill(
        &system.eventstore_reader()?.seq(),
        std::collections::HashMap::from([(aggregate_id, 3)]),
        &std::collections::HashSet::from([e3_id.clone()]),
        &std::collections::HashSet::new(),
    )
    .await?;

    assert_eq!(recovered.sortition_seeds.get(&e3_id), Some(&seed));
    assert_eq!(
        recovered
            .pending_sortition_requests
            .get(&e3_id)
            .map(|request| request.request_block),
        Some(10)
    );
    assert_eq!(
        recovered
            .committee_requests
            .get(&e3_id)
            .map(|request| request.request.committee_deadline),
        Some(20)
    );
    assert_eq!(
        recovered
            .tickets
            .get(&e3_id)
            .and_then(|ticket| ticket.party_index),
        Some(2)
    );
    Ok(())
}

#[actix::test]
async fn backfill_tracks_unresolved_slash_intents() -> anyhow::Result<()> {
    let aggregate_id = AggregateId::from_chain_id(Some(1));
    let system =
        EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(e3_events::AggregateConfig::new(
                std::collections::HashMap::from([(aggregate_id, std::time::Duration::ZERO)]),
            ));
    let bus = system.handle()?.enable("test-slash-intent-recovery");
    let e3_id = E3id::new("7", 1);
    let accuser = "0x1111111111111111111111111111111111111111".parse()?;
    let accused = "0x2222222222222222222222222222222222222222".parse()?;
    let intent = AccusationQuorumReached {
        e3_id: e3_id.clone(),
        accuser,
        accused,
        proof_type: ProofType::C1PkGeneration,
        votes_for: Vec::new(),
        outcome: AccusationOutcome::AccusedFaulted,
        evidence: Default::default(),
    };
    bus.publish_without_context(intent.clone())?;
    bus.publish_without_context(E3StageChanged {
        e3_id: e3_id.clone(),
        previous_stage: E3Stage::KeyPublished,
        new_stage: E3Stage::Failed,
    })?;
    bus.flush_event_pipeline().await?;

    let slash_chains = std::collections::HashSet::from([1]);
    let recovered = project_restart_state_backfill(
        &system.eventstore_reader()?.seq(),
        std::collections::HashMap::from([(aggregate_id, 2)]),
        &std::collections::HashSet::new(),
        &slash_chains,
    )
    .await?;
    assert_eq!(recovered.slash_intents, vec![intent.clone()]);

    bus.publish_without_context(SlashExecuted {
        e3_id: e3_id.clone(),
        proposal_id: 1,
        operator: accused,
        reason: intent.proof_type.attestation_slash_reason().0,
        ticket_amount: 0,
        ciphernode_bond_amount: 0,
    })?;
    bus.flush_event_pipeline().await?;
    let recovered = project_restart_state_backfill(
        &system.eventstore_reader()?.seq(),
        std::collections::HashMap::from([(aggregate_id, 3)]),
        &std::collections::HashSet::new(),
        &slash_chains,
    )
    .await?;
    assert!(recovered.slash_intents.is_empty());

    let second_intent = AccusationQuorumReached {
        proof_type: ProofType::C2aSkShareComputation,
        ..intent
    };
    bus.publish_without_context(second_intent.clone())?;
    bus.publish_without_context(CommitteeMemberExcluded {
        e3_id,
        node: accused,
        proof_type: second_intent.proof_type,
        party_id: None,
    })?;
    bus.flush_event_pipeline().await?;
    let recovered = project_restart_state_backfill(
        &system.eventstore_reader()?.seq(),
        std::collections::HashMap::from([(aggregate_id, 5)]),
        &std::collections::HashSet::new(),
        &slash_chains,
    )
    .await?;
    assert!(recovered.slash_intents.is_empty());
    Ok(())
}

#[actix::test]
async fn replay_backlog_larger_than_event_bus_mailbox_is_delivered() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-large-sync-replay");
    let history = bus.history();
    let count = MAILBOX_LIMIT_LARGE * 2;
    let events = (0..count)
        .map(|i| {
            InterfoldEvent::<Unsequenced>::test_event("replay")
                .id(i as u64 + 1)
                .ts(i as u128 + 1)
                .seq(i as u64 + 1)
                .build()
        })
        .collect();

    let replayed = load_replay_fixture(events).await?.replay(&bus).await?;
    assert_eq!(replayed, count);

    let received = history.send(TakeEvents::new(count)).await?;
    assert!(!received.timed_out, "all replay events should be delivered");
    assert_eq!(received.events.len(), count);
    Ok(())
}

#[actix::test]
async fn replay_restores_global_timestamp_order_across_aggregates() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-ordered-sync-replay");
    let history = bus.history();
    let events = vec![
        InterfoldEvent::<Unsequenced>::test_event("third")
            .id(3)
            .aggregate_id(3)
            .ts(30)
            .seq(1)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("first")
            .id(1)
            .aggregate_id(1)
            .ts(10)
            .seq(1)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("second")
            .id(2)
            .aggregate_id(2)
            .ts(20)
            .seq(1)
            .build(),
    ];

    load_replay_fixture(events).await?.replay(&bus).await?;

    let received = history.send(TakeEvents::new(3)).await?;
    let timestamps = received
        .events
        .iter()
        .map(|event| event.ts())
        .collect::<Vec<_>>();
    assert_eq!(timestamps, vec![10, 20, 30]);
    Ok(())
}

#[actix::test]
async fn replay_seeds_clock_from_post_snapshot_log_history() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system
        .handle()?
        .enable_with_hlc(Hlc::new(7).with_clock(|| 1_000));
    let durable = HlcTimestamp::new(5_000, 17, 99);
    let events = vec![InterfoldEvent::<Unsequenced>::test_event("durable")
        .id(1)
        .ts(durable.to_u128())
        .seq(1)
        .build()];

    load_replay_fixture(events).await?.replay(&bus).await?;

    assert!(HlcTimestamp::from(bus.ts()?) > durable);
    Ok(())
}

#[actix::test]
async fn replay_preserves_aggregate_sequence_when_timestamps_regress() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-sequence-first-replay");
    let history = bus.history();
    let events = [(1, 1, 200), (2, 1, 100), (3, 2, 150), (4, 2, 200)]
        .into_iter()
        .map(|(id, aggregate, timestamp)| {
            InterfoldEvent::<Unsequenced>::test_event("sequence first")
                .id(id)
                .aggregate_id(aggregate)
                .ts(timestamp)
                .seq(if id == 2 || id == 4 { 2 } else { 1 })
                .build()
        })
        .collect();

    assert_eq!(load_replay_fixture(events).await?.replay(&bus).await?, 4);
    let received = history.send(TakeEvents::new(4)).await?;
    assert!(!received.timed_out);
    let actual = received
        .events
        .iter()
        .map(|event| (event.aggregate_id(), event.seq(), event.ts()))
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            (AggregateId::new(2), 1, 150),
            (AggregateId::new(1), 1, 200),
            (AggregateId::new(1), 2, 100),
            (AggregateId::new(2), 2, 200),
        ]
    );
    Ok(())
}

struct GatedReplaySubscriber {
    started: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
    completed: Arc<AtomicBool>,
}

impl Actor for GatedReplaySubscriber {
    type Context = actix::Context<Self>;
}

impl Handler<InterfoldEvent> for GatedReplaySubscriber {
    type Result = ResponseFuture<()>;

    fn handle(&mut self, _: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        let started = self.started.take().expect("one replay event");
        let release = self.release.take().expect("one replay event");
        let completed = Arc::clone(&self.completed);
        Box::pin(async move {
            started.send(()).expect("replay test is waiting");
            release.await.expect("replay test releases the subscriber");
            completed.store(true, Ordering::SeqCst);
        })
    }
}

#[actix::test]
async fn replay_waits_for_the_final_subscriber() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-replay-acknowledgement");
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let completed = Arc::new(AtomicBool::new(false));
    let subscriber = GatedReplaySubscriber {
        started: Some(started_tx),
        release: Some(release_rx),
        completed: Arc::clone(&completed),
    }
    .start();
    bus.event_bus()
        .send(Subscribe::new(EventType::TestEvent, subscriber.recipient()))
        .await?;

    let event = InterfoldEvent::<Unsequenced>::test_event("final replay event")
        .seq(1)
        .build();
    let spool = load_replay_fixture(vec![event]).await?;
    let mut replay = Box::pin(spool.replay(&bus));
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            biased;
            result = &mut replay => panic!("Replay completed before its subscriber: {result:?}"),
            started = started_rx => started.expect("subscriber must start"),
        }
        assert!(
            poll_fn(|cx| Poll::Ready(replay.as_mut().poll(cx).is_pending())).await,
            "Replay must remain pending while its final subscriber is blocked"
        );
        release_tx.send(()).expect("subscriber is waiting");
        assert_eq!(replay.await?, 1);
        assert!(
            completed.load(Ordering::SeqCst),
            "The final subscriber must finish before replay returns"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
