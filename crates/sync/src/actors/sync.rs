// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::{
    decide_schema_version, CollectOutcome, HistoricalEvmCollector, ReplayDecision,
    SchemaVersionDecision, SnapshotMeta, SyncPlanner, SCHEMA_VERSION,
};
use crate::SyncRepositoryFactory;
use actix::{Message, Recipient};
use anyhow::{bail, Result};
use e3_data::Repositories;
use e3_events::{
    AggregateConfig, BusHandle, CorrelationId, EffectsEnabled, Event, EventPublisher,
    EventStoreQueryBy, EventStoreQueryResponse, EventSubscriber, EventType, EvmEventConfig,
    HistoricalEvmEventsReceived, HistoricalEvmSyncStart, HistoricalNetSyncStart, InterfoldEvent,
    InterfoldEventData, SeqAgg, SyncEnded, Unsequenced,
};
use e3_utils::actix::channel as actix_toolbox;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tracing::{info, warn};

pub async fn sync(
    bus: &BusHandle,
    default_config: &EvmEventConfig,
    repositories: &Repositories,
    aggregate_config: &AggregateConfig,
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
) -> Result<()> {
    // 0. start listening early for net ready
    let net_ready = bus.wait_for(EventType::NetReady);

    // 0b. Verify the on-disk schema version is compatible with this binary
    //     before touching any persisted state, so an incompatible upgrade or
    //     downgrade halts loudly instead of silently loading garbage (H19/H20).
    check_schema_version(repositories).await?;

    // 1. Load snapsshot metadata
    info!("Loading snapshot metadata...");
    let snapshot =
        SnapshotMeta::read_from_disk(aggregate_config.aggregates(), default_config, repositories)
            .await?;
    info!(
        "Snapshot metadata loaded for {} aggregates.",
        snapshot.aggregates().len()
    );

    // 1b. Seed the HLC physical-time floor from the highest persisted aggregate
    //     timestamp so events created after this restart never sort before
    //     durable history, even if the wall clock jumped backwards (H15).
    if let Some(max_ts) = snapshot.to_net_config().values().copied().max() {
        bus.seed_clock(max_ts);
    }

    // 2. Determine the evm blocks to read from based on the SnapshotMeta
    let evm_config = snapshot.to_evm_config();
    let snapshot_net_config = snapshot.to_net_config();

    // 3. Load EventStore events since the sequence number found in the snapshot into memory.
    info!("Loading EventStore events...");
    let (addr, rx) = actix_toolbox::oneshot::<EventStoreQueryResponse>();
    eventstore.try_send(EventStoreQueryBy::<SeqAgg>::new(
        CorrelationId::new(),
        snapshot.to_sequence_map(),
        addr,
    ))?;
    let events = rx.await?.into_events();
    info!("{} EventStore events loaded.", events.len());

    info!("Replaying events to actors...");
    // 4. Replay the EventStore events to all listeners (except effects).
    //    Skip infrastructure events (SyncEnded, EffectsEnabled, HistoricalEvmSyncStart) because
    //    they will be re-published by this sync process (steps 5, 8, 10). Replaying them here
    //    would poison the EventBus bloom-filter deduplication: the replayed event has the same
    //    EventId (payload hash) as the one we publish later, causing the later event to be
    //    silently dropped.  This is critical for SyncEnded, if the EvmChainGateway never
    //    receives it, the gateway stays in BufferUntilLive and all live EVM events are lost.
    for event in events {
        if SyncPlanner::classify_replay(&event) == ReplayDecision::SkipInfrastructure {
            continue;
        }
        bus.event_bus().try_send(event)?;
    }
    info!("Events replayed.");

    // Loose ends after a crash:
    //
    // Terminal E3 work that *completed while this node was down* is recovered by the
    // historical EVM re-fetch in step 5 below: the terminal on-chain events
    // (PlaintextOutputPublished / E3Failed / committee completion) are re-delivered once
    // effects are enabled, which re-drives the Sortition release path and frees any tickets
    // the node was still holding. So "an E3 finished while we were offline" needs no special
    // handling here — it is reconciled by replaying the canonical chain state.
    //
    // What is intentionally NOT auto-re-driven *here in sync* is this node's *own* in-flight
    // request work by replaying the originating request events. Blindly re-publishing the
    // originating request event is a no-op: the event bus dedups by EventId (payload hash), so
    // the replayed event is dropped. Forcibly minting a fresh EventId to force re-execution is
    // unsafe on a value-bearing protocol (it can double-emit or race the canonical chain state)
    // and is therefore deliberately left out of the sync path.
    //
    // Note: this is *not* a global absence of restart recovery. Actors that hold determined,
    // idempotent in-flight results re-drive themselves when `EffectsEnabled` is broadcast at the
    // end of this sync (e.g. `ThresholdKeyshare::resume_in_flight_work` re-publishes a computed
    // keyshare / decryption share). What sync deliberately avoids is replaying *request* events.
    //
    // Detection of loose ends that cannot be locally re-driven is exposed offline and
    // non-destructively via `interfold node validate`, which cross-checks the persisted committee
    // slots against terminal events in the log and reports orphaned tickets. See
    // `crates/entrypoint/src/validate.rs`.

    // 5. Load the historical evm events to memory from all chains
    info!("Loading historical blockchain events...");
    let (addr, rx) = actix_toolbox::mpsc::<HistoricalEvmEventsReceived>(256);
    bus.publish_without_context(HistoricalEvmSyncStart::new(addr, evm_config.clone()))?;
    let historical_evm_events = collect_historical_evm_events(rx, &evm_config).await;
    info!(
        "{} historical blockchain events loaded.",
        historical_evm_events.len()
    );
    // Build the net sync cursor using snapshot timestamps (the original HLC timestamps
    // from before the restart). See SyncPlanner::net_sync_cursor for why the re-read EVM
    // event timestamps cannot be used.
    let net_config = SyncPlanner::net_sync_cursor(&historical_evm_events, &snapshot_net_config);

    // 6. Load the historical libp2p events to memory
    info!("Waiting until NetReady...");
    net_ready.await?;
    info!("NetReady!");
    info!("Loading historical libp2p events...");
    let events_received = bus.wait_for(EventType::HistoricalNetSyncEventsReceived);
    bus.publish_without_context(HistoricalNetSyncStart::new(net_config.clone()))?;
    let InterfoldEventData::HistoricalNetSyncEventsReceived(event) =
        events_received.await?.into_data()
    else {
        bail!("failed to get HistoricalNetSyncEventsReceived");
    };
    let historical_net_events = event.events;
    info!(
        "{} historical libp2p events loaded.",
        historical_net_events.len()
    );

    // 7. Sort both the evm and libp2p events together by HLC timestamp
    let mut historical = historical_evm_events
        .into_iter()
        .chain(historical_net_events)
        .collect::<Vec<_>>();

    SyncPlanner::sort_by_timestamp(&mut historical);
    info!("Historical events sorted.");

    // 8. Enable effects
    bus.publish_without_context(EffectsEnabled::new())?;
    info!("Effects enabled");

    // 9. Publish the new sorted events to the eventstore
    info!("Publishing historical events to actors...");
    for event in historical {
        bus.naked_dispatch_async(event).await?;
    }
    info!("Historical events published.");

    // 10. Publish the SyncEnded event
    info!("Publishing SyncEnded event...");
    bus.publish_without_context(SyncEnded::new())?;
    info!("Sync finished.");
    // normal live operations

    Ok(())
}

/// Verify the on-disk schema version against this binary and either stamp a
/// fresh marker (first boot) or halt loudly on an incompatible upgrade or
/// downgrade (H19/H20). Uses a synchronous write so the marker is durable
/// before any further state is loaded.
async fn check_schema_version(repositories: &Repositories) -> Result<()> {
    let repo = repositories.schema_version();
    let persisted = repo.read().await?;
    match decide_schema_version(persisted, SCHEMA_VERSION) {
        SchemaVersionDecision::Proceed => Ok(()),
        SchemaVersionDecision::WriteCurrent => {
            info!("Stamping on-disk schema version {SCHEMA_VERSION}.");
            repo.write_sync(&SCHEMA_VERSION).await?;
            Ok(())
        }
        SchemaVersionDecision::Halt(reason) => {
            bail!("Schema version check failed: {reason}");
        }
    }
}

pub async fn collect_historical_evm_events(
    mut receiver: Receiver<HistoricalEvmEventsReceived>,
    config: &EvmEventConfig,
) -> Vec<InterfoldEvent<Unsequenced>> {
    let mut collector = HistoricalEvmCollector::new(config);
    let progress_interval = Duration::from_secs(30);

    while !collector.is_complete() {
        match tokio::time::timeout(progress_interval, receiver.recv()).await {
            Ok(Some(mut msg)) => {
                let chain_id = msg.chain_id;
                if let CollectOutcome::Recorded {
                    chains_received,
                    chains_expected,
                } = collector.record(&mut msg)
                {
                    info!(
                        chain_id,
                        chains_received, chains_expected, "Received historical events from chain"
                    );
                }
            }
            Ok(None) => {
                // Channel closed — sender dropped
                warn!("Historical events channel closed before all chains reported");
                break;
            }
            Err(_) => {
                // Not a failure — just a progress heartbeat
                let remaining = collector.remaining();
                info!(
                    ?remaining,
                    "Still waiting for historical events from chains"
                );
                continue;
            }
        }
    }

    collector.into_events()
}

#[derive(Message)]
#[rtype("()")]
pub struct Bootstrap;

#[derive(Message)]
#[rtype("()")]
pub struct SnapshotLoaded {
    pub snapshot: SnapshotMeta,
}
impl SnapshotLoaded {
    pub fn new(snapshot: SnapshotMeta) -> Self {
        Self { snapshot }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::SyncPlanner;
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{
        EffectsEnabled, Event, EventPublisher, EventSubscriber, EventType, EvmEventConfig,
        HistoricalEvmSyncStart, InterfoldEvent, InterfoldEventData, SyncEnded, TakeEvents,
        Unsequenced,
    };

    fn make_historical_evm_sync_start() -> HistoricalEvmSyncStart {
        HistoricalEvmSyncStart {
            evm_config: EvmEventConfig::new(),
            sender: None,
        }
    }

    #[actix::test]
    async fn infrastructure_events_are_filtered_during_replay() -> anyhow::Result<()> {
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("test-sync-replay");
        let history = bus.history();

        let events: Vec<InterfoldEvent> = vec![
            InterfoldEvent::<Unsequenced>::test_event("before")
                .id(1)
                .seq(1)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("sync")
                .data(SyncEnded::new())
                .seq(2)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("fx")
                .data(EffectsEnabled::new())
                .seq(3)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("evm")
                .data(make_historical_evm_sync_start())
                .seq(4)
                .build(),
            InterfoldEvent::<Unsequenced>::test_event("after")
                .id(2)
                .seq(5)
                .build(),
        ];

        for event in events {
            if SyncPlanner::is_infrastructure_event(&event) {
                continue;
            }
            bus.event_bus().try_send(event)?;
        }

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

    /// Verify that `run_once::<EffectsEnabled>` correctly gates event subscriptions.
    ///
    /// Simulates the sync flow:
    /// 1. An event is published BEFORE EffectsEnabled (should be dropped — nobody listening)
    /// 2. EffectsEnabled is published (triggers subscription)
    /// 3. The same event is published AFTER EffectsEnabled (should be received)
    ///
    /// This is the pattern used by Sortition (E3Requested), CommitteeFinalizer
    /// (CommitteeRequested), Multithread (ComputeRequest), and the sol writers.
    #[actix::test]
    async fn effects_enabled_gates_event_subscriptions() -> anyhow::Result<()> {
        use std::sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        };

        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("test-effects-gating");

        let receive_count = Arc::new(AtomicU32::new(0));

        // Set up a gated subscription: only subscribe to TestEvent after EffectsEnabled
        let counter = receive_count.clone();
        let runner = e3_events::run_once::<EffectsEnabled>({
            let bus = bus.clone();
            move |_| {
                // Create a simple actor that counts received TestEvents
                use actix::{Actor, Context, Handler};

                struct Counter(Arc<AtomicU32>);
                impl Actor for Counter {
                    type Context = Context<Self>;
                }
                impl Handler<InterfoldEvent> for Counter {
                    type Result = ();
                    fn handle(
                        &mut self,
                        msg: InterfoldEvent,
                        _: &mut Self::Context,
                    ) -> Self::Result {
                        if matches!(msg.get_data(), InterfoldEventData::TestEvent(_)) {
                            self.0.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }

                let addr = Counter(counter).start();
                bus.subscribe(EventType::TestEvent, addr.recipient());
                Ok(())
            }
        });
        bus.subscribe(EventType::EffectsEnabled, runner.recipient());

        // 1. Publish a TestEvent BEFORE EffectsEnabled — should NOT be received
        bus.event_bus().try_send(
            InterfoldEvent::<Unsequenced>::test_event("before-effects")
                .id(1)
                .seq(1)
                .build(),
        )?;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            receive_count.load(Ordering::SeqCst),
            0,
            "Event before EffectsEnabled should not be received"
        );

        // 2. Publish EffectsEnabled — triggers the subscription
        bus.publish_without_context(EffectsEnabled::new())?;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 3. Publish a TestEvent AFTER EffectsEnabled — should be received
        bus.event_bus().try_send(
            InterfoldEvent::<Unsequenced>::test_event("after-effects")
                .id(2)
                .seq(2)
                .build(),
        )?;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            receive_count.load(Ordering::SeqCst),
            1,
            "Event after EffectsEnabled should be received exactly once"
        );

        Ok(())
    }

    /// Verify that ungated (immediate) subscriptions receive events both
    /// before and after EffectsEnabled.
    ///
    /// This mirrors how Sortition subscribes to state-building events
    /// (CiphernodeAdded, E3Failed, etc.) immediately, while gating
    /// E3Requested behind EffectsEnabled. The immediate subscriptions
    /// must work during EventStore replay (before EffectsEnabled).
    #[actix::test]
    async fn immediate_subscriptions_receive_before_effects_enabled() -> anyhow::Result<()> {
        use std::sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        };

        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("test-immediate-sub");

        let immediate_count = Arc::new(AtomicU32::new(0));
        let gated_count = Arc::new(AtomicU32::new(0));

        // Helper actor that counts TestEvents
        use actix::{Actor, Context, Handler};

        struct Counter(Arc<AtomicU32>);
        impl Actor for Counter {
            type Context = Context<Self>;
        }
        impl Handler<InterfoldEvent> for Counter {
            type Result = ();
            fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
                if matches!(msg.get_data(), InterfoldEventData::TestEvent(_)) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }
        }

        // Immediate subscription — receives all events, including before EffectsEnabled
        let immediate_actor = Counter(immediate_count.clone()).start();
        bus.subscribe(EventType::TestEvent, immediate_actor.recipient());

        // Gated subscription — only receives after EffectsEnabled
        let gated_counter = gated_count.clone();
        let runner = e3_events::run_once::<EffectsEnabled>({
            let bus = bus.clone();
            move |_| {
                let addr = Counter(gated_counter).start();
                bus.subscribe(EventType::TestEvent, addr.recipient());
                Ok(())
            }
        });
        bus.subscribe(EventType::EffectsEnabled, runner.recipient());

        // 1. Publish event BEFORE EffectsEnabled
        bus.event_bus().try_send(
            InterfoldEvent::<Unsequenced>::test_event("during-replay")
                .id(1)
                .seq(1)
                .build(),
        )?;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            immediate_count.load(Ordering::SeqCst),
            1,
            "Immediate subscription should receive events before EffectsEnabled"
        );
        assert_eq!(
            gated_count.load(Ordering::SeqCst),
            0,
            "Gated subscription should NOT receive events before EffectsEnabled"
        );

        // 2. Publish EffectsEnabled
        bus.publish_without_context(EffectsEnabled::new())?;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 3. Publish event AFTER EffectsEnabled
        bus.event_bus().try_send(
            InterfoldEvent::<Unsequenced>::test_event("after-effects")
                .id(2)
                .seq(2)
                .build(),
        )?;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            immediate_count.load(Ordering::SeqCst),
            2,
            "Immediate subscription should receive events after EffectsEnabled too"
        );
        assert_eq!(
            gated_count.load(Ordering::SeqCst),
            1,
            "Gated subscription should receive events after EffectsEnabled"
        );

        Ok(())
    }
}
