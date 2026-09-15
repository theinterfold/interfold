// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

#[cfg(test)]
use crate::domain::ReplayDecision;
use crate::domain::{
    decide_schema_version, CollectOutcome, HistoricalEvmCollector, SchemaVersionDecision,
    SnapshotMeta, SyncPlanner, SCHEMA_VERSION,
};
use crate::replay_spool::ReplaySpool;
use crate::SyncRepositoryFactory;
use actix::{Message, Recipient};
use anyhow::{bail, ensure, Context, Result};
use e3_data::Repositories;
use e3_events::{
    AccusationOutcome, AccusationQuorumReached, AggregateConfig, AggregateId, BusHandle,
    CommitteeMemberExcluded, CommitteeMemberExpelled, CommitteeRequested, CorrelationId,
    E3Requested, E3id, EffectsEnabled, Event, EventContext, EventPublisher, EventStoreQueryBy,
    EventStoreQueryResponse, EventSubscriber, EventType, EvmEventConfig,
    HistoricalEvmEventsReceived, HistoricalEvmSyncStart, HistoricalNetSyncStart, InterfoldEvent,
    InterfoldEventData, Seed, SeqAgg, Sequenced, SlashExecuted, StoreKeys, SyncEffect, SyncEnded,
    TicketGenerated, TypedEvent, Unsequenced,
};
#[cfg(test)]
use e3_events::{EventBusBarrier, EventBusFanout, EventContextAccessors};
use e3_utils::actix::channel as actix_toolbox;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    time::Duration,
};
use tokio::sync::mpsc::Receiver;
use tracing::info;

#[cfg(test)]
const REPLAY_PROGRESS_INTERVAL: usize = 10_000;

/// Advance the request-router checkpoint when it trails aggregate snapshots.
///
/// The projection changes only router admission state. It does not replay protocol actors, which
/// already hydrate from their aggregate snapshots.
pub async fn reconcile_request_router_checkpoint(
    repositories: &Repositories,
    aggregate_ids: impl IntoIterator<Item = AggregateId>,
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
) -> Result<()> {
    let mut target_cursors = std::collections::HashMap::new();
    for aggregate_id in aggregate_ids {
        let cursor = repositories
            .aggregate_seq(aggregate_id)
            .read()
            .await?
            .unwrap_or(0);
        target_cursors.insert(aggregate_id, cursor);
    }

    let checkpoint_store = repositories.request_router_checkpoint();
    let mut checkpoint = checkpoint_store
        .read()
        .await?
        .context("request-router checkpoint is missing after storage preflight")?;
    let needs_advance = target_cursors.iter().any(|(aggregate_id, target)| {
        checkpoint
            .replay_cursors
            .get(aggregate_id)
            .copied()
            .unwrap_or(0)
            < *target
    });
    if !needs_advance {
        return Ok(());
    }

    info!(
        checkpoint_cursors = ?checkpoint.replay_cursors,
        target_cursors = ?target_cursors,
        "Advancing the request-router checkpoint from EventStore"
    );
    let spool = ReplaySpool::load_between(
        eventstore,
        checkpoint.replay_cursors.clone(),
        target_cursors.clone(),
    )
    .await?;
    let projected = spool.project(|event| {
        e3_request::project_request_router_event(&mut checkpoint, event);
        Ok(())
    })?;
    for (aggregate_id, target) in &target_cursors {
        let cursor = checkpoint
            .replay_cursors
            .get(aggregate_id)
            .copied()
            .unwrap_or(0);
        ensure!(
            cursor >= *target,
            "request-router recovery stopped at sequence {} for aggregate {}, before required sequence {}",
            cursor,
            aggregate_id,
            target
        );
    }
    checkpoint_store.write_sync(&checkpoint).await?;
    info!(
        projected_events = projected,
        "Request-router checkpoint advanced"
    );
    Ok(())
}

#[derive(Clone, Debug)]
pub struct RecoveredCommitteeRequest {
    pub request: CommitteeRequested,
    pub context: EventContext<Sequenced>,
}

#[derive(Clone, Debug, Default)]
pub struct RestartStateBackfill {
    pub sortition_seeds: HashMap<E3id, Seed>,
    pub pending_sortition_requests: HashMap<E3id, TypedEvent<E3Requested>>,
    pub pending_expulsions: HashMap<E3id, Vec<(CommitteeMemberExpelled, EventContext<Sequenced>)>>,
    pub pending_exclusions: HashMap<E3id, Vec<(CommitteeMemberExcluded, EventContext<Sequenced>)>>,
    pub committee_requests: HashMap<E3id, RecoveredCommitteeRequest>,
    pub tickets: HashMap<E3id, TicketGenerated>,
    pub slash_intents: Vec<AccusationQuorumReached>,
}

impl RestartStateBackfill {
    fn complete_committee_formation(&mut self, e3_id: &E3id) {
        self.sortition_seeds.remove(e3_id);
        self.pending_sortition_requests.remove(e3_id);
        self.committee_requests.remove(e3_id);
        self.tickets.remove(e3_id);
    }

    fn remove(&mut self, e3_id: &E3id) {
        self.complete_committee_formation(e3_id);
        self.pending_expulsions.remove(e3_id);
        self.pending_exclusions.remove(e3_id);
    }

    fn acknowledge_expulsion(&mut self, data: &CommitteeMemberExpelled) {
        let Some(pending) = self.pending_expulsions.get_mut(&data.e3_id) else {
            return;
        };
        pending.retain(|(existing, _)| {
            existing.node != data.node
                || existing.reason != data.reason
                || existing.active_count_after != data.active_count_after
        });
        if pending.is_empty() {
            self.pending_expulsions.remove(&data.e3_id);
        }
    }

    fn acknowledge_exclusion(&mut self, data: &CommitteeMemberExcluded) {
        let Some(pending) = self.pending_exclusions.get_mut(&data.e3_id) else {
            return;
        };
        pending.retain(|(existing, _)| {
            existing.node != data.node || existing.proof_type != data.proof_type
        });
        if pending.is_empty() {
            self.pending_exclusions.remove(&data.e3_id);
        }
    }

    fn acknowledge_slash_exclusion(&mut self, data: &CommitteeMemberExcluded) {
        self.slash_intents.retain(|intent| {
            intent.e3_id != data.e3_id
                || intent.accused != data.node
                || intent.proof_type != data.proof_type
        });
    }

    fn acknowledge_slash_execution(&mut self, data: &SlashExecuted) {
        self.slash_intents.retain(|intent| {
            intent.e3_id != data.e3_id
                || intent.accused != data.operator
                || intent.proof_type.attestation_slash_reason().0 != data.reason
        });
    }
}

/// Recover restart-critical inputs from EventStore history.
///
/// Stores that predate the dedicated recovery repositories kept delayed sortition inputs,
/// pre-finalization membership changes, committee-finalization requests, generated ticket
/// retries, and pending slash submissions only in the event log. The ciphernode builder writes
/// this projection into missing recovery repositories before actors start.
pub async fn project_restart_state_backfill(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    end_cursors: HashMap<AggregateId, u64>,
    target_e3s: &HashSet<E3id>,
    slash_target_chains: &HashSet<u64>,
) -> Result<RestartStateBackfill> {
    if (target_e3s.is_empty() && slash_target_chains.is_empty()) || end_cursors.is_empty() {
        return Ok(RestartStateBackfill::default());
    }

    let spool = ReplaySpool::load_bounded(eventstore, end_cursors).await?;
    let mut recovered = RestartStateBackfill::default();
    spool.project(|event| {
        match event.get_data() {
            InterfoldEventData::AccusationQuorumReached(intent)
                if slash_target_chains.contains(&intent.e3_id.chain_id())
                    && intent.outcome == AccusationOutcome::AccusedFaulted =>
            {
                replace_slash_intent(&mut recovered.slash_intents, intent.clone());
            }
            InterfoldEventData::SlashExecuted(execution)
                if slash_target_chains.contains(&execution.e3_id.chain_id()) =>
            {
                recovered.acknowledge_slash_execution(execution);
            }
            InterfoldEventData::E3Requested(request) if target_e3s.contains(&request.e3_id) => {
                recovered.pending_sortition_requests.insert(
                    request.e3_id.clone(),
                    TypedEvent::new(request.clone(), event.get_ctx().clone()),
                );
            }
            InterfoldEventData::CommitteeRequested(request)
                if target_e3s.contains(&request.e3_id) =>
            {
                recovered
                    .sortition_seeds
                    .insert(request.e3_id.clone(), request.seed);
                recovered.committee_requests.insert(
                    request.e3_id.clone(),
                    RecoveredCommitteeRequest {
                        request: request.clone(),
                        context: event.get_ctx().clone(),
                    },
                );
            }
            InterfoldEventData::TicketGenerated(ticket)
                if target_e3s.contains(&ticket.e3_id) && ticket.party_index.is_some() =>
            {
                recovered
                    .tickets
                    .insert(ticket.e3_id.clone(), ticket.clone());
            }
            InterfoldEventData::CommitteeMemberExpelled(expulsion)
                if target_e3s.contains(&expulsion.e3_id) =>
            {
                if expulsion.party_id.is_some() {
                    recovered.acknowledge_expulsion(expulsion);
                } else {
                    let pending = recovered
                        .pending_expulsions
                        .entry(expulsion.e3_id.clone())
                        .or_default();
                    if !pending.iter().any(|(existing, _)| existing == expulsion) {
                        pending.push((expulsion.clone(), event.get_ctx().clone()));
                    }
                }
            }
            InterfoldEventData::CommitteeMemberExcluded(exclusion) => {
                if slash_target_chains.contains(&exclusion.e3_id.chain_id()) {
                    recovered.acknowledge_slash_exclusion(exclusion);
                }
                if target_e3s.contains(&exclusion.e3_id) && exclusion.party_id.is_some() {
                    recovered.acknowledge_exclusion(exclusion);
                } else if target_e3s.contains(&exclusion.e3_id) {
                    let pending = recovered
                        .pending_exclusions
                        .entry(exclusion.e3_id.clone())
                        .or_default();
                    if !pending.iter().any(|(existing, _)| existing == exclusion) {
                        pending.push((exclusion.clone(), event.get_ctx().clone()));
                    }
                }
            }
            InterfoldEventData::CommitteeFinalized(event) => {
                recovered.complete_committee_formation(&event.e3_id)
            }
            InterfoldEventData::E3Failed(event) => recovered.remove(&event.e3_id),
            InterfoldEventData::E3RequestComplete(event) => recovered.remove(&event.e3_id),
            InterfoldEventData::E3StageChanged(event)
                if matches!(
                    event.new_stage,
                    e3_events::E3Stage::Complete | e3_events::E3Stage::Failed
                ) =>
            {
                recovered.remove(&event.e3_id);
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(recovered)
}

fn replace_slash_intent(
    intents: &mut Vec<AccusationQuorumReached>,
    replacement: AccusationQuorumReached,
) {
    intents.retain(|intent| {
        intent.e3_id != replacement.e3_id
            || intent.accused != replacement.accused
            || intent.proof_type != replacement.proof_type
    });
    intents.push(replacement);
}

pub async fn sync(
    bus: &BusHandle,
    default_config: &EvmEventConfig,
    repositories: &Repositories,
    aggregate_config: &AggregateConfig,
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
) -> Result<()> {
    let net_ready = bus.wait_for(EventType::NetReady);
    sync_with_net_ready(
        bus,
        default_config,
        repositories,
        aggregate_config,
        eventstore,
        net_ready,
    )
    .await
}

/// Run startup sync with a network-readiness listener that is already armed.
///
/// Production creates this listener before it starts the network transport. This prevents an
/// immediate no-peer `NetReady` event from passing before sync begins to wait for it.
pub async fn sync_with_net_ready<F>(
    bus: &BusHandle,
    default_config: &EvmEventConfig,
    repositories: &Repositories,
    aggregate_config: &AggregateConfig,
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    net_ready: F,
) -> Result<()>
where
    F: Future<Output = Result<InterfoldEvent<Sequenced>>> + Send,
{
    // 0b. Verify the on-disk schema version is compatible with this binary
    //     before touching any persisted state, so an incompatible upgrade or
    //     downgrade halts loudly instead of silently loading garbage (H19/H20).
    preflight_schema_version(repositories, aggregate_config, eventstore).await?;

    // 1. Load snapsshot metadata
    info!("Loading snapshot metadata...");
    let snapshot =
        SnapshotMeta::read_from_disk(aggregate_config.aggregates(), default_config, repositories)
            .await?;
    info!(
        "Snapshot metadata loaded for {} aggregates.",
        snapshot.aggregates().len()
    );

    // 1b. Restore the HLC ordering floor from the highest persisted aggregate
    //     timestamp so events created after this restart remain strictly after
    //     durable history, including its logical counter, even if wall time moved backwards.
    if let Some(max_ts) = snapshot.to_net_config().values().copied().max() {
        bus.seed_clock(max_ts)?;
    }

    // 2. Determine the evm blocks to read from based on the SnapshotMeta
    let evm_config = snapshot.to_evm_config();
    let snapshot_net_config = snapshot.to_net_config();

    // 3. Page post-snapshot EventStore history into temporary per-aggregate runs. Replay preserves
    // each aggregate's durable sequence and uses HLC order to choose between aggregate heads,
    // without retaining the complete backlog in memory.
    info!("Loading EventStore replay pages...");
    let request_router_checkpoint = repositories
        .request_router_checkpoint()
        .read()
        .await?
        .context("request-router recovery checkpoint is missing after storage preflight")?;
    snapshot.ensure_request_router_covers(&request_router_checkpoint.replay_cursors)?;
    let replay_spool = ReplaySpool::load(eventstore, snapshot.to_sequence_map()).await?;
    info!("{} EventStore events spooled.", replay_spool.total_events());

    info!("Replaying events to actors...");
    // 4. Replay the EventStore events to all listeners (except effects).
    //    Skip lifecycle infrastructure events. SyncEnded, EffectsEnabled and sync-start events are
    //    re-published by this sync process; Shutdown belongs to the previous process and would stop
    //    freshly constructed actors. Replaying these here
    //    would poison the EventBus deduplication window: the replayed event has the same
    //    EventId (payload hash) as the one we publish later, causing the later event to be
    //    silently dropped.  This is critical for SyncEnded, if the EvmChainGateway never
    //    receives it, the gateway stays in BufferUntilLive and all live EVM events are lost.
    let replayed = replay_spool.replay(bus).await?;
    info!(replayed_events = replayed, "Events replayed.");

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
    // Note: this is *not* a global absence of restart recovery. Per-E3 actors restore versioned
    // recovery inputs and re-create collectors, proof jobs, compute jobs, and determined outputs
    // when `EffectsEnabled` is broadcast at the end of this sync. What sync deliberately avoids is
    // replaying request prefixes into actors that already hydrated from protocol snapshots.
    //
    // Detection of loose ends that cannot be locally re-driven is exposed offline and
    // non-destructively via `interfold node validate`, which cross-checks the persisted committee
    // slots against terminal events in the log and reports orphaned tickets. See
    // `crates/entrypoint/src/validate.rs`.

    // 5. Load the historical evm events to memory from all chains
    info!("Loading historical blockchain events...");
    let (addr, rx) = actix_toolbox::mpsc::<HistoricalEvmEventsReceived>(256);
    bus.publish_without_context(HistoricalEvmSyncStart::new(addr, evm_config.clone()))?;
    let historical_evm_events = collect_historical_evm_events(rx, &evm_config).await?;
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

    // 8-10. Enable effects, publish canonical history, then enter live mode. Each phase is fenced
    // through durable storage and EventBus fanout so aggregate-specific EventStore response order
    // cannot move history ahead of EffectsEnabled or SyncEnded ahead of history.
    publish_reconciled_history(bus, historical).await?;
    // normal live operations

    Ok(())
}

async fn publish_reconciled_history(
    bus: &BusHandle,
    historical: Vec<InterfoldEvent<Unsequenced>>,
) -> Result<()> {
    info!("Enabling effects...");
    bus.publish_without_context(EffectsEnabled::new())?;
    bus.flush_event_pipeline().await?;
    info!("Effects enabled.");

    // Effects subscribers are now attached. Resume derived local work before canonical history is
    // released so per-E3 actors observe the same order as an uninterrupted process.
    bus.publish_without_context(SyncEffect::new())?;
    bus.flush_event_pipeline().await?;

    info!("Publishing historical events to actors...");
    for event in historical {
        bus.naked_dispatch_async(event).await?;
    }
    bus.flush_event_pipeline().await?;
    info!("Historical events published.");

    info!("Publishing SyncEnded event...");
    bus.publish_without_context(SyncEnded::new())?;
    bus.flush_event_pipeline().await?;
    info!("Sync finished.");
    Ok(())
}

#[cfg(test)]
async fn replay_eventstore_events(
    bus: &BusHandle,
    mut events: Vec<InterfoldEvent>,
) -> Result<usize> {
    let total_events = events.len();
    let mut replayed = 0usize;

    // Snapshot metadata can lag the append-only log after a failed snapshot write. Seed from the
    // actual replay set before any subscriber can emit follow-up work, otherwise new local events
    // may receive timestamps behind durable post-snapshot history.
    if let Some(max_ts) = events.iter().map(EventContextAccessors::ts).max() {
        bus.seed_clock(max_ts)?;
    }

    // This test helper receives fixtures whose per-aggregate sequences are already monotonic. Sort
    // those ready aggregate events by HLC before stateful subscribers observe cross-aggregate
    // dependencies. Production uses ReplaySpool to enforce the sequence precondition.
    events.sort_by_key(|event| event.ts());

    for event in events {
        if SyncPlanner::classify_replay(&event) == ReplayDecision::SkipInfrastructure {
            continue;
        }
        // Await EventBus handling before submitting the next event. `try_send` lets this producer
        // outrun the bounded mailbox and aborts startup when it fills; the awaited Actix request
        // preserves replay order, yields between events, and reports a closed mailbox.
        bus.event_bus().send(EventBusFanout(event)).await??;
        replayed += 1;

        if replayed.is_multiple_of(REPLAY_PROGRESS_INTERVAL) {
            info!(
                replayed_events = replayed,
                total_events, "EventStore replay progress"
            );
        }
    }
    // The EventBus acknowledges its own handler before an awaited subscriber fanout finishes.
    // A fence queued after the final replay event therefore proves the last downstream handler
    // has completed before startup advances to canonical-chain reconciliation.
    bus.event_bus().send(EventBusBarrier).await?;
    Ok(replayed)
}

#[path = "history.rs"]
mod historical;
mod preflight;

pub use historical::collect_historical_evm_events;
pub use preflight::{has_schema_governed_kv_state, preflight_schema_version};

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
#[path = "tests/mod.rs"]
mod tests;
