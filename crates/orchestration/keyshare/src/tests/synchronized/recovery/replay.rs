// SPDX-License-Identifier: LGPL-3.0-only

//! Disk log -> production startup sync -> manually hydrated keyshare. Historical EVM/network
//! adapters return empty history; disabled production profile admission is not bypassed outside
//! this private fixture, and no whole-node or hard-crash guarantee is implied.

use super::*;
use e3_data::{CommitLogEventLog, SledSequenceIndex};
use e3_event_system::{EventStoreAddrs, EventSystem};
use e3_events::{
    hlc::Hlc, AggregateConfig, AggregateId, EventBusBarrier, EventContextAccessors, EventLog,
    EventPublisher, EventStore, EventSubscriber, EvmEventConfig, EvmEventConfigChain,
    HistoricalEvmEventsReceived, HistoricalNetSyncEventsReceived, NetReady, Shutdown, SyncEnded,
};
use e3_request::RequestRouterCheckpoint;
use e3_sync::SyncRepositoryFactory;
use std::{collections::HashMap, time::Duration};

impl Handler<StopForReopen> for EventStore<SledSequenceIndex, CommitLogEventLog> {
    type Result = Result<()>;
    fn handle(&mut self, _: StopForReopen, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

#[derive(Message)]
#[rtype(result = "bool")]
struct EffectsAreEnabled;

impl Handler<EffectsAreEnabled> for ThresholdKeyshare {
    type Result = bool;
    fn handle(&mut self, _: EffectsAreEnabled, _: &mut Self::Context) -> Self::Result {
        self.effects_enabled
    }
}

fn logged(
    data: impl Into<InterfoldEventData>,
    timestamp: u128,
    source: EventSource,
) -> InterfoldEvent<Unsequenced> {
    InterfoldEvent::new_with_timestamp(data.into(), None, timestamp, None, source)
}

#[actix::test]
async fn synchronized_disk_log_replay_preserves_authenticated_work_until_fresh_effects(
) -> Result<()> {
    let _exclusive = DISK_RECOVERY.lock().await;
    let mut ciphers = Vec::new();
    for owner in 0..3 {
        ciphers.push(cipher(owner).await?);
    }
    let mut setup = Setup::with_ciphers(ciphers).await?;
    let artifacts = artifacts(&mut setup, None).await?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("node");
    let logs = directory.path().join("journal");
    let owner = 1; // Outside non-prefix H=[0,2], so neither incoming share is an own row.
    let e3 = &setup.selected[owner].e3_id;
    let chain = AggregateId::from_chain_id(Some(e3.chain_id()));
    let local = AggregateId::new(0);
    let prefix = logged(setup.pending[owner].clone(), 900, EventSource::Local).into_sequenced(1);
    let checkpoint = Node::open(&path, owner, &setup, Some(&artifacts)).await?;
    // Tie the manually hydrated work to the actual journal prefix, not the mailbox fixture's EC.
    let mut root = checkpoint.root(e3).await?;
    let pending = TypedEvent::new(setup.pending[owner].clone(), prefix.get_ctx().clone());
    root.threshold_share_pending_ref = Some(
        ThresholdKeyshareRecoveryPayloads::new(
            checkpoint
                .repositories
                .threshold_keyshare_recovery_payloads(e3),
        )
        .write_pending(&pending, pending.get_ctx())?,
    );
    root.last_ec = Some(prefix.get_ctx().clone());
    checkpoint
        .repositories
        .threshold_keyshare_recovery(e3)
        .write_sync(&root)
        .await?;
    checkpoint
        .repositories
        .schema_version()
        .write_sync(&e3_sync::SCHEMA_VERSION)
        .await?;
    checkpoint
        .repositories
        .aggregate_seq(chain)
        .write_sync(&1)
        .await?;
    checkpoint
        .repositories
        .aggregate_ts(chain)
        .write_sync(&900)
        .await?;
    e3_request::RouterRepositoryFactory::request_router_checkpoint(&checkpoint.repositories)
        .write_sync(&RequestRouterCheckpoint {
            contexts: vec![e3.clone()],
            replay_cursors: HashMap::from([(chain, 1), (local, 0)]),
            ..Default::default()
        })
        .await?;
    checkpoint.stop().await?;
    SledDb::close_all_connections();

    let mut forged = artifacts.messages[&(0, owner)].clone();
    forged.signature = Default::default();
    let tail = [
        logged(forged, 800, EventSource::Net),
        logged(
            artifacts.messages[&(0, owner)].clone(),
            700,
            EventSource::Net,
        ),
        logged(
            artifacts.messages[&(0, owner)].clone(),
            600,
            EventSource::Net,
        ),
        logged(
            artifacts.messages[&(2, owner)].clone(),
            500,
            EventSource::Net,
        ),
    ];
    // Use the real durable adapter, then drop it before startup reopens/reconciles its index.
    // The decreasing remote HLC must not reorder this aggregate's physical sequence.
    {
        let log_path = e3_event_system::enumerate_path(&logs, chain.to_usize());
        let mut log = CommitLogEventLog::new(&log_path)?;
        ensure!(log.append(&prefix.clone_unsequenced())? == 1);
        for event in &tail {
            log.append(event)?;
        }
        log.flush()?;
    }
    let stale = [
        logged(EffectsEnabled::new(), 1_000, EventSource::Local),
        logged(SyncEnded::new(), 1_001, EventSource::Local),
        logged(Shutdown, 1_002, EventSource::Local),
    ];
    {
        let mut log = CommitLogEventLog::new(&e3_event_system::enumerate_path(&logs, 0))?;
        for event in &stale {
            log.append(event)?;
        }
        log.flush()?;
    }
    let aggregate_config = AggregateConfig::new(HashMap::from([
        (local, Duration::ZERO),
        (chain, Duration::ZERO),
    ]));
    let system = EventSystem::persisted(logs, path.clone())
        .with_fresh_bus()
        .with_aggregate_config(aggregate_config.clone());
    let failure = system.failure_receiver();
    let store = system.store()?;
    let bus = system
        .enable_handle_with_hlc(Hlc::new(7).with_clock(|| 1))
        .await?;
    let history = bus.history();
    let node = Node::restore(store.clone(), bus.clone(), history.clone(), owner, &setup).await?;
    bus.subscribe(EventType::All, node.actor.clone().recipient());
    bus.event_bus().send(EventBusBarrier).await?;
    let evm_start = bus.wait_for(EventType::HistoricalEvmSyncStart);
    let net_start = bus.wait_for(EventType::HistoricalNetSyncStart);
    let sync_bus = bus.clone();
    let repositories = store.repositories();
    let reader = system.eventstore_reader()?.seq();
    let evm_config = EvmEventConfig::from_config(BTreeMap::from([(
        e3.chain_id(),
        EvmEventConfigChain::new(0),
    )]));
    let syncing = actix::spawn(async move {
        e3_sync::sync_with_net_ready(
            &sync_bus,
            &evm_config,
            &repositories,
            &aggregate_config,
            &reader,
            async { Ok(logged(NetReady::new(), 0, EventSource::Local).into_sequenced(1)) },
        )
        .await
    });
    let evm = actix::clock::timeout(Duration::from_secs(10), evm_start).await??;
    node.actor.send(AssertReplayQuiescent).await??;
    bus.flush_event_pipeline().await?;
    // Log flush is not a snapshot drain. Assert persistence only after the acknowledged drain.
    system
        .buffer()?
        .send(e3_events::FlushPendingSnapshots)
        .await??;
    let root = node.root(e3).await?;
    ensure!(
        failure.borrow().is_none(),
        "event system failed: {:?}",
        *failure.borrow()
    );
    ensure!(root.threshold_share_refs.len() == 2);
    let last = root.last_ec.as_ref().context("replay lost its context")?;
    ensure!(last.aggregate_id() == chain && last.seq() == 5);
    let payloads = ThresholdKeyshareRecoveryPayloads::load(
        node.repositories.threshold_keyshare_recovery_payloads(e3),
        &root,
    )
    .await?;
    let saved_pending = payloads.pending().context("replay lost checkpoint work")?;
    ensure!(saved_pending.get_ctx() == prefix.get_ctx());
    ensure!(bincode::serialize(&**saved_pending)? == bincode::serialize(&setup.pending[owner])?);
    for dealer in [0, 2] {
        let saved = payloads
            .share(dealer)
            .context("replay lost authenticated share")?;
        ensure!(
            bincode::serialize(&**saved)?
                == bincode::serialize(&artifacts.messages[&(dealer as usize, owner)])?
        );
    }
    ensure!(root.synchronized == Some(setup.material[owner].clone()));
    ensure!(!node.actor.send(EffectsAreEnabled).await?);
    let replayed = history.send(GetEvents::new()).await?;
    let replayed_shares: Vec<_> = replayed
        .iter()
        .filter(|event| {
            matches!(
                event.get_data(),
                InterfoldEventData::ThresholdShareCreated(_)
            )
        })
        .collect();
    // Forgery cannot reserve dealer 0's slot; its valid replacement precedes dealer 2 by durable
    // sequence even though HLC decreases. The identical dealer-0 redelivery is deduplicated.
    ensure!(
        replayed_shares
            .iter()
            .map(|event| (event.seq(), event.ts()))
            .collect::<Vec<_>>()
            == [(2, 800), (3, 700), (5, 500)]
    );
    // Startup replay includes the checkpoint's boundary event. It must only re-observe the saved
    // work, not generate another randomized plan while effects are disabled.
    let pending_events: Vec<_> = replayed
        .iter()
        .filter(|event| {
            matches!(
                event.get_data(),
                InterfoldEventData::ThresholdSharePending(_)
            )
        })
        .collect();
    ensure!(pending_events.len() == 1 && pending_events[0].get_ctx() == prefix.get_ctx());
    ensure!(replayed.iter().all(|event| !matches!(
        event.get_data(),
        InterfoldEventData::EffectsEnabled(_)
            | InterfoldEventData::SyncEnded(_)
            | InterfoldEventData::Shutdown(_)
            | InterfoldEventData::ComputeRequest(_)
            | InterfoldEventData::DecryptionShareProofsPending(_)
    )));
    let InterfoldEventData::HistoricalEvmSyncStart(evm) = evm.into_data() else {
        anyhow::bail!("startup skipped the replay/history fence");
    };
    evm.sender
        .context("missing EVM history response channel")?
        .send(HistoricalEvmEventsReceived::new(vec![], e3.chain_id()))
        .await?;
    actix::clock::timeout(Duration::from_secs(10), net_start).await??;
    node.actor.send(AssertReplayQuiescent).await??;
    bus.publish_without_context(HistoricalNetSyncEventsReceived::new(vec![]))?;
    actix::clock::timeout(Duration::from_secs(10), syncing).await???;
    ensure!(node.actor.send(EffectsAreEnabled).await?);
    let history = history.send(GetEvents::new()).await?;
    for kind in [EventType::EffectsEnabled, EventType::SyncEnded] {
        let events: Vec<_> = history
            .iter()
            .filter(|event| event.event_type() == kind.to_string())
            .collect();
        ensure!(events.len() == 1 && events[0].ts() > 1_002);
    }
    node.actor.send(StopForReopen).await??;
    bus.publish_shutdown_and_wait().await?;
    bus.flush_event_pipeline().await?;
    if let EventStoreAddrs::Persisted(stores) = system.eventstore_addrs()? {
        for actor in stores.values() {
            actor.send(StopForReopen).await??;
        }
    }
    store.shutdown().await?;
    ensure!(
        failure.borrow().is_none(),
        "event system failed: {:?}",
        *failure.borrow()
    );
    drop(node);
    drop(system);
    SledDb::close_all_connections();
    let reopened = Node::open(&path, owner, &setup, None).await?;
    let root = reopened.root(e3).await?;
    ensure!(root.threshold_share_refs.len() == 2);
    ensure!(root.synchronized == Some(setup.material[owner].clone()));
    reopened.stop().await?;
    SledDb::close_all_connections();
    ensure!(!PROFILE.admission_enabled());
    Ok(())
}
