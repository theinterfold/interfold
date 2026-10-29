// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::CommitteeFinalizerRepositoryFactory;
use e3_data::{DataStore, InMemStore, Repositories, SledStore};
use e3_event_system::test_support::EventFixture;
use e3_events::{
    EventConstructorWithTimestamp, EventContextAccessors, EventSource, FailureReason, Get,
    GetEvents, InsertSync, Seed, TicketId, Unsequenced, Unsubscribe,
};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

struct TimeRead {
    chain_id: u64,
    reply: oneshot::Sender<Result<u64>>,
}

fn chain_time() -> (CommitteeChainTimeReader, mpsc::UnboundedReceiver<TimeRead>) {
    let (requests, receiver) = mpsc::unbounded_channel();
    let reader: CommitteeChainTimeReader = Arc::new(move |chain_id| {
        let requests = requests.clone();
        Box::pin(async move {
            let (reply, response) = oneshot::channel();
            requests.send(TimeRead { chain_id, reply })?;
            response.await?
        })
    });
    (reader, receiver)
}

fn request() -> CommitteeRequested {
    CommitteeRequested {
        e3_id: E3id::new("2324", 2),
        seed: Seed([42; 32]),
        threshold: [1, 3],
        request_block: 42,
        committee_deadline: 1_100,
        ticket_price: alloy::primitives::U256::from(17),
        chain_id: 2,
    }
}

fn ticket(rank: Option<u64>) -> TicketGenerated {
    TicketGenerated {
        e3_id: request().e3_id,
        ticket_id: TicketId::Score(19),
        node: "0xabababababababababababababababababababab".to_owned(),
        party_index: rank,
    }
}

fn event(data: impl Into<InterfoldEventData>, seq: u64) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        data.into(),
        None,
        1_234,
        Some(42),
        EventSource::Evm,
    )
    .into_sequenced(seq)
}

fn repository() -> Repository<CommitteeFinalizerRecoveryState> {
    Repositories::from(DataStore::from_in_mem(&InMemStore::new(false).start()))
        .committee_finalizer_recovery()
}

async fn drain(bus: &BusHandle) -> Result<()> {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    bus.flush_event_pipeline().await
}

async fn advance(bus: &BusHandle, seconds: u64) -> Result<()> {
    tokio::time::advance(Duration::from_secs(seconds)).await;
    // Cross Tokio's millisecond timer-wheel boundary as well as the whole-second deadline.
    tokio::time::advance(Duration::from_millis(1)).await;
    drain(bus).await
}

async fn next_read(reads: &mut mpsc::UnboundedReceiver<TimeRead>) -> TimeRead {
    tokio::time::timeout(Duration::from_secs(5), reads.recv())
        .await
        .expect("finalizer did not read chain time")
        .expect("reader was dropped")
}

async fn publications(fixture: &EventFixture) -> Result<Vec<InterfoldEvent>> {
    drain(&fixture.bus).await?;
    Ok(fixture
        .history
        .send(GetEvents::new())
        .await?
        .into_iter()
        .filter(|event| {
            matches!(
                event.get_data(),
                InterfoldEventData::CommitteeFinalizeRequested(_)
            )
        })
        .collect())
}

#[actix::test]
async fn either_input_order_waits_for_effects_and_preserves_request_context() -> Result<()> {
    tokio::time::pause();
    for request_first in [true, false] {
        let fixture = EventFixture::new()?;
        let (reader, mut reads) = chain_time();
        let actor =
            CommitteeFinalizer::attach_with_recovery(&fixture.bus, repository(), reader).await?;
        let requested = event(request(), 7);
        let generated = event(ticket(Some(0)), 8);
        let inputs = if request_first {
            [requested.clone(), generated]
        } else {
            [generated, requested.clone()]
        };
        for input in inputs {
            actor.send(input).await?;
        }
        advance(&fixture.bus, 200).await?;
        assert!(
            reads.try_recv().is_err(),
            "replayed inputs started RPC before effects"
        );
        actor.send(EffectsEnabled::new()).await?;
        let read = next_read(&mut reads).await;
        assert_eq!(read.chain_id, 2);
        read.reply.send(Ok(1_000)).unwrap();
        drain(&fixture.bus).await?;
        advance(&fixture.bus, 100).await?;
        assert!(publications(&fixture).await?.is_empty());
        advance(&fixture.bus, 1).await?;
        let published = publications(&fixture).await?;
        assert_eq!(published.len(), 1);
        let context = published[0].get_ctx();
        assert_eq!(context.causation_id(), requested.get_ctx().id());
        assert_eq!(context.origin_id(), requested.get_ctx().origin_id());
        assert_eq!(context.block(), requested.get_ctx().block());
        assert_eq!(context.aggregate_id(), requested.get_ctx().aggregate_id());
        actor.send(Shutdown).await?;
    }
    Ok(())
}

#[actix::test]
async fn a_rank_is_required_and_duplicate_signals_do_not_start_parallel_attempts() -> Result<()> {
    tokio::time::pause();
    let fixture = EventFixture::new()?;
    let (reader, mut reads) = chain_time();
    let actor =
        CommitteeFinalizer::attach_with_recovery(&fixture.bus, repository(), reader).await?;
    actor.send(event(request(), 7)).await?;
    actor.send(event(ticket(None), 8)).await?;
    actor.send(EffectsEnabled::new()).await?;
    advance(&fixture.bus, 100).await?;
    assert!(reads.try_recv().is_err());
    actor.send(event(ticket(Some(1)), 9)).await?;
    let read = next_read(&mut reads).await;
    actor.send(EffectsEnabled::new()).await?;
    actor.send(event(ticket(Some(1)), 10)).await?;
    actor.send(event(request(), 11)).await?;
    drain(&fixture.bus).await?;
    assert!(reads.try_recv().is_err());
    read.reply.send(Ok(2_000)).unwrap();
    drain(&fixture.bus).await?;
    advance(&fixture.bus, 30).await?;
    assert!(publications(&fixture).await?.is_empty());
    advance(&fixture.bus, 1).await?;
    assert_eq!(publications(&fixture).await?.len(), 1);
    assert!(reads.try_recv().is_err());
    Ok(())
}

#[actix::test]
async fn rpc_retry_rereads_chain_time_without_restarting_the_submission_window() -> Result<()> {
    tokio::time::pause();
    let fixture = EventFixture::new()?;
    let (reader, mut reads) = chain_time();
    let actor =
        CommitteeFinalizer::attach_with_recovery(&fixture.bus, repository(), reader).await?;
    actor.send(event(request(), 7)).await?;
    actor.send(event(ticket(Some(2)), 8)).await?;
    actor.send(EffectsEnabled::new()).await?;
    next_read(&mut reads)
        .await
        .reply
        .send(Err(anyhow::anyhow!("RPC unavailable")))
        .unwrap();
    drain(&fixture.bus).await?;
    advance(&fixture.bus, 29).await?;
    assert!(reads.try_recv().is_err());
    advance(&fixture.bus, 1).await?;
    let retry = next_read(&mut reads).await;
    assert_eq!(retry.chain_id, 2);
    retry.reply.send(Ok(1_090)).unwrap();
    drain(&fixture.bus).await?;
    advance(&fixture.bus, 70).await?;
    assert!(publications(&fixture).await?.is_empty());
    advance(&fixture.bus, 1).await?;
    assert_eq!(publications(&fixture).await?.len(), 1);
    Ok(())
}

#[actix::test]
async fn a_rejected_publication_retries_the_time_read() -> Result<()> {
    tokio::time::pause();
    let fixture = EventFixture::new()?;
    let (reader, mut reads) = chain_time();
    let actor =
        CommitteeFinalizer::attach_with_recovery(&fixture.bus, repository(), reader).await?;
    actor.send(event(request(), 7)).await?;
    actor.send(event(ticket(Some(0)), 8)).await?;
    actor.send(EffectsEnabled::new()).await?;
    next_read(&mut reads).await.reply.send(Ok(2_000)).unwrap();
    drain(&fixture.bus).await?;
    // Close real bus admission without stopping this actor, so its publication returns an error.
    fixture
        .bus
        .event_bus()
        .send(Unsubscribe::new(
            EventType::Shutdown,
            actor.clone().recipient(),
        ))
        .await?;
    fixture.bus.publish_shutdown_and_wait().await?;
    advance(&fixture.bus, 1).await?;
    advance(&fixture.bus, 29).await?;
    assert!(reads.try_recv().is_err());
    advance(&fixture.bus, 1).await?;
    assert_eq!(next_read(&mut reads).await.chain_id, 2);
    assert!(publications(&fixture).await?.is_empty());
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Pending {
    Read,
    Retry,
    Timer,
}

fn cancellations() -> Vec<InterfoldEventData> {
    let id = request().e3_id;
    vec![
        CommitteeFinalized {
            e3_id: id.clone(),
            committee: vec![],
            scores: vec![],
            chain_id: 2,
        }
        .into(),
        E3Failed {
            e3_id: id.clone(),
            failed_at_stage: E3Stage::Requested,
            reason: FailureReason::CommitteeFormationTimeout,
        }
        .into(),
        E3StageChanged {
            e3_id: id.clone(),
            previous_stage: E3Stage::Requested,
            new_stage: E3Stage::Complete,
        }
        .into(),
        E3StageChanged {
            e3_id: id.clone(),
            previous_stage: E3Stage::Requested,
            new_stage: E3Stage::Failed,
        }
        .into(),
        E3RequestComplete { e3_id: id }.into(),
        Shutdown.into(),
    ]
}

#[actix::test]
async fn canonical_and_terminal_cleanup_cancel_every_pending_phase() -> Result<()> {
    tokio::time::pause();
    for phase in [Pending::Read, Pending::Retry, Pending::Timer] {
        for cancellation in cancellations() {
            let fixture = EventFixture::new()?;
            let repository = repository();
            let (reader, mut reads) = chain_time();
            let actor =
                CommitteeFinalizer::attach_with_recovery(&fixture.bus, repository.clone(), reader)
                    .await?;
            actor.send(event(request(), 7)).await?;
            actor.send(event(ticket(Some(3)), 8)).await?;
            actor.send(EffectsEnabled::new()).await?;
            let read = next_read(&mut reads).await;
            let pending_reply = match phase {
                Pending::Read => Some(read.reply),
                Pending::Retry => {
                    read.reply.send(Err(anyhow::anyhow!("RPC failed"))).unwrap();
                    None
                }
                Pending::Timer => {
                    read.reply.send(Ok(2_000)).unwrap();
                    None
                }
            };
            drain(&fixture.bus).await?;
            let shutdown = matches!(cancellation, InterfoldEventData::Shutdown(_));
            actor.send(event(cancellation, 9)).await?;
            if let Some(reply) = pending_reply {
                assert!(
                    reply.send(Ok(2_000)).is_err(),
                    "{phase:?}: cancelled RPC future survived"
                );
            }
            advance(&fixture.bus, 200).await?;
            assert!(
                reads.try_recv().is_err(),
                "{phase:?}: cancelled work retried"
            );
            assert!(
                publications(&fixture).await?.is_empty(),
                "{phase:?}: cancelled work published"
            );
            let recovered = repository.read().await?.unwrap();
            assert_eq!(recovered.pending_requests.len(), usize::from(shutdown));
            assert_eq!(recovered.tickets.len(), usize::from(shutdown));
        }
    }
    Ok(())
}

#[actix::test]
async fn restart_keeps_the_absolute_deadline_and_reapplies_the_saved_rank() -> Result<()> {
    tokio::time::pause();
    for (first_now, restart_now, wait) in [(1_000, 1_040, 151), (2_000, 2_040, 91)] {
        let fixture = EventFixture::new()?;
        let repository = repository();
        let (reader, mut reads) = chain_time();
        let actor = CommitteeFinalizer::attach_with_recovery(
            &fixture.bus,
            repository.clone(),
            reader.clone(),
        )
        .await?;
        actor.send(event(request(), 7)).await?;
        actor.send(event(ticket(Some(3)), 8)).await?;
        actor.send(EffectsEnabled::new()).await?;
        next_read(&mut reads)
            .await
            .reply
            .send(Ok(first_now))
            .unwrap();
        drain(&fixture.bus).await?;
        advance(&fixture.bus, 40).await?;
        actor.send(Shutdown).await?;
        let recovered = repository.read().await?.unwrap();
        assert_eq!(
            recovered.pending_requests[&request().e3_id]
                .request
                .committee_deadline,
            1_100
        );
        let resumed =
            CommitteeFinalizer::attach_with_recovery(&fixture.bus, repository, reader).await?;
        advance(&fixture.bus, 200).await?;
        assert!(
            reads.try_recv().is_err(),
            "hydration started RPC before effects"
        );
        resumed.send(EffectsEnabled::new()).await?;
        next_read(&mut reads)
            .await
            .reply
            .send(Ok(restart_now))
            .unwrap();
        drain(&fixture.bus).await?;
        advance(&fixture.bus, wait - 1).await?;
        assert!(publications(&fixture).await?.is_empty());
        advance(&fixture.bus, 1).await?;
        let published = publications(&fixture).await?;
        assert_eq!(published.len(), 1);
        assert_eq!(
            published[0].get_ctx().causation_id(),
            event(request(), 7).get_ctx().id()
        );
        resumed.send(Shutdown).await?;
    }
    Ok(())
}

#[actix::test]
async fn baseline_snapshot_reopens_at_the_original_disk_key_without_changing_bytes() -> Result<()> {
    // Generated from the unchanged recovery definitions at 26023af50, before relocation. One
    // request and ticket exercise real context, deadline, price and rank, not just empty maps.
    let baseline = alloy::hex::decode(include_str!("fixtures/recovery-v1.hex").trim())?;
    let directory = tempfile::tempdir()?;
    let fixture = EventFixture::new()?;
    let path = directory.path().to_path_buf();
    let store = DataStore::from_sled_store(&SledStore::new(&fixture.bus, &path)?);
    let key = "//committee_finalizer/recovery/v1";
    store
        .insert_sync_recipient()
        .send(InsertSync::new(key, baseline.clone()))
        .await??;
    store.shutdown().await?;
    let reopened = DataStore::from_sled_store(&SledStore::new(&fixture.bus, &path)?);
    let repository = Repositories::from(reopened.clone()).committee_finalizer_recovery();
    let recovered = repository
        .read()
        .await?
        .expect("relocation changed the repository key");
    let id = request().e3_id;
    assert_eq!(recovered.schema_version, 1);
    assert_eq!(recovered.pending_requests[&id].request, request());
    assert_eq!(
        &recovered.pending_requests[&id].context,
        event(request(), 7).get_ctx()
    );
    assert_eq!(recovered.tickets[&id], ticket(Some(3)));
    repository.write_sync(&recovered).await?;
    assert_eq!(
        reopened.get_recipient().send(Get::new(key)).await?.unwrap(),
        baseline
    );
    let (reader, mut reads) = chain_time();
    let actor = CommitteeFinalizer::attach_with_recovery(&fixture.bus, repository, reader).await?;
    actor.send(EffectsEnabled::new()).await?;
    assert_eq!(next_read(&mut reads).await.chain_id, 2);
    actor.send(Shutdown).await?;
    reopened.shutdown().await?;
    Ok(())
}

#[actix::test]
async fn production_replay_restores_ticket_suffix_and_applies_finalization_before_effects(
) -> Result<()> {
    use e3_event_system::EventSystem;
    use e3_events::{
        AggregateConfig, AggregateId, EvmEventConfig, EvmEventConfigChain, FlushPendingSnapshots,
        HistoricalEvmEventsReceived, HistoricalNetSyncEventsReceived, NetReady,
    };
    use e3_request::RequestRouterCheckpoint;
    use e3_sync::SyncRepositoryFactory;
    use std::collections::BTreeMap;

    tokio::time::pause();
    for finalized in [false, true] {
        let aggregate = AggregateId::new(2);
        let config = AggregateConfig::new(HashMap::from([(aggregate, Duration::ZERO)]));
        // Fixture creation must not seed the recovering bus's clock or dedup state.
        let source = EventSystem::in_mem()
            .with_fresh_bus()
            .with_aggregate_config(config.clone());
        let source_bus = source.handle()?.enable("finalizer-source");
        let history = source_bus.history();
        source_bus.publish_without_context(request())?;
        source_bus.publish_without_context(ticket(Some(1)))?;
        if finalized {
            source_bus.publish_without_context(CommitteeFinalized {
                e3_id: request().e3_id,
                committee: vec![],
                scores: vec![],
                chain_id: 2,
            })?;
        }
        source_bus.flush_event_pipeline().await?;
        let prefix = history.send(GetEvents::new()).await?;
        let requested = prefix
            .iter()
            .find(|event| matches!(event.get_data(), InterfoldEventData::CommitteeRequested(_)))
            .unwrap();
        let cursor = requested.get_ctx().seq();

        let destination = EventSystem::in_mem()
            .with_fresh_bus()
            .with_aggregate_config(config.clone());
        let bus = destination.handle()?.enable("finalizer-recovered");
        let history = bus.history();
        let repositories = Repositories::from(destination.store()?);
        repositories
            .schema_version()
            .write_sync(&e3_sync::SCHEMA_VERSION)
            .await?;
        repositories
            .aggregate_seq(aggregate)
            .write_sync(&cursor)
            .await?;
        e3_request::RouterRepositoryFactory::request_router_checkpoint(&repositories)
            .write_sync(&RequestRouterCheckpoint {
                contexts: vec![request().e3_id],
                replay_cursors: HashMap::from([(aggregate, cursor)]),
                ..Default::default()
            })
            .await?;
        repositories
            .committee_finalizer_recovery()
            .write_sync(&CommitteeFinalizerRecoveryState {
                pending_requests: HashMap::from([(
                    request().e3_id,
                    RecoveredCommitteeRequest {
                        request: request(),
                        context: requested.get_ctx().clone(),
                    },
                )]),
                ..Default::default()
            })
            .await?;
        let (reader, mut reads) = chain_time();
        let actor = CommitteeFinalizer::attach_with_recovery(
            &bus,
            repositories.committee_finalizer_recovery(),
            reader,
        )
        .await?;
        let evm = bus.wait_for(EventType::HistoricalEvmSyncStart);
        let net = bus.wait_for(EventType::HistoricalNetSyncStart);
        let evm_config =
            EvmEventConfig::from_config(BTreeMap::from([(2, EvmEventConfigChain::new(0))]));
        let source_reader = source.eventstore_reader()?.seq();
        tokio::try_join!(
            e3_sync::sync_with_net_ready(
                &bus,
                &evm_config,
                &repositories,
                &config,
                &source_reader,
                std::future::ready(Ok(event(NetReady::new(), 0))),
            ),
            async {
                let InterfoldEventData::HistoricalEvmSyncStart(start) = evm.await?.into_data()
                else {
                    unreachable!()
                };
                assert!(
                    reads.try_recv().is_err(),
                    "replay ran effects before current-boot readiness"
                );
                start
                    .sender
                    .unwrap()
                    .try_send(HistoricalEvmEventsReceived::new(vec![], 2))?;
                net.await?;
                bus.publish_without_context(HistoricalNetSyncEventsReceived::new(vec![]))?;
                Ok::<_, anyhow::Error>(())
            }
        )?;
        drain(&bus).await?;
        destination.buffer()?.send(FlushPendingSnapshots).await??;
        if finalized {
            assert!(
                reads.try_recv().is_err(),
                "canonical finalization was lost during replay"
            );
            assert!(repositories
                .committee_finalizer_recovery()
                .read()
                .await?
                .unwrap()
                .pending_requests
                .is_empty());
        } else {
            let read = next_read(&mut reads).await;
            assert_eq!(read.chain_id, 2);
            read.reply.send(Ok(2_000)).unwrap();
            drain(&bus).await?;
            advance(&bus, 31).await?;
            let published = history.send(GetEvents::new()).await?;
            let publication = published
                .iter()
                .find(|event| {
                    matches!(
                        event.get_data(),
                        InterfoldEventData::CommitteeFinalizeRequested(_)
                    )
                })
                .expect("replayed ticket did not resume finalization");
            assert_eq!(
                publication.get_ctx().causation_id(),
                requested.get_ctx().id()
            );
        }
        actor.send(Shutdown).await?;
    }
    Ok(())
}
