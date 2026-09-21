// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use super::{
    batch_router::{BatchRouter, FlushSeq},
    timelock_queue::{Clock, StartTimelock, SystemClock, Tick, TimelockQueue},
    AggregateConfig, FlushPendingSnapshots,
};
use crate::{Insert, InsertBatch, InterfoldEvent};
use actix::{Actor, Addr, Handler, Message, Recipient, ResponseFuture};
use anyhow::{Context, Result};
use e3_utils::MAILBOX_LIMIT;
use std::sync::Arc;
use tracing::{info, trace};

#[derive(Message)]
#[rtype(result = "()")]
struct SetDependencies {
    router: Addr<BatchRouter>,
    timelock: Addr<TimelockQueue>,
}

impl SetDependencies {
    pub fn new(router: Addr<BatchRouter>, timelock: Addr<TimelockQueue>) -> Self {
        Self { router, timelock }
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Start;

#[derive(Message)]
#[rtype(result = "()")]
pub struct UpdateDestination(pub Recipient<InsertBatch>);
impl UpdateDestination {
    pub fn new(base: impl Into<Recipient<InsertBatch>>) -> Self {
        Self(base.into())
    }
}

pub struct SnapshotBuffer {
    router: Option<Addr<BatchRouter>>,
    timelock: Option<Recipient<StartTimelock>>,
    tickable: Option<Recipient<Tick>>,
}

impl Default for SnapshotBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotBuffer {
    pub fn new() -> Self {
        SnapshotBuffer {
            router: None,
            timelock: None,
            tickable: None,
        }
    }

    pub fn spawn(
        config: &AggregateConfig,
        store: impl Into<Recipient<InsertBatch>>,
    ) -> Result<Addr<Self>> {
        info!("spawning SnapshotBuffer...");
        let (addr, _) = Self::with_clock(config, store, Arc::new(SystemClock), Some(1))?;
        Ok(addr)
    }

    pub fn with_clock(
        config: &AggregateConfig,
        store: impl Into<Recipient<InsertBatch>>,
        clock: Arc<dyn Clock>,
        interval: Option<u64>,
    ) -> Result<(Addr<Self>, Addr<TimelockQueue>)> {
        let addr = Self::new().start();
        let store = store.into();
        let router =
            BatchRouter::with_clock(config, addr.clone(), store.clone(), clock.clone()).start();
        let timelock = TimelockQueue::with_clock(addr.clone(), clock, interval).start();
        addr.try_send(SetDependencies::new(router, timelock.clone()))?;
        Ok((addr, timelock))
    }
}

impl Actor for SnapshotBuffer {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<FlushSeq> for SnapshotBuffer {
    type Result = ();
    fn handle(&mut self, msg: FlushSeq, _: &mut Self::Context) -> Self::Result {
        if let Some(ref router) = self.router {
            router.do_send(msg);
        }
    }
}

impl Handler<StartTimelock> for SnapshotBuffer {
    type Result = ();
    fn handle(&mut self, msg: StartTimelock, _: &mut Self::Context) -> Self::Result {
        if let Some(ref timelock) = self.timelock {
            timelock.do_send(msg);
        }
    }
}

impl Handler<SetDependencies> for SnapshotBuffer {
    type Result = ();
    fn handle(&mut self, msg: SetDependencies, _: &mut Self::Context) -> Self::Result {
        let SetDependencies { timelock, router } = msg;
        self.timelock = Some(timelock.clone().into());
        self.tickable = Some(timelock.into());
        self.router = Some(router);
    }
}

impl Handler<Insert> for SnapshotBuffer {
    type Result = ();
    fn handle(&mut self, msg: Insert, _: &mut Self::Context) -> Self::Result {
        if let Some(ref router) = self.router {
            trace!("Forwarding Insert message to batch router...");
            router.do_send(msg);
        }
    }
}

impl Handler<InterfoldEvent> for SnapshotBuffer {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, _ctx: &mut Self::Context) -> Self::Result {
        if let Some(ref router) = self.router {
            router.do_send(msg);
        }
    }
}

impl Handler<FlushPendingSnapshots> for SnapshotBuffer {
    type Result = ResponseFuture<Result<()>>;

    fn handle(&mut self, _: FlushPendingSnapshots, _: &mut Self::Context) -> Self::Result {
        let router = self.router.clone();
        Box::pin(async move {
            let router = router.context("snapshot buffer has no batch router")?;
            router
                .send(FlushPendingSnapshots)
                .await
                .context("snapshot batch router stopped during final flush")??;
            Ok(())
        })
    }
}

impl Handler<Tick> for SnapshotBuffer {
    type Result = ();
    fn handle(&mut self, msg: Tick, _: &mut Self::Context) -> Self::Result {
        if let Some(ref tickable) = self.tickable {
            tickable.do_send(msg);
        }
    }
}

impl Handler<UpdateDestination> for SnapshotBuffer {
    type Result = ();
    fn handle(&mut self, msg: UpdateDestination, _: &mut Self::Context) -> Self::Result {
        if let Some(ref router) = self.router {
            router.do_send(msg);
        }
    }
}

#[cfg(test)]
mod mock_store {
    use crate::InsertBatch;
    use actix::{Actor, Handler, Message};

    #[derive(Message)]
    #[rtype(result = "Vec<InsertBatch>")]
    pub struct GetEvts;

    #[derive(Default)]
    pub struct MockStore {
        evts: Vec<InsertBatch>,
    }

    impl Actor for MockStore {
        type Context = actix::Context<Self>;
    }

    impl Handler<InsertBatch> for MockStore {
        type Result = anyhow::Result<()>;

        fn handle(&mut self, msg: InsertBatch, _: &mut Self::Context) -> Self::Result {
            if !msg.commands().is_empty() {
                self.evts.push(msg);
            }
            Ok(())
        }
    }

    impl Handler<GetEvts> for MockStore {
        type Result = Vec<InsertBatch>;
        fn handle(&mut self, _: GetEvts, _: &mut Self::Context) -> Self::Result {
            std::mem::take(&mut self.evts)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::timelock_queue::mock_clock::MockClock;
    use super::mock_store::GetEvts;
    use super::{mock_store, FlushPendingSnapshots, SnapshotBuffer};
    use crate::snapshot_buffer::timelock_queue::Tick;
    use crate::{
        AggregateConfig, AggregateId, E3id, EventContext, EventContextAccessors, EventContextSeq,
        EventId, EventSource, Insert, InsertBatch, InterfoldEvent, Sequenced, Shutdown, SyncEnded,
        TestEvent,
    };
    use actix::{Actor, Handler, ResponseFuture};
    use anyhow::{Context, Result};
    use e3_test_helpers::with_tracing;
    use std::collections::{HashMap, HashSet};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tracing::info;

    struct GatedStore {
        entered: Option<oneshot::Sender<()>>,
        release: Option<oneshot::Receiver<()>>,
        write_completed: Arc<AtomicBool>,
    }

    impl Actor for GatedStore {
        type Context = actix::Context<Self>;
    }

    impl Handler<InsertBatch> for GatedStore {
        type Result = ResponseFuture<Result<()>>;

        fn handle(&mut self, msg: InsertBatch, _: &mut Self::Context) -> Self::Result {
            if msg.commands().is_empty() {
                return Box::pin(async { Ok(()) });
            }

            let entered = self.entered.take();
            let release = self.release.take();
            let write_completed = self.write_completed.clone();
            Box::pin(async move {
                entered
                    .context("gated store received more than one data batch")?
                    .send(())
                    .map_err(|_| anyhow::anyhow!("flush test stopped before the write began"))?;
                release
                    .context("gated store received more than one data batch")?
                    .await
                    .context("flush test dropped the destination write gate")?;
                write_completed.store(true, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    fn create_ec(ag: usize, seq: u64) -> EventContext<Sequenced> {
        EventContext::new_origin(
            EventId::hash(1),
            1000,
            AggregateId::new(ag),
            None,
            EventSource::Local,
        )
        .sequence(seq)
    }

    fn create_event(ec: &EventContext<Sequenced>) -> InterfoldEvent {
        InterfoldEvent::<Sequenced>::from_data_ec(
            TestEvent::new("hello", ec.seq())
                .with_e3_id(E3id::new("1", *ec.aggregate_id() as u64))
                .into(),
            ec.clone(),
        )
    }

    #[actix::test]
    async fn test_snapshot_buffer() -> Result<()> {
        let _guard = with_tracing("debug");
        let mut delays = HashMap::new();
        delays.insert(AggregateId::new(0), Duration::from_micros(0));
        delays.insert(AggregateId::new(23), Duration::from_micros(30));
        delays.insert(AggregateId::new(1), Duration::from_micros(60));

        let config = &AggregateConfig::new(delays);
        let store = mock_store::MockStore::default().start();

        let clock = Arc::new(MockClock::new(1000));
        let (buffer, timelock) =
            SnapshotBuffer::with_clock(config, store.clone(), clock.clone(), None)?;

        let ec = create_ec(23, 1);
        let aggregate_23_first = create_event(&ec);

        let aggregate_23_inserts = [
            Insert::new_with_context("one", b"one".to_vec(), ec.clone()),
            Insert::new_with_context("two", b"two".to_vec(), ec.clone()),
        ];

        let ec = create_ec(1, 1);
        let aggregate_1_first = create_event(&ec);

        let aggregate_1_inserts = [
            Insert::new_with_context("one", b"one".to_vec(), ec.clone()),
            Insert::new_with_context("two", b"two".to_vec(), ec.clone()),
        ];

        buffer.send(aggregate_23_first).await?;
        buffer.send(aggregate_23_inserts[0].clone()).await?;
        // The next sequence for the same aggregate starts its predecessor's timelock.
        buffer.send(create_event(&create_ec(23, 2))).await?;
        // State written during the grace period still belongs to aggregate 23, sequence 1.
        buffer.send(aggregate_23_inserts[1].clone()).await?;

        buffer.send(aggregate_1_first).await?;
        buffer.send(aggregate_1_inserts[0].clone()).await?;
        buffer.send(aggregate_1_inserts[1].clone()).await?;
        buffer.send(create_event(&create_ec(1, 2))).await?;

        // Nothing happens as there has not been enough delay
        info!("Clock=1020 : Checking for events but there should be nothing that has flushed...");
        clock.set(Duration::from_micros(1020));
        timelock.send(Tick).await?;
        let batches = store.send(GetEvts).await?;
        assert_eq!(0, batches.len());

        // Time is up so lets flush aggregate 23 (but not aggregate 1)
        info!("Clock=1030 : aggregate 23 sequence 1 should flush...");
        clock.set(Duration::from_micros(1030));
        timelock.send(Tick).await?;
        let batches = store.send(GetEvts).await?;
        assert_eq!(1, batches.len());
        let InsertBatch(inserts) = batches.first().unwrap();
        assert_eq!(5, inserts.len()); // Have 5 inserts as sequence,block and ts get written

        // Not ready yet
        info!("Clock=1050 : Not ready yet...");
        clock.set(Duration::from_micros(1050));
        timelock.send(Tick).await?;
        let batches = store.send(GetEvts).await?;
        assert_eq!(0, batches.len());

        // Time is up so lets flush aggregate 1
        info!("Clock=1060 : aggregate 1 sequence 1 should flush...");
        clock.set(Duration::from_micros(1060));
        timelock.send(Tick).await?;
        let batches = store.send(GetEvts).await?;
        assert_eq!(1, batches.len());
        let InsertBatch(inserts) = batches.first().unwrap();
        assert_eq!(5, inserts.len()); // Have 5 inserts as sequence,block and ts get written

        Ok(())
    }

    #[actix::test]
    async fn cross_aggregate_batches_flush_in_event_order() -> Result<()> {
        let config = &AggregateConfig::new(HashMap::from([
            (AggregateId::new(1), Duration::from_secs(60)),
            (AggregateId::new(2), Duration::from_secs(60)),
        ]));
        let store = mock_store::MockStore::default().start();
        let clock = Arc::new(MockClock::new(1000));
        let (buffer, _) = SnapshotBuffer::with_clock(config, store.clone(), clock.clone(), None)?;

        let first = create_ec(1, 1);
        let second = create_ec(2, 1);
        buffer.send(create_event(&first)).await?;
        buffer.send(create_event(&second)).await?;
        buffer
            .send(Insert::new_with_context("aggregate-one", vec![1], first))
            .await?;
        buffer
            .send(Insert::new_with_context("aggregate-two", vec![2], second))
            .await?;
        buffer
            .send(Insert::new_with_context(
                "shared-state",
                vec![1],
                create_ec(1, 1),
            ))
            .await?;
        buffer
            .send(Insert::new_with_context(
                "shared-state",
                vec![2],
                create_ec(2, 1),
            ))
            .await?;

        buffer.send(FlushPendingSnapshots).await??;

        let batches = store.send(GetEvts).await?;
        assert_eq!(batches.len(), 2);
        let aggregate_ids = batches
            .iter()
            .flat_map(|batch| batch.commands())
            .filter_map(Insert::ctx)
            .map(EventContextAccessors::aggregate_id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            aggregate_ids,
            HashSet::from([AggregateId::new(1), AggregateId::new(2)])
        );
        let shared_values = batches
            .iter()
            .flat_map(|batch| batch.commands())
            .filter(|insert| insert.key().as_slice() == b"shared-state")
            .map(|insert| insert.value().clone())
            .collect::<Vec<_>>();
        assert_eq!(shared_values, vec![vec![1], vec![2]]);
        Ok(())
    }

    #[actix::test]
    async fn a_sequence_gap_still_schedules_every_older_snapshot() -> Result<()> {
        let aggregate_id = AggregateId::new(7);
        let config =
            &AggregateConfig::new(HashMap::from([(aggregate_id, Duration::from_micros(10))]));
        let store = mock_store::MockStore::default().start();
        let clock = Arc::new(MockClock::new(1000));
        let (buffer, timelock) =
            SnapshotBuffer::with_clock(config, store.clone(), clock.clone(), None)?;

        let first = create_ec(7, 1);
        buffer.send(create_event(&first)).await?;
        buffer
            .send(Insert::new_with_context("state", vec![1], first))
            .await?;

        // Sequence 2 is intentionally absent. Sequence 3 must still close sequence 1.
        buffer.send(create_event(&create_ec(7, 3))).await?;
        clock.set(Duration::from_micros(1010));
        timelock.send(Tick).await?;

        let batches = store.send(GetEvts).await?;
        assert_eq!(batches.len(), 1);
        assert_eq!(
            batches[0]
                .snapshot_revision()?
                .context("flushed snapshot has no revision")?
                .seq(),
            1
        );
        Ok(())
    }

    #[actix::test]
    async fn final_flush_waits_for_destination_acknowledgement() -> Result<()> {
        let config = &AggregateConfig::new(HashMap::from([(
            AggregateId::new(1),
            Duration::from_secs(60),
        )]));
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let write_completed = Arc::new(AtomicBool::new(false));
        let store = GatedStore {
            entered: Some(entered_tx),
            release: Some(release_rx),
            write_completed: write_completed.clone(),
        }
        .start();
        let clock = Arc::new(MockClock::new(1000));
        let (buffer, _) = SnapshotBuffer::with_clock(config, store, clock, None)?;

        let context = create_ec(1, 1);
        buffer.send(create_event(&context)).await?;
        buffer
            .send(Insert::new_with_context("state", vec![1], context))
            .await?;

        let mut flush = Box::pin(buffer.send(FlushPendingSnapshots));
        tokio::select! {
            result = &mut flush => anyhow::bail!("final flush returned before its data write began: {result:?}"),
            result = entered_rx => result.context("destination write never began")?,
        }

        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut flush)
                .await
                .is_err(),
            "final flush returned while the destination write was still blocked"
        );
        assert!(!write_completed.load(Ordering::SeqCst));

        release_tx
            .send(())
            .map_err(|_| anyhow::anyhow!("destination write stopped before gate release"))?;
        flush
            .await
            .context("snapshot buffer stopped during final flush")??;
        assert!(write_completed.load(Ordering::SeqCst));
        Ok(())
    }

    #[actix::test]
    async fn test_shutdown_force_flushes_open_batches() -> Result<()> {
        // An open, debounced batch whose timelock has NOT fired must still be
        // committed when a Shutdown event arrives, instead of being lost in the
        // durability window (H2/GF-5).
        let mut delays = HashMap::new();
        // Large delays so batches would never flush via the timelock here.
        delays.insert(AggregateId::new(0), Duration::from_micros(1_000_000));
        delays.insert(AggregateId::new(7), Duration::from_micros(1_000_000));

        let config = &AggregateConfig::new(delays);
        let store = mock_store::MockStore::default().start();
        let clock = Arc::new(MockClock::new(1000));
        let (buffer, timelock) =
            SnapshotBuffer::with_clock(config, store.clone(), clock.clone(), None)?;

        // Turn the buffer on (opens a batch for seq=1).
        buffer
            .send(InterfoldEvent::from_data_ec(
                SyncEnded::new().into(),
                create_ec(0, 1),
            ))
            .await?;

        // Open another batch for aggregate 7 at seq=2 (creates seq/block/ts inserts).
        buffer.send(create_event(&create_ec(7, 2))).await?;

        // Neither timelock has expired, so a Tick flushes nothing.
        timelock.send(Tick).await?;
        let batches = store.send(GetEvts).await?;
        assert_eq!(
            0,
            batches.len(),
            "batches should still be open before shutdown"
        );

        // Shutdown arrives: every open batch must be force-flushed.
        buffer
            .send(InterfoldEvent::from_data_ec(
                Shutdown.into(),
                create_ec(7, 3),
            ))
            .await?;
        buffer.send(FlushPendingSnapshots).await??;

        let batches = store.send(GetEvts).await?;
        assert_eq!(
            2,
            batches.len(),
            "shutdown should force-flush both open batches"
        );

        Ok(())
    }
}
