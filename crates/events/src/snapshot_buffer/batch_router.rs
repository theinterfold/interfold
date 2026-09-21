// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use super::{
    batch::Batch,
    timelock_queue::{Clock, StartTimelock},
    AggregateConfig, FlushPendingSnapshots, UpdateDestination,
};
use crate::{
    AggregateId, EventContextAccessors, EventContextSeq, EventType, Insert, InsertBatch,
    InterfoldEvent, Sequenced, StoreKeys,
};
use actix::{
    Actor, ActorFutureExt, Addr, AsyncContext, Handler, Message, Recipient, ResponseFuture,
    WrapFuture,
};
use anyhow::Result;
use e3_utils::MAILBOX_LIMIT;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::{debug, error};

type Seq = u64;

/// Snapshot batches are scoped by both aggregate and per-aggregate sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct SnapshotKey {
    aggregate_id: AggregateId,
    seq: Seq,
}

struct PendingBatch {
    order: u128,
    addr: Addr<Batch>,
    scheduled: bool,
}

impl SnapshotKey {
    pub(super) fn new(aggregate_id: AggregateId, seq: Seq) -> Self {
        Self { aggregate_id, seq }
    }

    pub(super) fn aggregate_id(self) -> AggregateId {
        self.aggregate_id
    }

    pub(super) fn seq(self) -> Seq {
        self.seq
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct FlushSeq(pub(super) SnapshotKey);

impl FlushSeq {
    pub fn seq(&self) -> u64 {
        self.0.seq()
    }

    pub fn aggregate_id(&self) -> AggregateId {
        self.0.aggregate_id()
    }
}

pub struct BatchRouter {
    config: AggregateConfig,
    batches: HashMap<SnapshotKey, PendingBatch>,
    next_batch_order: u128,
    block_height_seen: HashMap<AggregateId, u64>,
    timelock_queue: Recipient<StartTimelock>,
    db: Recipient<InsertBatch>,
    clock: Arc<dyn Clock>,
    write_failure: Option<String>,
}

impl Actor for BatchRouter {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl BatchRouter {
    #[allow(dead_code)]
    pub fn new(
        config: &AggregateConfig,
        timelock_queue: impl Into<Recipient<StartTimelock>>,
        db: impl Into<Recipient<InsertBatch>>,
    ) -> Self {
        Self::with_clock(
            config,
            timelock_queue,
            db,
            Arc::new(super::timelock_queue::SystemClock),
        )
    }

    pub fn with_clock(
        config: &AggregateConfig,
        timelock_queue: impl Into<Recipient<StartTimelock>>,
        db: impl Into<Recipient<InsertBatch>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            batches: HashMap::new(),
            next_batch_order: 0,
            config: config.clone(),
            timelock_queue: timelock_queue.into(),
            block_height_seen: HashMap::new(),
            db: db.into(),
            clock,
            write_failure: None,
        }
    }

    fn get_highest_block(&mut self, agg: AggregateId, block: Option<u64>) -> u64 {
        let highest = block
            .into_iter()
            .chain(self.block_height_seen.get(&agg).copied())
            .max()
            .unwrap_or(0);

        self.block_height_seen.insert(agg, highest);
        highest
    }

    fn record_write_failure(&mut self, error: anyhow::Error) {
        let error = format!("{error:#}");
        error!(%error, "Snapshot batch flush failed");
        if self.write_failure.is_none() {
            self.write_failure = Some(error);
        }
    }

    fn schedule_older_batches(&mut self, aggregate_id: AggregateId, seq: Seq) {
        let mut older = self
            .batches
            .iter()
            .filter_map(|(key, batch)| {
                (key.aggregate_id() == aggregate_id && key.seq() < seq && !batch.scheduled)
                    .then_some((*key, batch.order))
            })
            .collect::<Vec<_>>();
        older.sort_by_key(|(_, order)| *order);

        let delay = self.config.get_delay(&aggregate_id);
        let now = Duration::from_micros(self.clock.now_micros());
        for (key, _) in older {
            let Some(batch) = self.batches.get_mut(&key) else {
                continue;
            };
            batch.scheduled = true;
            debug!(
                aggregate = %aggregate_id,
                seq = key.seq(),
                "Scheduling older snapshot batch"
            );
            self.timelock_queue
                .do_send(StartTimelock::new(key, now, delay));
        }
    }
}

impl Handler<Insert> for BatchRouter {
    type Result = ();
    fn handle(&mut self, msg: Insert, _: &mut Self::Context) -> Self::Result {
        // Messages without context go straight to disk
        // This is probably direct datastore manipulation
        let Some(ctx) = msg.ctx() else {
            debug!("Message without context. Flushing straight to disk.");
            self.db.do_send(InsertBatch::new(vec![msg]));
            return;
        };

        // Route to existing batch, or fall back to disk
        let key = SnapshotKey::new(ctx.aggregate_id(), ctx.seq());
        match self.batches.get(&key) {
            Some(batch) => {
                debug!(
                    aggregate = %key.aggregate_id(),
                    seq = key.seq(),
                    "Forwarding insert to snapshot batch"
                );
                batch.addr.do_send(msg);
            }
            // This must mean that this insert is late
            None => {
                debug!(
                    aggregate = %key.aggregate_id(),
                    seq = key.seq(),
                    "No snapshot batch is open; flushing late insert directly"
                );
                self.db.do_send(InsertBatch::new(vec![msg]));
            }
        }
    }
}

impl Handler<InterfoldEvent<Sequenced>> for BatchRouter {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent<Sequenced>, _: &mut Self::Context) -> Self::Result {
        // Keep every open batch registered until the acknowledged
        // `FlushPendingSnapshots` fence drains it. Enqueueing child flushes here and clearing the
        // map lets the later fence return before the destination store has handled them.
        if msg.event_type_enum() == EventType::Shutdown {
            debug!(
                open_batches = self.batches.len(),
                "Shutdown observed; snapshot batches await the acknowledged drain"
            );
            return;
        }

        let ec = msg.get_ctx();
        let agg_id = ec.aggregate_id();
        // A downstream deduplication or a failed subscriber must not strand an earlier sequence.
        // Schedule every older open batch, not only the exact predecessor.
        self.schedule_older_batches(agg_id, ec.seq());

        let key = SnapshotKey::new(agg_id, ec.seq());
        if self.batches.contains_key(&key) {
            error!(
                aggregate = %agg_id,
                seq = ec.seq(),
                "Snapshot batch already exists for event context; retaining the original batch"
            );
            return;
        }
        debug!(aggregate = %agg_id, seq = ec.seq(), "Creating snapshot batch");
        let highest_block = self.get_highest_block(agg_id, ec.block());
        let batch = Batch::spawn(
            self.db.clone(),
            vec![
                Insert::new_with_context(
                    StoreKeys::aggregate_seq(agg_id),
                    encode_u64(ec.seq()),
                    ec.clone(),
                ),
                Insert::new_with_context(
                    StoreKeys::aggregate_block(agg_id),
                    encode_u64(highest_block),
                    ec.clone(),
                ),
                Insert::new_with_context(
                    StoreKeys::aggregate_ts(agg_id),
                    encode_u128(ec.ts()),
                    ec.clone(),
                ),
            ],
        );
        let order = self.next_batch_order;
        self.next_batch_order = self.next_batch_order.saturating_add(1);
        self.batches.insert(
            key,
            PendingBatch {
                order,
                addr: batch,
                scheduled: false,
            },
        );
    }
}

impl Handler<FlushSeq> for BatchRouter {
    type Result = ();
    fn handle(&mut self, msg: FlushSeq, ctx: &mut Self::Context) -> Self::Result {
        let key = msg.0;
        debug!(
            aggregate = %key.aggregate_id(),
            seq = key.seq(),
            "Flushing snapshot batch"
        );
        let Some(batch) = self.batches.remove(&key) else {
            return;
        };

        let flush = async move {
            batch
                .addr
                .send(FlushPendingSnapshots)
                .await
                .map_err(anyhow::Error::from)??;
            Ok::<(), anyhow::Error>(())
        }
        .into_actor(self)
        .map(|result, actor, _| {
            if let Err(error) = result {
                actor.record_write_failure(error);
            }
        });

        // Preserve event/insert ordering and ensure the shutdown fence cannot overtake a normal
        // timelock flush that is already in the router mailbox.
        ctx.wait(flush);
    }
}

impl Handler<FlushPendingSnapshots> for BatchRouter {
    type Result = ResponseFuture<Result<()>>;

    fn handle(&mut self, _: FlushPendingSnapshots, _: &mut Self::Context) -> Self::Result {
        let mut batches: Vec<_> = self.batches.drain().map(|(_, batch)| batch).collect();
        // The latest event for each aggregate remains open until another event schedules it.
        // Preserve cross-aggregate event order so the newest snapshot is the final write.
        batches.sort_by_key(|batch| batch.order);
        let db = self.db.clone();
        let previous_failure = self.write_failure.take();
        Box::pin(async move {
            let mut failures = previous_failure.into_iter().collect::<Vec<_>>();
            for batch in batches {
                match batch.addr.send(FlushPendingSnapshots).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => failures.push(format!("{error:#}")),
                    Err(error) => failures.push(format!(
                        "snapshot batch stopped before its final flush: {error}"
                    )),
                }
            }

            // Destination-mailbox barrier for late/direct inserts that were already sent by this
            // router before the shutdown fence. The empty transactional batch has no data effect.
            match db.send(InsertBatch::new(vec![])).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(format!("{error:#}")),
                Err(error) => failures.push(format!(
                    "snapshot destination stopped before its final barrier: {error}"
                )),
            }

            if !failures.is_empty() {
                anyhow::bail!("snapshot drain failed: {}", failures.join("; "));
            }
            Ok(())
        })
    }
}

impl Handler<UpdateDestination> for BatchRouter {
    type Result = ();
    fn handle(&mut self, msg: UpdateDestination, _: &mut Self::Context) -> Self::Result {
        self.db = msg.0;
    }
}

/// Encode the same as bincode without using a result
fn encode_u64(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// Encode the same as bincode without using a result
fn encode_u128(value: u128) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}
