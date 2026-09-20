// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    events::{FlushEventStores, SequencerBarrier, StoreEventRequested, StoreEventResponse},
    EventBus, InterfoldEvent, Sequenced, Unsequenced,
};
use actix::{
    Actor, ActorContext, ActorFutureExt, Addr, AsyncContext, Handler, Recipient, ResponseFuture,
    WrapFuture,
};
use anyhow::{Context, Result};
use e3_utils::MAILBOX_LIMIT;
use tracing::error;

/// Component to sequence the storage of events
pub struct Sequencer {
    bus: Addr<EventBus<InterfoldEvent<Sequenced>>>,
    eventstore: Recipient<StoreEventRequested>,
    eventstore_flush: Option<Recipient<FlushEventStores>>,
    pre_fanout: Option<Recipient<InterfoldEvent<Sequenced>>>,
}

impl Sequencer {
    pub fn new(
        bus: &Addr<EventBus<InterfoldEvent<Sequenced>>>,
        eventstore: impl Into<Recipient<StoreEventRequested>>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            eventstore: eventstore.into(),
            eventstore_flush: None,
            pre_fanout: None,
        }
    }

    pub fn new_with_flush(
        bus: &Addr<EventBus<InterfoldEvent<Sequenced>>>,
        eventstore: impl Into<Recipient<StoreEventRequested>>,
        eventstore_flush: impl Into<Recipient<FlushEventStores>>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            eventstore: eventstore.into(),
            eventstore_flush: Some(eventstore_flush.into()),
            pre_fanout: None,
        }
    }

    /// Deliver each durable sequence to infrastructure before domain-event deduplication.
    pub fn with_pre_fanout(
        mut self,
        recipient: impl Into<Recipient<InterfoldEvent<Sequenced>>>,
    ) -> Self {
        self.pre_fanout = Some(recipient.into());
        self
    }
}

impl Actor for Sequencer {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent<Unsequenced>> for Sequencer {
    type Result = ();
    fn handle(
        &mut self,
        msg: InterfoldEvent<Unsequenced>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        self.eventstore
            .do_send(StoreEventRequested::new(msg, ctx.address()));
    }
}

impl Handler<StoreEventResponse> for Sequencer {
    type Result = ();
    fn handle(&mut self, msg: StoreEventResponse, ctx: &mut Self::Context) -> Self::Result {
        let event = msg.into_event();
        let pre_fanout = self.pre_fanout.clone();
        let bus = self.bus.clone();

        // The snapshot batch must exist before stateful subscribers can enqueue writes for this
        // event. It also must observe sequences that domain deduplication intentionally suppresses.
        ctx.wait(
            async move {
                if let Some(pre_fanout) = pre_fanout {
                    pre_fanout.send(event.clone()).await.context(
                        "pre-fanout subscriber stopped before accepting a durable event",
                    )?;
                }
                Ok::<_, anyhow::Error>(event)
            }
            .into_actor(self)
            .map(move |result, _, ctx| match result {
                Ok(event) => bus.do_send(event),
                Err(error) => {
                    error!(%error, "Stopping the sequencer after pre-fanout delivery failed");
                    ctx.stop();
                }
            }),
        );
    }
}

impl Handler<FlushEventStores> for Sequencer {
    type Result = ResponseFuture<Result<()>>;

    fn handle(&mut self, _: FlushEventStores, _: &mut Self::Context) -> Self::Result {
        let eventstore_flush = self.eventstore_flush.clone();
        Box::pin(async move {
            let eventstore_flush = eventstore_flush
                .context("sequencer was constructed without an event-store flush endpoint")?;
            eventstore_flush
                .send(FlushEventStores)
                .await
                .context("event-store router stopped during shutdown flush")??;
            Ok(())
        })
    }
}

impl Handler<SequencerBarrier> for Sequencer {
    type Result = ();

    fn handle(&mut self, _: SequencerBarrier, _: &mut Self::Context) -> Self::Result {}
}

#[cfg(test)]
mod tests {
    use actix::{Actor, Handler, Message};
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{
        EventPublisher, EventSource, FlushPendingSnapshots, GetEvents, InsertBatch, InterfoldEvent,
        TakeEvents, TestEvent, UpdateDestination,
    };

    #[derive(Default)]
    struct SnapshotCollector(Vec<InsertBatch>);

    impl Actor for SnapshotCollector {
        type Context = actix::Context<Self>;
    }

    impl Handler<InsertBatch> for SnapshotCollector {
        type Result = anyhow::Result<()>;

        fn handle(&mut self, batch: InsertBatch, _: &mut Self::Context) -> Self::Result {
            if !batch.commands().is_empty() {
                self.0.push(batch);
            }
            Ok(())
        }
    }

    #[derive(Message)]
    #[rtype(result = "Vec<InsertBatch>")]
    struct TakeSnapshots;

    impl Handler<TakeSnapshots> for SnapshotCollector {
        type Result = Vec<InsertBatch>;

        fn handle(&mut self, _: TakeSnapshots, _: &mut Self::Context) -> Self::Result {
            std::mem::take(&mut self.0)
        }
    }

    #[actix::test]
    async fn it_adds_seqence_numbers_to_events() -> anyhow::Result<()> {
        let system = EventSystem::new();
        let bus = system.handle()?.enable("test");
        let history = bus.history();

        let event_data = vec![
            TestEvent::new("one", 1),
            TestEvent::new("two", 2),
            TestEvent::new("three", 3),
        ];

        for d in event_data.clone() {
            bus.publish_without_context(d)?;
        }

        let expected = event_data
            .into_iter()
            .map(|d| InterfoldEvent::new_stored_event(d.clone().into(), 0, d.entropy))
            .collect::<Vec<_>>();
        let events = history.send(TakeEvents::new(3)).await?;

        assert_eq!(
            events
                .events
                .iter()
                .map(InterfoldEvent::strip_ts)
                .collect::<Vec<_>>(),
            expected
        );
        Ok(())
    }

    #[actix::test]
    async fn it_handles_event_burst_without_overflow() -> anyhow::Result<()> {
        let count = 500usize;
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("test-burst");
        let history = bus.history();

        let start = std::time::Instant::now();

        for i in 0..count {
            bus.publish_without_context(TestEvent::new(&format!("evt-{i}"), i as u64))?;
        }

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let events: Vec<InterfoldEvent> = history.send(GetEvents::new()).await?;
            if events.len() >= count {
                let elapsed = start.elapsed();
                println!("All {count} events arrived in {elapsed:?}");
                assert_eq!(events.len(), count, "all events must arrive");
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let got = events.len();
                panic!("test timed out — only {got}/{count} events arrived after 30s");
            }
            // Yield to let the actor system make progress.
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        Ok(())
    }

    #[actix::test]
    async fn equal_evm_facts_reach_domain_and_snapshot_paths() -> anyhow::Result<()> {
        let system = EventSystem::new().with_fresh_bus();
        let snapshots = SnapshotCollector::default().start();
        let buffer = system.buffer()?;
        buffer
            .send(UpdateDestination::new(snapshots.clone().recipient()))
            .await?;
        let bus = system.handle()?.enable("same-evm-fact");
        let history = bus.history();

        let fact = TestEvent::new("same fact", 1);
        bus.publish_from_remote(fact.clone(), 1_000_000, Some(100), EventSource::Evm)?;
        bus.publish_from_remote(fact, 2_000_000, Some(101), EventSource::Evm)?;
        bus.flush_event_pipeline().await?;
        buffer.send(FlushPendingSnapshots).await??;

        let delivered = history.send(GetEvents::new()).await?;
        assert_eq!(
            delivered.len(),
            2,
            "both chain occurrences must be delivered"
        );

        let snapshot_batches = snapshots.send(TakeSnapshots).await?;
        let revisions = snapshot_batches
            .iter()
            .map(InsertBatch::snapshot_revision)
            .collect::<anyhow::Result<Vec<_>>>()?;
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].expect("first revision").seq(), 1);
        assert_eq!(revisions[1].expect("second revision").seq(), 2);
        Ok(())
    }
}
