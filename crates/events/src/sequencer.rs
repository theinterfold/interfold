// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    events::{FlushEventStores, PersistEvent, PublishEvent, SequencerBarrier},
    EventBus, EventBusFanout, InterfoldEvent, Sequenced, Unsequenced,
};
use actix::{
    Actor, ActorContext, ActorFutureExt, Addr, AsyncContext, AtomicResponse, Handler, Recipient,
    ResponseFuture, WrapFuture,
};
use anyhow::{Context, Result};
use e3_utils::MAILBOX_LIMIT;

/// Component to sequence the storage of events
pub struct Sequencer {
    bus: Addr<EventBus<InterfoldEvent<Sequenced>>>,
    eventstore: Recipient<PersistEvent>,
    eventstore_flush: Option<Recipient<FlushEventStores>>,
}

impl Sequencer {
    pub fn new(
        bus: &Addr<EventBus<InterfoldEvent<Sequenced>>>,
        eventstore: impl Into<Recipient<PersistEvent>>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            eventstore: eventstore.into(),
            eventstore_flush: None,
        }
    }

    pub fn new_with_flush(
        bus: &Addr<EventBus<InterfoldEvent<Sequenced>>>,
        eventstore: impl Into<Recipient<PersistEvent>>,
        eventstore_flush: impl Into<Recipient<FlushEventStores>>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            eventstore: eventstore.into(),
            eventstore_flush: Some(eventstore_flush.into()),
        }
    }
}

async fn persist_and_fanout(
    eventstore: Recipient<PersistEvent>,
    bus: Addr<EventBus<InterfoldEvent<Sequenced>>>,
    event: InterfoldEvent<Unsequenced>,
) -> Result<()> {
    let stored = eventstore
        .send(PersistEvent(event))
        .await
        .context("event-store router stopped before accepting publication")??;
    if let Some(event) = stored {
        bus.send(EventBusFanout(event))
            .await
            .context("EventBus stopped before accepting persisted event")??;
    }
    Ok(())
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
        let future = persist_and_fanout(self.eventstore.clone(), self.bus.clone(), msg);
        ctx.wait(future.into_actor(self).map(|result, _, ctx| {
            if let Err(error) = result {
                ctx.stop();
                panic!("required event pipeline failed: {error:#}");
            }
        }));
    }
}

impl Handler<PublishEvent> for Sequencer {
    type Result = AtomicResponse<Self, Result<()>>;

    fn handle(&mut self, msg: PublishEvent, _: &mut Self::Context) -> Self::Result {
        AtomicResponse::new(Box::pin(
            persist_and_fanout(self.eventstore.clone(), self.bus.clone(), msg.0).into_actor(self),
        ))
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
    use actix::{Actor, Handler, ResponseFuture};
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{
        EventType, GetEvents, InterfoldEvent, Sequenced, Subscribe, TakeEvents, TestEvent,
    };
    use std::sync::Arc;
    use tokio::sync::Notify;

    struct BlockingSubscriber(Arc<Notify>);

    impl Actor for BlockingSubscriber {
        type Context = actix::Context<Self>;
    }

    impl Handler<InterfoldEvent<Sequenced>> for BlockingSubscriber {
        type Result = ResponseFuture<()>;

        fn handle(&mut self, _: InterfoldEvent<Sequenced>, _: &mut Self::Context) -> Self::Result {
            let gate = Arc::clone(&self.0);
            Box::pin(async move { gate.notified().await })
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
            bus.publish_and_wait(d, None).await?;
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
            bus.publish_and_wait(TestEvent::new(&format!("evt-{i}"), i as u64), None)
                .await?;
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
    async fn acknowledged_publish_waits_for_subscriber_completion() -> anyhow::Result<()> {
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("acknowledged-publish");
        let gate = Arc::new(Notify::new());
        let subscriber = BlockingSubscriber(Arc::clone(&gate)).start();

        bus.event_bus()
            .send(Subscribe::new(EventType::TestEvent, subscriber.recipient()))
            .await?;

        let mut publish = Box::pin(bus.publish_and_wait(TestEvent::new("blocked", 1), None));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut publish)
                .await
                .is_err(),
            "publication acknowledged before its subscriber completed"
        );

        gate.notify_one();
        publish.await?;
        Ok(())
    }
}
