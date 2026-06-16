// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    events::{StoreEventRequested, StoreEventResponse},
    EventBus, InterfoldEvent, Sequenced, Unsequenced,
};
use actix::{Actor, Addr, AsyncContext, Handler, Recipient};
use e3_utils::MAILBOX_LIMIT;

/// Component to sequence the storage of events
pub struct Sequencer {
    bus: Addr<EventBus<InterfoldEvent<Sequenced>>>,
    eventstore: Recipient<StoreEventRequested>,
}

impl Sequencer {
    pub fn new(
        bus: &Addr<EventBus<InterfoldEvent<Sequenced>>>,
        eventstore: impl Into<Recipient<StoreEventRequested>>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            eventstore: eventstore.into(),
        }
    }

    fn handle_store_event_response(&self, msg: StoreEventResponse) {
        let event = msg.into_event();
        self.bus.do_send(event);
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
    fn handle(&mut self, msg: StoreEventResponse, _: &mut Self::Context) -> Self::Result {
        self.handle_store_event_response(msg);
    }
}

#[cfg(test)]
mod tests {
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{EventPublisher, GetEvents, InterfoldEvent, TakeEvents, TestEvent};

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
}
