// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    events::{FlushEventStores, SequencerBarrier, StoreEventRequested, StoreEventResponse},
    EventBus, InterfoldEvent, Sequenced, Unsequenced,
};
use actix::{Actor, Addr, AsyncContext, Handler, Recipient, ResponseFuture};
use anyhow::{Context, Result};
use e3_utils::MAILBOX_LIMIT;

/// Component to sequence the storage of events
pub struct Sequencer {
    bus: Addr<EventBus<InterfoldEvent<Sequenced>>>,
    eventstore: Recipient<StoreEventRequested>,
    eventstore_flush: Option<Recipient<FlushEventStores>>,
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
        }
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
        self.bus.do_send(msg.into_event());
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
