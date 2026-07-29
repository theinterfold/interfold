// SPDX-License-Identifier: LGPL-3.0-only

//! Mailbox entry points and lifecycle hooks.

use super::*;
use actix::{ActorFutureExt, AsyncContext, AtomicResponse, WrapFuture};

impl Actor for EvmChainGateway {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        self.signal_startup(Err(
            "EVM chain gateway stopped before reaching Live; inspect preceding EVM errors"
                .to_owned(),
        ));
    }
}

impl Handler<InterfoldEvent> for EvmChainGateway {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        match msg.into_data() {
            InterfoldEventData::HistoricalEvmSyncStart(event) => {
                if let Err(error) = self.handle_sync_start(event) {
                    self.fail_closed(error, ctx);
                }
            }
            InterfoldEventData::SyncEnded(event) => match self.handle_sync_ended(event) {
                Ok(pending) => self.drain_buffered_events(pending, ctx),
                Err(error) => self.fail_closed(error, ctx),
            },
            _ => {}
        }
    }
}

impl EvmChainGateway {
    /// Replay a batch only after returning from the `SyncEnded` EventBus
    /// callback. Waiting inside that callback would form a cycle: EventBus ->
    /// gateway -> sequencer -> EventBus.
    fn drain_buffered_events(
        &mut self,
        pending: Vec<InterfoldEvent<Unsequenced>>,
        ctx: &mut actix::Context<Self>,
    ) {
        if pending.is_empty() {
            self.finish_drain_batch(ctx);
            return;
        }

        let bus = self.bus.clone();
        ctx.spawn(
            async move {
                for event in pending {
                    bus.naked_dispatch_async(event).await?;
                }
                anyhow::Ok(())
            }
            .into_actor(self)
            .map(|result, actor, ctx| match result {
                Ok(()) => actor.finish_drain_batch(ctx),
                Err(error) => actor.fail_closed(error, ctx),
            }),
        );
    }

    fn finish_drain_batch(&mut self, ctx: &mut actix::Context<Self>) {
        match self.status.finish_drain_batch() {
            Ok(Some(pending)) => self.drain_buffered_events(pending, ctx),
            Ok(None) => self.signal_startup(Ok(())),
            Err(error) => self.fail_closed(error, ctx),
        }
    }
}

impl Handler<InterfoldEvmEvent> for EvmChainGateway {
    type Result = AtomicResponse<Self, ()>;

    fn handle(&mut self, msg: InterfoldEvmEvent, ctx: &mut Self::Context) -> Self::Result {
        let pending = match self.handle_evm_event(msg) {
            Ok(pending) => pending,
            Err(error) => {
                self.fail_closed(error, ctx);
                return AtomicResponse::new(Box::pin(actix::fut::ready(())));
            }
        };
        let Some(event) = pending else {
            return AtomicResponse::new(Box::pin(actix::fut::ready(())));
        };
        let bus = self.bus.clone();
        AtomicResponse::new(Box::pin(
            async move { bus.naked_dispatch_async(event).await }
                .into_actor(self)
                .map(|result, actor, ctx| {
                    if let Err(error) = result {
                        actor.fail_closed(error, ctx);
                    }
                }),
        ))
    }
}
