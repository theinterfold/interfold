// SPDX-License-Identifier: LGPL-3.0-only

//! Mailbox entry points and lifecycle hooks.

use super::*;

impl<P: Provider + Clone + 'static> Actor for EvmReadInterface<P> {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);

        let bus = self.bus.clone();
        let next = self.next.clone();
        let filters = self.filters.clone();
        let provider_factory = self.provider_factory.take();
        let ingestion_status = self.ingestion_status.clone();

        let Some(provider) = self.provider.take() else {
            error!("Could not start event reader as provider has already been used.");
            return;
        };

        let Some(shutdown) = self.shutdown_rx.take() else {
            bus.err(EType::Evm, anyhow!("shutdown already called"));
            return;
        };

        ctx.spawn(
            async move {
                stream_from_evm(
                    provider,
                    provider_factory,
                    next,
                    shutdown,
                    &bus,
                    filters,
                    ingestion_status,
                )
                .await
            }
            .into_actor(self),
        );
    }
}

impl<P: Provider + Clone + 'static> Handler<InterfoldEvent> for EvmReadInterface<P> {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        if let InterfoldEventData::Shutdown(_) = msg.into_data() {
            if let Some(shutdown) = self.shutdown_tx.take() {
                let _ = shutdown.send(());
            }
        }
    }
}
