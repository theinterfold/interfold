// SPDX-License-Identifier: LGPL-3.0-only

//! Mailbox entry points and lifecycle hooks.

use super::*;

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
        let result = (|| {
            match msg.into_data() {
                InterfoldEventData::HistoricalEvmSyncStart(e) => self.handle_sync_start(e)?,
                InterfoldEventData::SyncEnded(e) => self.handle_sync_ended(e)?,
                _ => (),
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.fail_closed(error, ctx);
        }
    }
}

impl Handler<InterfoldEvmEvent> for EvmChainGateway {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvmEvent, ctx: &mut Self::Context) -> Self::Result {
        if let Err(error) = self.handle_evm_event(msg) {
            self.fail_closed(error, ctx);
        }
    }
}
