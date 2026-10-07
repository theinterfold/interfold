// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::historical_order_fixer::HistoricalOrderFixer;
use crate::messages::{EvmEventProcessor, InterfoldEvmEvent};
use actix::{Actor, Addr, Handler};
use e3_utils::MAILBOX_LIMIT;
use tracing::debug;

pub struct FixHistoricalOrder {
    dest: EvmEventProcessor,
    fixer: HistoricalOrderFixer,
}

impl FixHistoricalOrder {
    pub fn new(dest: impl Into<EvmEventProcessor>) -> Self {
        Self {
            dest: dest.into(),
            fixer: HistoricalOrderFixer::new(),
        }
    }

    pub fn setup(dest: impl Into<EvmEventProcessor>) -> Addr<Self> {
        Self::new(dest).start()
    }
}

impl Actor for FixHistoricalOrder {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl Handler<InterfoldEvmEvent> for FixHistoricalOrder {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvmEvent, _ctx: &mut Self::Context) {
        debug!("Receiving InterfoldEvmEvent event({})", msg.get_id());
        for event in self.fixer.process(msg) {
            self.dest.do_send(event);
        }
    }
}
