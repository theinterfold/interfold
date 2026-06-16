// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, Addr, Handler, Recipient};
use e3_events::{Event, HistoricalEvmSyncStart, InterfoldEvent, InterfoldEventData};
use e3_utils::MAILBOX_LIMIT;

pub struct SyncStartExtractor {
    dest: Recipient<HistoricalEvmSyncStart>,
}

impl SyncStartExtractor {
    pub fn new(dest: impl Into<Recipient<HistoricalEvmSyncStart>>) -> Self {
        Self { dest: dest.into() }
    }

    pub fn setup(dest: impl Into<Recipient<HistoricalEvmSyncStart>>) -> Addr<Self> {
        Self::new(dest).start()
    }
}
impl Actor for SyncStartExtractor {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl Handler<InterfoldEvent> for SyncStartExtractor {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        if let InterfoldEventData::HistoricalEvmSyncStart(evt) = msg.into_data() {
            self.dest.do_send(evt)
        }
    }
}
