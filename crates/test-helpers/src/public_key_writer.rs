// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::path::PathBuf;

use super::write_file_with_dirs;
use actix::{Actor, Addr, Context, Handler};
use e3_events::{
    prelude::*, BusHandle, EventSubscriber, EventType, InterfoldEvent, InterfoldEventData,
};
use e3_utils::MAILBOX_LIMIT;
use tracing::info;

pub struct PublicKeyWriter {
    path: PathBuf,
}

impl PublicKeyWriter {
    pub fn attach(path: &PathBuf, bus: BusHandle) -> Addr<Self> {
        let addr = Self {
            path: path.to_owned(),
        }
        .start();
        bus.subscribe(EventType::PublicKeyAggregated, addr.clone().recipient());
        addr
    }
}

impl Actor for PublicKeyWriter {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for PublicKeyWriter {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        if let InterfoldEventData::PublicKeyAggregated(data) = msg.into_data() {
            info!(path = ?&self.path, "Writing Pubkey To Path");
            write_file_with_dirs(&self.path, &data.pubkey).unwrap();
        }
    }
}
