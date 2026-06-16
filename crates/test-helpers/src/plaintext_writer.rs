// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::path::PathBuf;

use super::write_file_with_dirs;
use actix::{Actor, Addr, Context, Handler};
use e3_bfv_client::decode_bytes_to_vec_u64;
use e3_events::{prelude::*, BusHandle, EventType, InterfoldEvent, InterfoldEventData};
use e3_utils::MAILBOX_LIMIT;
use tracing::{error, info};

pub struct PlaintextWriter {
    path: PathBuf,
}

impl PlaintextWriter {
    pub fn attach(path: &PathBuf, bus: BusHandle) -> Addr<Self> {
        let addr = Self {
            path: path.to_owned(),
        }
        .start();
        bus.subscribe(EventType::PlaintextAggregated, addr.clone().recipient());
        addr
    }
}

impl Actor for PlaintextWriter {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for PlaintextWriter {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        if let InterfoldEventData::PlaintextAggregated(data) = msg.into_data() {
            let Some(decrypted) = data.decrypted_output.first() else {
                error!("Decrypted output must not be empty!");
                return;
            };

            let output = decode_bytes_to_vec_u64(decrypted).unwrap();

            info!(path = ?&self.path, "Writing Plaintext To Path");
            let contents: Vec<String> = output.iter().map(|&num| num.to_string()).collect();

            write_file_with_dirs(&self.path, contents.join(",").to_string().as_bytes()).unwrap();
        }
    }
}
