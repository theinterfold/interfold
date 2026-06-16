// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, Message, Recipient};
use e3_utils::MAILBOX_LIMIT;

use crate::{Die, Insert, InsertBatch};

#[derive(Message)]
#[rtype(result = "()")]
pub struct Flush;

pub struct Batch {
    inserts: Vec<Insert>,
    db: Recipient<InsertBatch>,
}

impl Batch {
    pub fn new(db: impl Into<Recipient<InsertBatch>>, inserts: Vec<Insert>) -> Self {
        Self {
            inserts,
            db: db.into(),
        }
    }
    pub fn spawn(db: impl Into<Recipient<InsertBatch>>, inserts: Vec<Insert>) -> Addr<Self> {
        Self::new(db, inserts).start()
    }
}

impl Actor for Batch {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<Insert> for Batch {
    type Result = ();
    fn handle(&mut self, msg: Insert, _: &mut Self::Context) -> Self::Result {
        self.inserts.push(msg)
    }
}

impl Handler<Flush> for Batch {
    type Result = ();
    fn handle(&mut self, _: Flush, ctx: &mut Self::Context) -> Self::Result {
        let inserts = std::mem::take(&mut self.inserts);
        if !inserts.is_empty() {
            self.db.do_send(InsertBatch::new(inserts));
        }
        ctx.notify(Die);
    }
}

impl Handler<Die> for Batch {
    type Result = ();
    fn handle(&mut self, _: Die, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}
