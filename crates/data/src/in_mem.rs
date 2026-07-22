// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    in_mem_kv_store::{DataOp, InMemKvStore},
    ShutdownStore, StoreHasExactKeys, StoreIsEmpty,
};
use actix::{Actor, ActorContext, Handler, Message};
use anyhow::Result;
use e3_events::{Flush, Get, Insert, InsertBatch, InsertBatchIfAbsent, InsertSync, Remove};
use e3_utils::MAILBOX_LIMIT;

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash)]
#[rtype(result = "Vec<DataOp>")]
pub struct GetLog;

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash)]
#[rtype(result = "anyhow::Result<Vec<u8>>")]
pub struct GetDump;

/// Thin actix actor wrapping the pure [`InMemKvStore`]. The actor is purely
/// responsible for message passing; all storage logic lives in the service.
pub struct InMemStore {
    store: InMemKvStore,
}

impl Actor for InMemStore {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl InMemStore {
    pub fn new(capture: bool) -> Self {
        Self {
            store: InMemKvStore::new(capture),
        }
    }

    pub fn get_dump(&self) -> Result<Vec<u8>> {
        self.store.dump()
    }

    pub fn from_dump(db: Vec<u8>, capture: bool) -> anyhow::Result<Self> {
        Ok(Self {
            store: InMemKvStore::from_dump(&db, capture)?,
        })
    }
}

impl Handler<Insert> for InMemStore {
    type Result = ();
    fn handle(&mut self, event: Insert, _: &mut Self::Context) {
        let key = event.key().to_vec();
        let value = event.value().to_vec();
        self.store.insert(key, value, Some(DataOp::Insert(event)));
    }
}

impl Handler<InsertBatch> for InMemStore {
    type Result = Result<()>;
    fn handle(&mut self, msg: InsertBatch, _: &mut Self::Context) -> Self::Result {
        for cmd in msg.commands() {
            self.store.insert(
                cmd.key().to_owned(),
                cmd.value().to_owned(),
                Some(DataOp::Insert(cmd.clone())),
            );
        }
        Ok(())
    }
}

impl Handler<StoreIsEmpty> for InMemStore {
    type Result = Result<bool>;

    fn handle(&mut self, _: StoreIsEmpty, _: &mut Self::Context) -> Self::Result {
        Ok(self.store.is_empty())
    }
}

impl Handler<StoreHasExactKeys> for InMemStore {
    type Result = Result<bool>;

    fn handle(&mut self, message: StoreHasExactKeys, _: &mut Self::Context) -> Self::Result {
        Ok(self.store.has_exact_keys(message.keys()))
    }
}

impl Handler<InsertBatchIfAbsent> for InMemStore {
    type Result = Result<bool>;

    fn handle(&mut self, msg: InsertBatchIfAbsent, _: &mut Self::Context) -> Self::Result {
        if msg
            .commands()
            .iter()
            .any(|command| self.store.get(command.key()).is_some())
        {
            return Ok(false);
        }
        for command in msg.commands() {
            self.store.insert(
                command.key().to_owned(),
                command.value().to_owned(),
                Some(DataOp::Insert(command.clone())),
            );
        }
        Ok(true)
    }
}

impl Handler<InsertSync> for InMemStore {
    type Result = Result<()>;

    fn handle(&mut self, event: InsertSync, _: &mut Self::Context) -> Self::Result {
        let key = event.key().to_vec();
        let value = event.value().to_vec();
        self.store
            .insert(key, value, Some(DataOp::Insert(event.into())));
        Ok(())
    }
}

impl Handler<Remove> for InMemStore {
    type Result = ();
    fn handle(&mut self, event: Remove, _: &mut Self::Context) {
        let key = event.key().to_vec();
        self.store.remove(&key, Some(DataOp::Remove(event)));
    }
}

impl Handler<Get> for InMemStore {
    type Result = Result<Option<Vec<u8>>>;
    fn handle(&mut self, event: Get, _: &mut Self::Context) -> Self::Result {
        Ok(self.store.get(event.key()))
    }
}

impl Handler<Flush> for InMemStore {
    type Result = Result<()>;
    fn handle(&mut self, _: Flush, _: &mut Self::Context) -> Self::Result {
        Ok(())
    }
}

impl Handler<ShutdownStore> for InMemStore {
    type Result = Result<()>;

    fn handle(&mut self, _: ShutdownStore, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
        Ok(())
    }
}

impl Handler<GetLog> for InMemStore {
    type Result = Vec<DataOp>;
    fn handle(&mut self, _: GetLog, _: &mut Self::Context) -> Vec<DataOp> {
        self.store.log()
    }
}

impl Handler<GetDump> for InMemStore {
    type Result = anyhow::Result<Vec<u8>>;
    fn handle(&mut self, _: GetDump, _: &mut Self::Context) -> Self::Result {
        self.get_dump()
    }
}
