// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{ShutdownStore, SledDb, StoreHasExactKeys, StoreIsEmpty};
use actix::{Actor, ActorContext, Addr, Handler, ResponseFuture};
use anyhow::{Context, Result};
use e3_events::{BusHandle, EType, ErrorDispatcher, Flush, InterfoldEvent, Unsequenced};
use e3_events::{Get, Insert, InsertBatch, InsertBatchIfAbsent, InsertSync, Remove};
use e3_utils::MAILBOX_LIMIT;
use std::path::PathBuf;
use tracing::{error, info};

pub struct SledStore {
    db: Option<SledDb>,
    bus: Box<dyn ErrorDispatcher<InterfoldEvent<Unsequenced>>>,
    write_failure: Option<String>,
}

impl Actor for SledStore {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl SledStore {
    pub fn new<S: 'static>(bus: &BusHandle<S>, path: &PathBuf) -> Result<Addr<Self>> {
        // The generic BusHandle is retained only for structured storage errors;
        // shutdown itself is coordinated explicitly after actor snapshots drain.
        info!("Starting SledStore with {:?}", path);
        let db = SledDb::new(path, "datastore")?;

        let store = Self {
            db: Some(db),
            bus: Box::new(bus.clone()),
            write_failure: None,
        }
        .start();

        Ok(store)
    }

    fn record_write_failure(&mut self, error: &anyhow::Error) {
        if self.write_failure.is_none() {
            self.write_failure = Some(format!("{error:#}"));
        }
    }

    fn report_write_failure(&mut self, error: &anyhow::Error) {
        self.record_write_failure(error);
        self.bus
            .err(EType::Data, anyhow::anyhow!(format!("{error:#}")));
    }
}

impl Handler<Insert> for SledStore {
    type Result = ();

    fn handle(&mut self, event: Insert, _: &mut Self::Context) -> Self::Result {
        if let Some(ref mut db) = &mut self.db {
            if let Err(err) = db.insert(event) {
                self.report_write_failure(&err);
            }
        }
    }
}

impl Handler<InsertBatch> for SledStore {
    type Result = Result<()>;

    fn handle(&mut self, event: InsertBatch, _: &mut Self::Context) -> Self::Result {
        let Some(ref mut db) = &mut self.db else {
            anyhow::bail!("SledStore is closed");
        };
        if let Err(error) = db.insert_batch(event.commands()) {
            self.report_write_failure(&error);
            return Err(error);
        }
        Ok(())
    }
}

impl Handler<InsertBatchIfAbsent> for SledStore {
    type Result = Result<bool>;

    fn handle(&mut self, event: InsertBatchIfAbsent, _: &mut Self::Context) -> Self::Result {
        let Some(ref mut db) = &mut self.db else {
            anyhow::bail!("SledStore is closed");
        };
        match db.insert_batch_if_absent(event.commands()) {
            Ok(inserted) => Ok(inserted),
            Err(error) => {
                self.report_write_failure(&error);
                Err(error)
            }
        }
    }
}

impl Handler<InsertSync> for SledStore {
    type Result = Result<()>;

    fn handle(&mut self, event: InsertSync, _: &mut Self::Context) -> Self::Result {
        let Some(ref mut db) = &mut self.db else {
            anyhow::bail!("SledStore is closed");
        };
        if let Err(error) = db.insert(event.into()) {
            self.report_write_failure(&error);
            return Err(error);
        }
        Ok(())
    }
}

impl Handler<Remove> for SledStore {
    type Result = ();

    fn handle(&mut self, event: Remove, _: &mut Self::Context) -> Self::Result {
        if let Some(ref mut db) = &mut self.db {
            if let Err(err) = db.remove(event) {
                self.record_write_failure(&err);
                self.bus.err(EType::Data, err)
            }
        }
    }
}

impl Handler<Get> for SledStore {
    type Result = Result<Option<Vec<u8>>>;

    fn handle(&mut self, event: Get, _: &mut Self::Context) -> Self::Result {
        let Some(ref db) = self.db else {
            let error = anyhow::anyhow!("SledStore is closed");
            error!(%error, "Attempt to get data from dropped db");
            self.bus
                .err(EType::Data, anyhow::anyhow!(error.to_string()));
            return Err(error);
        };

        match db.get(event) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.bus
                    .err(EType::Data, anyhow::anyhow!(format!("{error:#}")));
                Err(error)
            }
        }
    }
}

impl Handler<StoreIsEmpty> for SledStore {
    type Result = Result<bool>;

    fn handle(&mut self, _: StoreIsEmpty, _: &mut Self::Context) -> Self::Result {
        let db = self.db.as_ref().context("SledStore is closed")?;
        Ok(db.is_empty())
    }
}

impl Handler<StoreHasExactKeys> for SledStore {
    type Result = Result<bool>;

    fn handle(&mut self, message: StoreHasExactKeys, _: &mut Self::Context) -> Self::Result {
        let db = self.db.as_ref().context("SledStore is closed")?;
        db.has_exact_keys(message.keys())
    }
}

impl Handler<Flush> for SledStore {
    type Result = Result<()>;
    fn handle(&mut self, _: Flush, _: &mut Self::Context) -> Self::Result {
        if let Some(error) = &self.write_failure {
            anyhow::bail!("SledStore observed an earlier write failure: {error}");
        }
        let Some(ref db) = self.db else {
            anyhow::bail!("SledStore is closed");
        };
        if let Err(error) = db.flush() {
            self.report_write_failure(&error);
            return Err(error);
        }
        Ok(())
    }
}

impl Handler<ShutdownStore> for SledStore {
    type Result = ResponseFuture<Result<()>>;

    fn handle(&mut self, _: ShutdownStore, ctx: &mut Self::Context) -> Self::Result {
        let db = self.db.take();
        let write_failure = self.write_failure.take();
        ctx.stop();

        Box::pin(async move {
            let db = db.context("SledStore was already closed")?;
            tokio::task::spawn_blocking(move || db.flush())
                .await
                .context("SledStore flush task failed")??;

            if let Some(error) = write_failure {
                anyhow::bail!("SledStore observed a write failure before shutdown: {error}");
            }
            Ok(())
        })
    }
}
