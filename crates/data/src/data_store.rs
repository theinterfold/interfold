// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::borrow::Cow;

use crate::{InMemStore, SledStore};
use actix::{Addr, Recipient};
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use e3_events::IntoKey;
use e3_events::{Flush, Get, Insert, InsertSync, Remove};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Clone, Debug)]
pub enum StoreAddr {
    InMem(Addr<InMemStore>),
    Sled(Addr<SledStore>),
}

impl StoreAddr {
    pub fn to_maybe_in_mem(&self) -> Option<&Addr<InMemStore>> {
        match self {
            StoreAddr::InMem(ref store) => Some(store),
            _ => None,
        }
    }
}

/// Generate proxy for the DB / KV store
/// DataStore is scopable
#[derive(Clone, Debug)]
pub struct DataStore {
    scope: Vec<u8>,
    addr: StoreAddr,
    get: Recipient<Get>,
    insert: Recipient<Insert>,
    insert_sync: Recipient<InsertSync>,
    remove: Recipient<Remove>,
    flush: Recipient<Flush>,
}

impl DataStore {
    /// Read data at the scope location
    pub async fn read<T>(&self) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let Some(bytes) = self.get.send(Get::new(&self.scope)).await? else {
            return Ok(None);
        };

        // If we get a null value return None as this doesn't deserialize correctly
        if bytes == [0] {
            return Ok(None);
        }
        Ok(Some(bincode::deserialize(&bytes)?))
    }

    /// Writes data to the scope location
    pub fn write<T: Serialize>(&self, value: T) {
        let Ok(serialized) = bincode::serialize(&value) else {
            let str_key = self.get_scope().unwrap_or(Cow::Borrowed("<bad key>"));
            let str_error = format!("Could not serialize value passed to {}", str_key);
            error!(str_error);
            return;
        };
        let msg = Insert::new(&self.scope, serialized);
        self.insert.do_send(msg)
    }

    /// Writes data syncronously to the scope location
    pub async fn write_sync<T: Serialize>(&self, value: T) -> Result<()> {
        let serialized = bincode::serialize(&value).with_context(|| {
            let str_key = self.get_scope().unwrap_or(Cow::Borrowed("<bad key>"));
            anyhow!("Could not serialize value passed to {}", str_key)
        })?;

        let msg = InsertSync::new(&self.scope, serialized);
        self.insert_sync.send(msg).await??;
        self.flush.send(Flush).await?; // Write sync will flush all pending writes
        Ok(())
    }

    /// Removes data from the scope location
    pub fn clear(&self) {
        self.remove.do_send(Remove::new(&self.scope))
    }

    /// Get the scope as a string
    pub fn get_scope(&self) -> Result<Cow<'_, str>> {
        Ok(String::from_utf8_lossy(&self.scope))
    }

    /// Get a reference to the addr enum
    pub fn get_addr(&self) -> &StoreAddr {
        &self.addr
    }

    /// Get a reference to the Recipient<Get>
    pub fn get_recipient(&self) -> &Recipient<Get> {
        &self.get
    }

    /// Get a reference to the Recipient<Remove>
    pub fn remove_recipient(&self) -> &Recipient<Remove> {
        &self.remove
    }

    /// Get a reference to the Recipient<Insert>
    pub fn insert_recipient(&self) -> &Recipient<Insert> {
        &self.insert
    }

    /// Get a reference to the Recipient<InsertSync>
    pub fn insert_sync_recipient(&self) -> &Recipient<InsertSync> {
        &self.insert_sync
    }

    /// Get a clone of the scope bytes
    pub fn scope_bytes(&self) -> &[u8] {
        &self.scope
    }

    /// Changes the scope for the data store.
    /// Non-leading segments get a `/` separator; leading `/` on a segment is preserved.
    /// Example: `base("//foo").scope("bar").scope("/baz")` → `"//foo/bar/baz"`.
    pub fn scope<K: IntoKey>(&self, key: K) -> Self {
        let mut scope = self.scope.clone();
        let encoded_key = key.into_key();
        if !encoded_key.starts_with(b"/") {
            scope.extend("/".into_key());
        }
        scope.extend(encoded_key);
        Self {
            addr: self.addr.clone(),
            get: self.get.clone(),
            insert: self.insert.clone(),
            insert_sync: self.insert_sync.clone(),
            remove: self.remove.clone(),
            scope,
            flush: self.flush.clone(),
        }
    }

    pub fn base<K: IntoKey>(&self, key: K) -> Self {
        Self {
            addr: self.addr.clone(),
            get: self.get.clone(),
            insert: self.insert.clone(),
            insert_sync: self.insert_sync.clone(),
            remove: self.remove.clone(),
            scope: key.into_key(),
            flush: self.flush.clone(),
        }
    }

    pub fn from_sled_store_with_buffer(
        addr: &Addr<SledStore>,
        snapshot_buffer: impl Into<Recipient<Insert>>,
    ) -> Self {
        println!("from_sled_store_with_buffer...");
        Self {
            addr: StoreAddr::Sled(addr.clone()),
            get: addr.clone().recipient(),
            insert: snapshot_buffer.into(),
            insert_sync: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
        }
    }

    pub fn from_in_mem_with_buffer(
        addr: &Addr<InMemStore>,
        snapshot_buffer: impl Into<Recipient<Insert>>,
    ) -> Self {
        Self {
            addr: StoreAddr::InMem(addr.clone()),
            get: addr.clone().recipient(),
            insert: snapshot_buffer.into(),
            insert_sync: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
        }
    }

    pub fn from_in_mem(addr: &Addr<InMemStore>) -> Self {
        Self {
            addr: StoreAddr::InMem(addr.clone()),
            get: addr.clone().recipient(),
            insert: addr.clone().recipient(),
            insert_sync: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
        }
    }

    pub fn from_sled_store(addr: &Addr<SledStore>) -> Self {
        Self {
            addr: StoreAddr::Sled(addr.clone()),
            get: addr.clone().recipient(),
            insert: addr.clone().recipient(),
            insert_sync: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
        }
    }
}

impl From<&Addr<SledStore>> for DataStore {
    fn from(addr: &Addr<SledStore>) -> Self {
        Self {
            addr: StoreAddr::Sled(addr.clone()),
            get: addr.clone().recipient(),
            insert: addr.clone().recipient(),
            insert_sync: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
        }
    }
}

impl From<&Addr<InMemStore>> for DataStore {
    fn from(addr: &Addr<InMemStore>) -> Self {
        Self {
            addr: StoreAddr::InMem(addr.clone()),
            get: addr.clone().recipient(),
            insert: addr.clone().recipient(),
            insert_sync: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::Actor;

    #[test]
    fn scope_normalizes_slashes() {
        actix::System::new().block_on(async {
            let addr = InMemStore::new(false).start();
            let store = DataStore::from(&addr);
            let scoped = store.base("//foo").scope("bar").scope("/baz");
            let scope = scoped.get_scope().expect("scope");
            assert_eq!(scope, "//foo/bar/baz");
        });
    }
}
