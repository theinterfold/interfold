// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::borrow::Cow;

use crate::{InMemStore, SledStore};
use actix::{Addr, Message, Recipient};
use anyhow::Context;
use anyhow::Result;
use anyhow::{anyhow, ensure};
use e3_events::IntoKey;
use e3_events::{
    Flush, FlushPendingSnapshots, Get, Insert, InsertBatch, InsertBatchIfAbsent, InsertSync,
    Remove, SnapshotBuffer,
};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Clone, Debug)]
pub enum StoreAddr {
    InMem(Addr<InMemStore>),
    Sled(Addr<SledStore>),
}

/// Flush and close the underlying store after every snapshot batch has been
/// acknowledged. This message is intentionally separate from the protocol
/// `Shutdown` event so storage remains available while actors persist their
/// final state.
#[derive(Message, Debug)]
#[rtype(result = "Result<()>")]
pub struct ShutdownStore;

#[derive(Message, Debug)]
#[rtype(result = "Result<bool>")]
pub(crate) struct StoreIsEmpty;

#[derive(Message, Debug)]
#[rtype(result = "Result<bool>")]
pub(crate) struct StoreHasExactKeys {
    keys: Vec<Vec<u8>>,
}

impl StoreHasExactKeys {
    fn new<K, I>(keys: I) -> Self
    where
        K: IntoKey,
        I: IntoIterator<Item = K>,
    {
        let mut keys = keys.into_iter().map(IntoKey::into_key).collect::<Vec<_>>();
        keys.sort();
        keys.dedup();
        Self { keys }
    }

    pub(crate) fn keys(&self) -> &[Vec<u8>] {
        &self.keys
    }
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
    insert_batch: Recipient<InsertBatch>,
    insert_batch_if_absent: Recipient<InsertBatchIfAbsent>,
    remove: Recipient<Remove>,
    flush: Recipient<Flush>,
    flush_pending_snapshots: Option<Recipient<FlushPendingSnapshots>>,
    shutdown: Recipient<ShutdownStore>,
}

impl DataStore {
    /// Return whether the complete backing key/value store contains no entries.
    ///
    /// This intentionally ignores the current scope: schema compatibility is a property of the
    /// whole physical store, not one repository prefix.
    pub async fn is_empty(&self) -> Result<bool> {
        match &self.addr {
            StoreAddr::InMem(store) => Ok(store.send(StoreIsEmpty).await??),
            StoreAddr::Sled(store) => Ok(store.send(StoreIsEmpty).await??),
        }
    }

    /// Return whether the complete backing store contains exactly `keys` and no others.
    ///
    /// This intentionally ignores the current scope. Callers use it for whole-store safety
    /// checks where allowing an unknown persisted key would be unsafe.
    pub async fn has_exact_keys<K, I>(&self, keys: I) -> Result<bool>
    where
        K: IntoKey,
        I: IntoIterator<Item = K>,
    {
        let message = StoreHasExactKeys::new(keys);
        match &self.addr {
            StoreAddr::InMem(store) => Ok(store.send(message).await??),
            StoreAddr::Sled(store) => Ok(store.send(message).await??),
        }
    }

    /// Read data at the scope location
    pub async fn read<T>(&self) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let Some(bytes) = self.get.send(Get::new(&self.scope)).await?? else {
            return Ok(None);
        };

        // If we get a null value return None as this doesn't deserialize correctly
        if bytes == [0] {
            return Ok(None);
        }
        Ok(Some(e3_utils::deserialize_exact(&bytes)?))
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
        self.flush.send(Flush).await??;
        Ok(())
    }

    fn serialize_batch<K, T, I>(&self, entries: I) -> Result<Vec<Insert>>
    where
        K: IntoKey,
        T: Serialize,
        I: IntoIterator<Item = (K, T)>,
    {
        entries
            .into_iter()
            .map(|(key, value)| {
                let scoped = self.scope(key);
                let serialized = bincode::serialize(&value).with_context(|| {
                    let key = scoped.get_scope().unwrap_or(Cow::Borrowed("<bad key>"));
                    anyhow!("Could not serialize batched value passed to {key}")
                })?;
                Ok(Insert::new(scoped.scope_bytes().to_vec(), serialized))
            })
            .collect()
    }

    /// Atomically write and flush a group of same-typed values under this store's scopes.
    pub async fn write_batch_sync<K, T, I>(&self, entries: I) -> Result<()>
    where
        K: IntoKey,
        T: Serialize,
        I: IntoIterator<Item = (K, T)>,
    {
        let inserts = self.serialize_batch(entries)?;
        ensure!(!inserts.is_empty(), "cannot write an empty storage batch");
        self.insert_batch.send(InsertBatch::new(inserts)).await??;
        self.flush.send(Flush).await??;
        Ok(())
    }

    /// Atomically write and flush a group only when every target scope is absent.
    pub async fn write_batch_if_absent_sync<K, T, I>(&self, entries: I) -> Result<bool>
    where
        K: IntoKey,
        T: Serialize,
        I: IntoIterator<Item = (K, T)>,
    {
        let inserts = self.serialize_batch(entries)?;
        ensure!(!inserts.is_empty(), "cannot write an empty storage batch");
        let inserted = self
            .insert_batch_if_absent
            .send(InsertBatchIfAbsent::new(inserts))
            .await??;
        if inserted {
            self.flush.send(Flush).await??;
        }
        Ok(inserted)
    }

    /// Drain the snapshot buffer and durably close the backing store.
    pub async fn shutdown(&self) -> Result<()> {
        if let Some(flush_pending) = &self.flush_pending_snapshots {
            flush_pending
                .send(FlushPendingSnapshots)
                .await
                .context("snapshot buffer stopped during shutdown")??;
        }
        self.shutdown
            .send(ShutdownStore)
            .await
            .context("data store stopped during shutdown")??;
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
            insert_batch: self.insert_batch.clone(),
            insert_batch_if_absent: self.insert_batch_if_absent.clone(),
            remove: self.remove.clone(),
            scope,
            flush: self.flush.clone(),
            flush_pending_snapshots: self.flush_pending_snapshots.clone(),
            shutdown: self.shutdown.clone(),
        }
    }

    pub fn base<K: IntoKey>(&self, key: K) -> Self {
        Self {
            addr: self.addr.clone(),
            get: self.get.clone(),
            insert: self.insert.clone(),
            insert_sync: self.insert_sync.clone(),
            insert_batch: self.insert_batch.clone(),
            insert_batch_if_absent: self.insert_batch_if_absent.clone(),
            remove: self.remove.clone(),
            scope: key.into_key(),
            flush: self.flush.clone(),
            flush_pending_snapshots: self.flush_pending_snapshots.clone(),
            shutdown: self.shutdown.clone(),
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
            insert_batch: addr.clone().recipient(),
            insert_batch_if_absent: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
            flush_pending_snapshots: None,
            shutdown: addr.clone().recipient(),
        }
    }

    pub fn from_sled_store_with_snapshot_buffer(
        addr: &Addr<SledStore>,
        snapshot_buffer: Addr<SnapshotBuffer>,
    ) -> Self {
        Self {
            addr: StoreAddr::Sled(addr.clone()),
            get: addr.clone().recipient(),
            insert: snapshot_buffer.clone().recipient(),
            insert_sync: addr.clone().recipient(),
            insert_batch: addr.clone().recipient(),
            insert_batch_if_absent: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
            flush_pending_snapshots: Some(snapshot_buffer.recipient()),
            shutdown: addr.clone().recipient(),
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
            insert_batch: addr.clone().recipient(),
            insert_batch_if_absent: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
            flush_pending_snapshots: None,
            shutdown: addr.clone().recipient(),
        }
    }

    pub fn from_in_mem_with_snapshot_buffer(
        addr: &Addr<InMemStore>,
        snapshot_buffer: Addr<SnapshotBuffer>,
    ) -> Self {
        Self {
            addr: StoreAddr::InMem(addr.clone()),
            get: addr.clone().recipient(),
            insert: snapshot_buffer.clone().recipient(),
            insert_sync: addr.clone().recipient(),
            insert_batch: addr.clone().recipient(),
            insert_batch_if_absent: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
            flush_pending_snapshots: Some(snapshot_buffer.recipient()),
            shutdown: addr.clone().recipient(),
        }
    }

    pub fn from_in_mem(addr: &Addr<InMemStore>) -> Self {
        Self {
            addr: StoreAddr::InMem(addr.clone()),
            get: addr.clone().recipient(),
            insert: addr.clone().recipient(),
            insert_sync: addr.clone().recipient(),
            insert_batch: addr.clone().recipient(),
            insert_batch_if_absent: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
            flush_pending_snapshots: None,
            shutdown: addr.clone().recipient(),
        }
    }

    pub fn from_sled_store(addr: &Addr<SledStore>) -> Self {
        Self {
            addr: StoreAddr::Sled(addr.clone()),
            get: addr.clone().recipient(),
            insert: addr.clone().recipient(),
            insert_sync: addr.clone().recipient(),
            insert_batch: addr.clone().recipient(),
            insert_batch_if_absent: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
            flush_pending_snapshots: None,
            shutdown: addr.clone().recipient(),
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
            insert_batch: addr.clone().recipient(),
            insert_batch_if_absent: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
            flush_pending_snapshots: None,
            shutdown: addr.clone().recipient(),
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
            insert_batch: addr.clone().recipient(),
            insert_batch_if_absent: addr.clone().recipient(),
            remove: addr.clone().recipient(),
            scope: vec![],
            flush: addr.clone().recipient(),
            flush_pending_snapshots: None,
            shutdown: addr.clone().recipient(),
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

    #[actix::test]
    async fn conditional_batch_write_is_all_or_nothing() -> Result<()> {
        let addr = InMemStore::new(false).start();
        let store = DataStore::from(&addr);
        store
            .scope("existing")
            .write_sync(b"original".to_vec())
            .await?;

        let inserted = store
            .write_batch_if_absent_sync([
                ("existing", b"replacement".to_vec()),
                ("missing", b"new".to_vec()),
            ])
            .await?;

        assert!(!inserted);
        assert_eq!(
            store.scope("existing").read::<Vec<u8>>().await?,
            Some(b"original".to_vec())
        );
        assert_eq!(store.scope("missing").read::<Vec<u8>>().await?, None);
        Ok(())
    }

    #[actix::test]
    async fn batch_write_persists_every_value() -> Result<()> {
        let addr = InMemStore::new(false).start();
        let store = DataStore::from(&addr);

        store
            .write_batch_sync([("first", vec![1_u8]), ("second", vec![2_u8])])
            .await?;

        assert_eq!(store.scope("first").read::<Vec<u8>>().await?, Some(vec![1]));
        assert_eq!(
            store.scope("second").read::<Vec<u8>>().await?,
            Some(vec![2])
        );
        Ok(())
    }
}
