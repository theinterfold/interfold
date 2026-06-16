// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure, actor-free in-memory key/value store.
//!
//! The live key/value map is backed by a persistent [`Hamt`] so that cheap,
//! structurally-shared snapshots can be taken without cloning the whole map.
//! The on-disk dump format produced by [`InMemKvStore::dump`] is intentionally
//! identical to the previous `BTreeMap`-based implementation (a bincode-encoded
//! `BTreeMap<Vec<u8>, Vec<u8>>`) so existing persisted dumps remain readable
//! across upgrades.

use anyhow::{Context, Result};
use e3_events::{Insert, Remove};
use e3_hamt::Hamt;
use std::collections::BTreeMap;

/// A captured mutation, used when the store is run in capture mode.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DataOp {
    Insert(Insert),
    Remove(Remove),
}

/// Pure in-memory key/value store. Contains no actix/IO dependencies and is
/// fully unit-testable. The owning actor performs all message handling and
/// delegates the actual storage logic here.
#[derive(Clone)]
pub struct InMemKvStore {
    db: Hamt<Vec<u8>, Vec<u8>>,
    log: Vec<DataOp>,
    capture: bool,
}

impl InMemKvStore {
    pub fn new(capture: bool) -> Self {
        Self {
            db: Hamt::new(),
            log: vec![],
            capture,
        }
    }

    /// Inserts a key/value pair, optionally recording the operation.
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>, op: Option<DataOp>) {
        self.db = self.db.insert(key, value);
        if self.capture {
            if let Some(op) = op {
                self.log.push(op);
            }
        }
    }

    /// Removes a key, optionally recording the operation.
    pub fn remove(&mut self, key: &[u8], op: Option<DataOp>) {
        self.db = self.db.remove(&key.to_vec());
        if self.capture {
            if let Some(op) = op {
                self.log.push(op);
            }
        }
    }

    /// Returns the value for `key`, if present.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.db.get(&key.to_vec()).cloned()
    }

    /// Returns the captured operation log.
    pub fn log(&self) -> Vec<DataOp> {
        self.log.clone()
    }

    /// Serializes the store to the bincode `BTreeMap` dump format.
    pub fn dump(&self) -> Result<Vec<u8>> {
        let map: BTreeMap<Vec<u8>, Vec<u8>> = self.db.entries().into_iter().collect();
        bincode::serialize(&map).context("Error serializing in-memory store")
    }

    /// Reconstructs a store from a bincode `BTreeMap` dump.
    pub fn from_dump(bytes: &[u8], capture: bool) -> Result<Self> {
        let map: BTreeMap<Vec<u8>, Vec<u8>> =
            bincode::deserialize(bytes).context("Error deserializing in-memory store")?;
        let mut db = Hamt::new();
        for (k, v) in map {
            db = db.insert(k, v);
        }
        Ok(Self {
            db,
            log: vec![],
            capture,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_remove() {
        let mut store = InMemKvStore::new(false);
        store.insert(b"a".to_vec(), b"1".to_vec(), None);
        store.insert(b"b".to_vec(), b"2".to_vec(), None);
        assert_eq!(Some(b"1".to_vec()), store.get(b"a"));
        assert_eq!(Some(b"2".to_vec()), store.get(b"b"));
        assert_eq!(None, store.get(b"missing"));

        store.remove(b"a", None);
        assert_eq!(None, store.get(b"a"));
        assert_eq!(Some(b"2".to_vec()), store.get(b"b"));
    }

    #[test]
    fn overwrite_updates_value() {
        let mut store = InMemKvStore::new(false);
        store.insert(b"k".to_vec(), b"v1".to_vec(), None);
        store.insert(b"k".to_vec(), b"v2".to_vec(), None);
        assert_eq!(Some(b"v2".to_vec()), store.get(b"k"));
    }

    #[test]
    fn capture_records_ops_only_when_enabled() {
        let insert = Insert::new(b"k".to_vec(), b"v".to_vec());
        let remove = Remove::new(b"k".to_vec());

        let mut off = InMemKvStore::new(false);
        off.insert(
            b"k".to_vec(),
            b"v".to_vec(),
            Some(DataOp::Insert(insert.clone())),
        );
        off.remove(b"k", Some(DataOp::Remove(remove.clone())));
        assert!(off.log().is_empty());

        let mut on = InMemKvStore::new(true);
        on.insert(
            b"k".to_vec(),
            b"v".to_vec(),
            Some(DataOp::Insert(insert.clone())),
        );
        on.remove(b"k", Some(DataOp::Remove(remove.clone())));
        assert_eq!(
            vec![DataOp::Insert(insert), DataOp::Remove(remove)],
            on.log()
        );
    }

    #[test]
    fn dump_roundtrip_preserves_data() {
        let mut store = InMemKvStore::new(false);
        store.insert(b"alpha".to_vec(), b"1".to_vec(), None);
        store.insert(b"beta".to_vec(), b"2".to_vec(), None);
        store.insert(b"gamma".to_vec(), b"3".to_vec(), None);

        let bytes = store.dump().unwrap();
        let restored = InMemKvStore::from_dump(&bytes, false).unwrap();
        assert_eq!(Some(b"1".to_vec()), restored.get(b"alpha"));
        assert_eq!(Some(b"2".to_vec()), restored.get(b"beta"));
        assert_eq!(Some(b"3".to_vec()), restored.get(b"gamma"));
    }

    #[test]
    fn dump_format_is_bincode_btreemap() {
        // The dump is a bincode-encoded BTreeMap of the store's entries.
        let mut store = InMemKvStore::new(false);
        store.insert(b"alpha".to_vec(), b"1".to_vec(), None);
        store.insert(b"beta".to_vec(), b"2".to_vec(), None);

        let mut reference: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        reference.insert(b"alpha".to_vec(), b"1".to_vec());
        reference.insert(b"beta".to_vec(), b"2".to_vec());

        assert_eq!(
            bincode::serialize(&reference).unwrap(),
            store.dump().unwrap()
        );
    }
}
