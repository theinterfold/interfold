// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{EffectKey, Step, Store, StoreError, Stored};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// A store in memory. Clones share the data, so dropping an engine and opening another on a clone
/// behaves like a crash and a restart.
#[derive(Clone, Default)]
pub struct MemoryStore(Arc<Mutex<Inner>>);

#[derive(Default)]
struct Inner {
    snapshot: Option<(u64, Vec<u8>)>,
    journal: BTreeMap<u64, Vec<u8>>,
    outbox: BTreeMap<EffectKey, Vec<u8>>,
}

impl MemoryStore {
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().expect("memory store lock")
    }
}

impl Store for MemoryStore {
    fn read(&self) -> Result<Stored, StoreError> {
        let inner = self.inner();
        let after = inner.snapshot.as_ref().map_or(0, |(seq, _)| *seq);
        Ok(Stored {
            snapshot: inner.snapshot.clone(),
            journal: inner
                .journal
                .range(after + 1..)
                .map(|(seq, bytes)| (*seq, bytes.clone()))
                .collect(),
            outbox: inner
                .outbox
                .iter()
                .map(|(key, bytes)| (*key, bytes.clone()))
                .collect(),
        })
    }

    fn commit(&mut self, step: Step) -> Result<(), StoreError> {
        let mut inner = self.inner();
        inner.journal.insert(step.seq, step.entry);
        inner.outbox.extend(step.effects);
        if let Some(key) = step.answers {
            inner.outbox.remove(&key);
        }
        if let Some(snapshot) = step.snapshot {
            inner.snapshot = Some((step.seq, snapshot));
        }
        Ok(())
    }

    fn acknowledge(&mut self, key: EffectKey) -> Result<(), StoreError> {
        self.inner().outbox.remove(&key);
        Ok(())
    }
}
