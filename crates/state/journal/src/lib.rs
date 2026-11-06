// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The v2 node's durable store: the journal, the latest snapshot, and the outbox in one redb file.
//! Every commit is one fsynced redb transaction.

use e3_engine::{EffectKey, Step, Store, StoreError, Stored};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

const JOURNAL: TableDefinition<u64, &[u8]> = TableDefinition::new("journal");
const SNAPSHOT: TableDefinition<u64, &[u8]> = TableDefinition::new("snapshot");
const OUTBOX: TableDefinition<(u64, u32), &[u8]> = TableDefinition::new("outbox");

pub struct Journal {
    db: Database,
}

impl Journal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_tables(path.as_ref()).map_err(store_error)
    }

    fn open_tables(path: &Path) -> Result<Self, redb::Error> {
        let db = Database::create(path)?;
        // A read transaction cannot open a table that was never created.
        let txn = db.begin_write()?;
        txn.open_table(JOURNAL)?;
        txn.open_table(SNAPSHOT)?;
        txn.open_table(OUTBOX)?;
        txn.commit()?;
        Ok(Self { db })
    }

    fn read_tables(&self) -> Result<Stored, redb::Error> {
        let txn = self.db.begin_read()?;
        let snapshot = txn
            .open_table(SNAPSHOT)?
            .last()?
            .map(|(seq, bytes)| (seq.value(), bytes.value().to_vec()));
        let after = snapshot.as_ref().map_or(0, |(seq, _)| *seq);
        let journal = txn
            .open_table(JOURNAL)?
            .range(after + 1..)?
            .map(|entry| {
                let (seq, bytes) = entry?;
                Ok((seq.value(), bytes.value().to_vec()))
            })
            .collect::<Result<_, redb::StorageError>>()?;
        let outbox = txn
            .open_table(OUTBOX)?
            .iter()?
            .map(|entry| {
                let (key, bytes) = entry?;
                let (seq, index) = key.value();
                Ok((EffectKey { seq, index }, bytes.value().to_vec()))
            })
            .collect::<Result<_, redb::StorageError>>()?;
        Ok(Stored {
            snapshot,
            journal,
            outbox,
        })
    }

    fn commit_step(&self, step: Step) -> Result<(), redb::Error> {
        let txn = self.db.begin_write()?;
        let mut journal = txn.open_table(JOURNAL)?;
        journal.insert(step.seq, step.entry.as_slice())?;
        let mut outbox = txn.open_table(OUTBOX)?;
        for (key, bytes) in &step.effects {
            outbox.insert((key.seq, key.index), bytes.as_slice())?;
        }
        drop(outbox);
        if let Some(snapshot) = &step.snapshot {
            let mut snapshots = txn.open_table(SNAPSHOT)?;
            snapshots.retain(|_, _| false)?;
            snapshots.insert(step.seq, snapshot.as_slice())?;
            // The snapshot holds every step up to it, so no restart reads those entries again.
            journal.retain_in(..=step.seq, |_, _| false)?;
        }
        drop(journal);
        txn.commit()?;
        Ok(())
    }

    fn remove_effect(&self, key: EffectKey) -> Result<(), redb::Error> {
        let txn = self.db.begin_write()?;
        txn.open_table(OUTBOX)?.remove((key.seq, key.index))?;
        txn.commit()?;
        Ok(())
    }
}

impl Store for Journal {
    fn read(&self) -> Result<Stored, StoreError> {
        self.read_tables().map_err(store_error)
    }

    fn commit(&mut self, step: Step) -> Result<(), StoreError> {
        self.commit_step(step).map_err(store_error)
    }

    fn acknowledge(&mut self, key: EffectKey) -> Result<(), StoreError> {
        self.remove_effect(key).map_err(store_error)
    }
}

fn store_error(error: redb::Error) -> StoreError {
    StoreError(Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seq: u64, index: u32) -> EffectKey {
        EffectKey { seq, index }
    }

    #[test]
    fn a_reopened_file_holds_the_latest_snapshot_the_journal_after_it_and_pending_effects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.redb");
        let mut journal = Journal::open(&path).unwrap();
        journal
            .commit(Step {
                seq: 1,
                entry: b"a".to_vec(),
                effects: vec![(key(1, 0), b"x".to_vec())],
                snapshot: None,
            })
            .unwrap();
        journal
            .commit(Step {
                seq: 2,
                entry: b"b".to_vec(),
                effects: vec![(key(2, 0), b"y".to_vec())],
                snapshot: Some(b"state at 2".to_vec()),
            })
            .unwrap();
        journal
            .commit(Step {
                seq: 3,
                entry: b"c".to_vec(),
                effects: vec![(key(3, 0), b"z".to_vec())],
                snapshot: None,
            })
            .unwrap();
        journal.acknowledge(key(1, 0)).unwrap();
        drop(journal);

        let stored = Journal::open(&path).unwrap().read().unwrap();
        assert_eq!(stored.snapshot, Some((2, b"state at 2".to_vec())));
        assert_eq!(stored.journal, vec![(3, b"c".to_vec())]);
        assert_eq!(
            stored.outbox,
            vec![(key(2, 0), b"y".to_vec()), (key(3, 0), b"z".to_vec())]
        );
    }

    #[test]
    fn a_snapshot_drops_the_journal_entries_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.redb");
        let mut journal = Journal::open(&path).unwrap();
        for seq in 1..=5 {
            journal
                .commit(Step {
                    seq,
                    entry: vec![seq as u8],
                    effects: Vec::new(),
                    snapshot: (seq == 3).then(|| b"state at 3".to_vec()),
                })
                .unwrap();
        }
        let txn = journal.db.begin_read().unwrap();
        let kept: Vec<u64> = txn
            .open_table(JOURNAL)
            .unwrap()
            .iter()
            .unwrap()
            .map(|entry| entry.unwrap().0.value())
            .collect();
        assert_eq!(kept, [4, 5]);
    }
}
