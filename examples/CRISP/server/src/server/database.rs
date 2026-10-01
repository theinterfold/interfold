// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::repo::CRISP_KEY_PREFIX;
use async_trait::async_trait;
use e3_sdk::indexer::{DataStore, INDEXER_CURSOR_KEY};
use log::error;
use rand::{rng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use sled::{Db, Tree};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    str,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("SledDB error: {0}")]
    SledDB(#[from] sled::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Compaction(String),
}

/// Keys under this prefix hold ballot ciphertexts. A ciphertext is large and never changes.
pub const CIPHERTEXT_KEY_PREFIX: &str = "_e3:crisp_ciphertext:";

/// The server database.
///
/// When one key of a sled page changes, sled writes the complete page again after ten changes. A
/// large page goes to a file of its own, and sled keeps old copies until it cleans the log. The
/// indexer cursor changes with each block and the ballot ciphertexts are large, so each has a tree
/// of its own: a cursor update never writes a ballot again.
#[derive(Clone)]
pub struct SledDB {
    pub db: Db,
    ciphertexts: Tree,
    cursor: Tree,
    path: PathBuf,
}

impl SledDB {
    pub fn new(path: &str) -> Result<Self, DatabaseError> {
        let db = sled::open(path)?;
        let cursor = db.open_tree("indexer-cursor")?;
        // Copy a cursor from the default tree once. The old key stays: after a rollback, an older
        // release resumes from it instead of from the chain head, where it would skip events.
        if cursor.get(INDEXER_CURSOR_KEY)?.is_none() {
            if let Some(value) = db.get(INDEXER_CURSOR_KEY)? {
                cursor.insert(INDEXER_CURSOR_KEY, value)?;
            }
        }
        Ok(Self {
            ciphertexts: db.open_tree("crisp-ciphertexts")?,
            cursor,
            db,
            path: PathBuf::from(path),
        })
    }

    fn tree(&self, key: &str) -> &Tree {
        if key == INDEXER_CURSOR_KEY {
            &self.cursor
        } else if key.starts_with(CIPHERTEXT_KEY_PREFIX) {
            &self.ciphertexts
        } else {
            &self.db
        }
    }

    /// Write the database to the disk, with the files of its large values.
    pub fn sync_to_disk(&self) -> Result<(), DatabaseError> {
        sync_to_disk(&self.db, &self.path)
    }

    /// The IDs of the stored rounds.
    pub fn round_ids(&self) -> Result<Vec<String>, DatabaseError> {
        self.db
            .scan_prefix(CRISP_KEY_PREFIX)
            .keys()
            .map(|key| Ok(String::from_utf8_lossy(&key?[CRISP_KEY_PREFIX.len()..]).into_owned()))
            .collect()
    }
}

/// Write a database to the disk, with the files of its large values. `Db::flush` syncs only the
/// log: sled does not sync the file of a large value, and recovery skips a log entry whose file is
/// missing.
fn sync_to_disk(db: &Db, path: &Path) -> Result<(), DatabaseError> {
    db.flush()?;
    let blobs = path.join("blobs");
    for entry in fs::read_dir(&blobs)? {
        File::open(entry?.path())?.sync_all()?;
    }
    File::open(&blobs)?.sync_all()?;
    Ok(())
}

/// Copy a stopped server's database into a new directory, without the old page copies that sled
/// keeps on disk. The copy can still be up to about three times the size of the data. The copy
/// gets the name `to` only when it is complete, so a failed run never leaves a partial copy there.
pub fn compact_database(from: &str, to: &str) -> Result<(), DatabaseError> {
    let partial = format!("{}.partial", to.trim_end_matches('/'));
    // `sled::open` creates a missing database, so check the paths first. sled writes `conf` in
    // each database directory.
    let taken = |path: &str| Path::new(path).exists();
    if !Path::new(from).join("conf").is_file() || taken(to) || taken(&partial) {
        let refusal = format!("{from} must hold a database, and {to} and {partial} must not exist");
        return Err(DatabaseError::Compaction(refusal));
    }
    let database = sled::open(from)?;
    let copy = sled::open(&partial)?;
    copy.import(database.export());
    sync_to_disk(&copy, Path::new(&partial))?;
    if copy.checksum()? != database.checksum()? {
        let mismatch = format!("the copy in {partial} does not match {from}");
        return Err(DatabaseError::Compaction(mismatch));
    }
    // A closed sled database writes no more files, so the rename moves a complete copy.
    drop(copy);
    fs::rename(&partial, to)?;
    Ok(())
}

#[async_trait]
impl DataStore for SledDB {
    type Error = DatabaseError;
    async fn insert<T: Serialize + Send + Sync>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), Self::Error> {
        let serialized = serde_json::to_vec(value)?;
        self.tree(key).insert(key.as_bytes(), serialized)?;
        Ok(())
    }

    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, Self::Error> {
        if let Some(bytes) = self.tree(key).get(key.as_bytes())? {
            let value = serde_json::from_slice(&bytes)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    async fn modify<T, F>(&mut self, key: &str, mut f: F) -> Result<Option<T>, Self::Error>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
        F: FnMut(Option<T>) -> Option<T> + Send,
    {
        // Edit in place
        let result = self.tree(key).update_and_fetch(key, |old_bytes| {
            let current_value = old_bytes.and_then(|bytes| serde_json::from_slice(bytes).ok());
            let new_value = f(current_value);
            new_value.and_then(|val| serde_json::to_vec(&val).ok())
        })?;

        // Deserialize the final result
        result
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()
            .map_err(|e| e.into())
    }
}

pub fn generate_emoji() -> [String; 2] {
    let emojis = [
        "🍇", "🍈", "🍉", "🍊", "🍋", "🍌", "🍍", "🥭", "🍎", "🍏", "🍐", "🍑", "🍒", "🍓", "🫐",
        "🥝", "🍅", "🫒", "🥥", "🥑", "🍆", "🥔", "🥕", "🌽", "🌶️", "🫑", "🥒", "🥬", "🥦", "🧄",
        "🧅", "🍄", "🥜", "🫘", "🌰", "🍞", "🥐", "🥖", "🫓", "🥨", "🥯", "🥞", "🧇", "🧀", "🍖",
        "🍗", "🥩", "🥓", "🍔", "🍟", "🍕", "🌭", "🥪", "🌮", "🌯", "🫔", "🥙", "🧆", "🥚", "🍳",
        "🥘", "🍲", "🫕", "🥣", "🥗", "🍿", "🧈", "🧂", "🥫", "🍱", "🍘", "🍙", "🍚", "🍛", "🍜",
        "🍝", "🍠", "🍢", "🍣", "🍤", "🍥", "🥮", "🍡", "🥟", "🥠", "🥡", "🦀", "🦞", "🦐", "🦑",
        "🦪", "🍦", "🍧", "🍨", "🍩", "🍪", "🎂", "🍰", "🧁", "🥧", "🍫", "🍬", "🍭", "🍮", "🍯",
        "🍼", "🥛", "☕", "🍵", "🍾", "🍷", "🍸", "🍹", "🍺", "🍻", "🥂", "🥃",
    ];
    let mut index1 = rng().random_range(0..emojis.len());
    let index2 = rng().random_range(0..emojis.len());
    if index1 == index2 {
        if index1 == emojis.len() {
            index1 -= 1;
        } else {
            index1 += 1;
        };
    };
    [emojis[index1].to_string(), emojis[index2].to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::models::{CensusMode, CreditMode, CustomParams, E3Crisp};
    use crate::server::repo::CrispE3Repository;
    use e3_fhe_params::{build_bfv_params_from_set_arc, BfvParamSet, BfvPreset};
    use e3_sdk::indexer::SharedStore;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// A database directory that is removed when the guard drops.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = format!("crisp-database-test-{name}-{}", std::process::id());
            Self(std::env::temp_dir().join(dir))
        }

        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn size_on_disk(db: &Db) -> u64 {
        db.flush().unwrap();
        db.size_on_disk().unwrap()
    }

    /// A round as `E3Requested` records it.
    async fn requested_round(
        store: &SharedStore<SledDB>,
        e3_id: &str,
    ) -> CrispE3Repository<SledDB> {
        let mut round = CrispE3Repository::new(store.clone(), e3_id);
        let params = CustomParams {
            token_address: "0x0000000000000000000000000000000000000001".to_string(),
            balance_threshold: "1".to_string(),
            num_options: "2".to_string(),
            credit_mode: CreditMode::Constant,
            credits: Some("1".to_string()),
            census_mode: CensusMode::Token,
            voting_power_divisor: "0".to_string(),
        };
        round
            .initialize_round(params, "requester".to_string(), 100, 100, 1)
            .await
            .unwrap();
        round
    }

    /// A ballot reaches the disk a fixed number of times: as hex, and again when sled writes its
    /// page after ten changes. When the ballots and the round record shared a page with the cursor,
    /// sled wrote them all again for each ten blocks, and each new ballot wrote the earlier ones
    /// again.
    #[tokio::test]
    async fn disk_use_is_linear_in_ballots_and_flat_in_blocks() {
        const BALLOTS: u64 = 12;
        const BALLOT_BYTES: usize = 128 * 1024;
        let dir = TempDir::new("growth");
        let sled_db = SledDB::new(dir.path()).unwrap();
        let disk = sled_db.db.clone();
        let mut store = SharedStore::new(Arc::new(RwLock::new(sled_db)));
        let mut round = requested_round(&store, "1").await;
        let bfv = build_bfv_params_from_set_arc(BfvParamSet::from(BfvPreset::InsecureThreshold512));
        let start = size_on_disk(&disk);

        for index in 0..BALLOTS {
            let ballot = vec![index as u8; BALLOT_BYTES];
            round
                .insert_ciphertext_input(ballot, index, [0; 32], [1; 20], 0, &bfv)
                .await
                .unwrap();
        }
        let after_ballots = size_on_disk(&disk);
        // A census makes the round record large, as in a real round.
        let census = vec![format!("0x{}", "ab".repeat(32)); 16_000];
        round.set_token_holder_hashes(census).await.unwrap();
        let before_blocks = size_on_disk(&disk);
        for block in 0..100u64 {
            store.insert(INDEXER_CURSOR_KEY, &block).await.unwrap();
        }
        let after_blocks = size_on_disk(&disk);

        let ballot_bytes = BALLOTS * BALLOT_BYTES as u64;
        let for_ballots = after_ballots - start;
        assert!(
            for_ballots < 6 * ballot_bytes,
            "{for_ballots} bytes for {ballot_bytes}"
        );
        let for_blocks = after_blocks - before_blocks;
        assert!(
            for_blocks < ballot_bytes,
            "100 blocks added {for_blocks} bytes"
        );
    }

    /// An older release kept the indexer cursor in the default tree and each ballot inside its
    /// round record. Both must read the same after startup moves them: a lost cursor makes the
    /// indexer start again at the chain head and skip the events since it stopped.
    #[tokio::test]
    async fn an_upgrade_keeps_the_cursor_and_the_ballots() {
        let dir = TempDir::new("upgrade");
        {
            let sled_db = SledDB::new(dir.path()).unwrap();
            let cursor = serde_json::to_vec(&4_242u64).unwrap();
            sled_db.db.insert(INDEXER_CURSOR_KEY, cursor).unwrap();
            let mut store = SharedStore::new(Arc::new(RwLock::new(sled_db)));
            requested_round(&store, "5").await;
            let key = format!("{CRISP_KEY_PREFIX}5");
            let mut record: E3Crisp = store.get(&key).await.unwrap().unwrap();
            record.ciphertext_inputs = vec![(vec![2; 3], 1), (vec![1; 3], 0)];
            record.input_commitments = vec![(1, [2; 32]), (0, [1; 32])];
            record.input_slots = vec![(1, [7; 20]), (0, [7; 20])];
            record.input_parents = vec![(1, 1), (0, 0)];
            record.input_usable = vec![(1, true), (0, true)];
            store.insert(&key, &record).await.unwrap();
        }

        // The steps of the server startup.
        let sled_db = SledDB::new(dir.path()).unwrap();
        let round_ids = sled_db.round_ids().unwrap();
        let disk = sled_db.clone();
        let store = SharedStore::new(Arc::new(RwLock::new(sled_db)));
        for e3_id in round_ids {
            let mut round = CrispE3Repository::new(store.clone(), &e3_id);
            let sync = || Ok(disk.sync_to_disk()?);
            round.move_inline_ciphertexts(sync).await.unwrap();
        }

        let cursor = store.get::<u64>(INDEXER_CURSOR_KEY).await.unwrap();
        assert_eq!(cursor, Some(4_242));
        let round = CrispE3Repository::new(store, "5");
        let snapshot = round.get_input_snapshot().await.unwrap();
        assert_eq!(snapshot.ciphertexts, vec![(vec![1; 3], 0), (vec![2; 3], 1)]);
        let head = round.get_slot_head([7; 20]).await.unwrap();
        assert_eq!(head, Some((vec![2; 3], 1)));
    }
}
