// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::repo::CRISP_KEY_PREFIX;
use async_trait::async_trait;
use e3_sdk::indexer::{DataStore, INDEXER_CURSOR_KEY};
use rand::{rng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use sled::{Db, Tree};
use std::{
    fmt::Display,
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
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

/// Keys under this prefix hold the input generation of a round, which changes with each indexed
/// input. The prefix does not start with `CRISP_KEY_PREFIX`, so `round_ids` does not list it.
pub const INPUT_GENERATION_KEY_PREFIX: &str = "_e3:crisp_inputs:";

/// Maps a store error to an error that names the failed action and the key.
pub(super) fn store_error<'a, E: Display>(
    what: &'a str,
    key: &'a str,
) -> impl FnOnce(E) -> eyre::Report + 'a {
    move |error| eyre::eyre!("Could not {what} at '{key}': {error}")
}

/// The server database.
///
/// When one key of a sled page changes, sled writes the complete page again after ten changes. A
/// large page goes to a file of its own, and sled keeps old copies until it cleans the log. The
/// indexer cursor changes with each block, the input generation of a round with each input, and
/// the ballot ciphertexts are large, so each has a tree of its own: a cursor or generation update
/// never writes a ballot or a round record again.
#[derive(Clone)]
pub struct SledDB {
    pub db: Db,
    ciphertexts: Tree,
    cursor: Tree,
    input_generations: Tree,
    path: PathBuf,
}

impl SledDB {
    pub fn new(path: &str) -> Result<Self, DatabaseError> {
        Self::open(sled::open(path)?, PathBuf::from(path))
    }

    /// The database over a sled handle that the caller opened, such as a temporary one, with the
    /// trees that `new` opens.
    #[cfg(test)]
    pub fn from_db(db: Db) -> Result<Self, DatabaseError> {
        Self::open(db, PathBuf::new())
    }

    fn open(db: Db, path: PathBuf) -> Result<Self, DatabaseError> {
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
            input_generations: db.open_tree("crisp-input-generations")?,
            db,
            path,
        })
    }

    fn tree(&self, key: &str) -> &Tree {
        if key == INDEXER_CURSOR_KEY {
            &self.cursor
        } else if key.starts_with(CIPHERTEXT_KEY_PREFIX) {
            &self.ciphertexts
        } else if key.starts_with(INPUT_GENERATION_KEY_PREFIX) {
            &self.input_generations
        } else {
            &self.db
        }
    }

    /// Write the database to the disk, with the files of its large values. `Db::flush` syncs only
    /// the log. sled never syncs the file of a large value, and recovery skips a log entry whose
    /// file is missing, so this also syncs every file in `blobs/` and the directory. The sync
    /// covers the files that exist when it runs. sled can later write a page again into a new file
    /// that the sync does not cover, as it can for every large value that the server stores.
    pub fn sync_to_disk(&self) -> Result<(), DatabaseError> {
        self.db.flush()?;
        sync_directory(&self.path.join("blobs"))
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

/// Sync every regular file in a directory, then the directory itself. sled removes the file of a
/// large value when a newer file replaces it, so a file that is gone before its sync is skipped.
/// A missing directory holds no files to sync.
fn sync_directory(dir: &Path) -> Result<(), DatabaseError> {
    let entries = match fs::read_dir(dir) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        entries => entries?,
    };
    for entry in entries {
        let synced = entry.and_then(|entry| {
            if entry.file_type()?.is_file() {
                File::open(entry.path())?.sync_all()
            } else {
                Ok(())
            }
        });
        match synced {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            synced => synced?,
        }
    }
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Copy a stopped server's database into a new directory, without the old page copies that sled
/// keeps on disk. The copy can still be up to about three times the size of the data. The copy
/// gets the name `to` only when it is complete and on the disk, so a failed run or a crash never
/// leaves a partial copy there.
pub fn compact_database(from: &str, to: &str) -> Result<(), DatabaseError> {
    let partial = format!("{}.partial", to.trim_end_matches('/'));
    // `sled::open` creates a missing database, with any missing parent directory, so check the
    // paths first. sled writes `conf` in each database directory. The directory that holds `to`
    // must exist: a directory that sled creates here is not synced into its own parent.
    let parent = Path::new(to)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let taken = |path: &str| Path::new(path).exists();
    if !Path::new(from).join("conf").is_file() || !parent.is_dir() || taken(to) || taken(&partial) {
        let refusal = format!(
            "{from} must hold a database, {} must exist, and {to} and {partial} must not exist",
            parent.display()
        );
        return Err(DatabaseError::Compaction(refusal));
    }
    let database = sled::open(from)?;
    let copy = sled::open(&partial)?;
    copy.import(database.export());
    if copy.checksum()? != database.checksum()? {
        let mismatch = format!("the copy in {partial} does not match {from}");
        return Err(DatabaseError::Compaction(mismatch));
    }
    // A drop only logs a failed flush, so flush the copy first: its log is then on the disk, and a
    // failure stops the command. A closed sled database creates no more files, so the syncs below
    // cover the complete copy. sled syncs neither the files of large values nor `conf` nor the
    // directories.
    copy.flush()?;
    drop(copy);
    drop(database);
    let partial_dir = Path::new(&partial);
    sync_directory(&partial_dir.join("blobs"))?;
    sync_directory(partial_dir)?;
    fs::rename(partial_dir, to)?;
    // The rename is durable only when the directory that holds `to` is synced.
    File::open(parent)?.sync_all()?;
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

    /// A record that does not deserialize, or a result that does not serialize, stays as stored
    /// and fails the call. Treating it as absent would let `f` overwrite or delete the record.
    async fn modify<T, F>(&mut self, key: &str, mut f: F) -> Result<Option<T>, Self::Error>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
        F: FnMut(Option<T>) -> Option<T> + Send,
    {
        let mut failure = None;
        let result = self.tree(key).update_and_fetch(key, |old| {
            // sled can run this again after a lost compare-and-swap.
            failure = None;
            let current = match old.map(serde_json::from_slice).transpose() {
                Ok(current) => current,
                Err(error) => {
                    failure = Some(error);
                    return old.map(<[u8]>::to_vec);
                }
            };
            match f(current)
                .map(|value| serde_json::to_vec(&value))
                .transpose()
            {
                Ok(bytes) => bytes,
                Err(error) => {
                    failure = Some(error);
                    old.map(<[u8]>::to_vec)
                }
            }
        })?;
        if let Some(error) = failure {
            return Err(error.into());
        }
        Ok(result
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?)
    }
}

const EMOJIS: &[&str] = &[
    "🍇", "🍈", "🍉", "🍊", "🍋", "🍌", "🍍", "🥭", "🍎", "🍏", "🍐", "🍑", "🍒", "🍓", "🫐", "🥝",
    "🍅", "🫒", "🥥", "🥑", "🍆", "🥔", "🥕", "🌽", "🌶️", "🫑", "🥒", "🥬", "🥦", "🧄", "🧅", "🍄",
    "🥜", "🫘", "🌰", "🍞", "🥐", "🥖", "🫓", "🥨", "🥯", "🥞", "🧇", "🧀", "🍖", "🍗", "🥩", "🥓",
    "🍔", "🍟", "🍕", "🌭", "🥪", "🌮", "🌯", "🫔", "🥙", "🧆", "🥚", "🍳", "🥘", "🍲", "🫕", "🥣",
    "🥗", "🍿", "🧈", "🧂", "🥫", "🍱", "🍘", "🍙", "🍚", "🍛", "🍜", "🍝", "🍠", "🍢", "🍣", "🍤",
    "🍥", "🥮", "🍡", "🥟", "🥠", "🥡", "🦀", "🦞", "🦐", "🦑", "🦪", "🍦", "🍧", "🍨", "🍩", "🍪",
    "🎂", "🍰", "🧁", "🥧", "🍫", "🍬", "🍭", "🍮", "🍯", "🍼", "🥛", "☕", "🍵", "🍾", "🍷", "🍸",
    "🍹", "🍺", "🍻", "🥂", "🥃",
];

/// Two distinct indexes into `EMOJIS`: `first`, and the entry `1 + offset` places after it,
/// wrapped. `offset` is below `EMOJIS.len() - 1`, so the second index never equals the first.
fn distinct_pair(first: usize, offset: usize) -> (usize, usize) {
    (first, (first + 1 + offset) % EMOJIS.len())
}

pub fn generate_emoji() -> [String; 2] {
    let mut rng = rng();
    let first = rng.random_range(0..EMOJIS.len());
    let offset = rng.random_range(0..EMOJIS.len() - 1);
    let (first, second) = distinct_pair(first, offset);
    [EMOJIS[first].to_string(), EMOJIS[second].to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::models::{test_custom_params, E3Crisp};
    use crate::server::repo::CrispE3Repository;
    use alloy_primitives::Address;
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
        let params = test_custom_params();
        round
            .initialize_round(params, Address::ZERO, "requester".to_string(), 100, 100, 1)
            .await
            .unwrap();
        round
    }

    /// A ballot reaches the disk a fixed number of times: as hex, and again when sled writes its
    /// page after ten changes. The cursor, the round record, and the ballots sit in separate
    /// trees, so a block never writes a ballot again and a new ballot never writes the earlier
    /// ones again.
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

    /// sled creates a missing parent directory of the copy, and nothing syncs that directory into
    /// its own parent. The command refuses such a target before it creates anything.
    #[test]
    fn compaction_refuses_a_target_whose_directory_is_missing() {
        let source = TempDir::new("compact-source");
        drop(SledDB::new(source.path()).unwrap());
        let missing = TempDir::new("compact-missing");
        let to = format!("{}/copy", missing.path());

        let refused = compact_database(source.path(), &to);

        assert!(
            matches!(refused, Err(DatabaseError::Compaction(_))),
            "{refused:?}"
        );
        assert!(!Path::new(missing.path()).exists());
    }

    /// A record that does not parse is not absent: `modify` keeps its bytes and fails, so the
    /// closure cannot overwrite or delete it.
    #[tokio::test]
    async fn modify_keeps_a_record_that_does_not_parse() {
        let mut db = SledDB::from_db(sled::Config::new().temporary(true).open().unwrap()).unwrap();
        let key = "_e3:round_index";
        db.db.insert(key, b"not json".as_slice()).unwrap();

        let modified = db
            .modify(key, |ids: Option<Vec<u64>>| Some(ids.unwrap_or_default()))
            .await;
        assert!(matches!(modified, Err(DatabaseError::Serialization(_))));
        let kept = db.db.get(key).unwrap().unwrap();
        assert_eq!(kept.as_ref(), b"not json");

        let deleted = db.modify(key, |_: Option<Vec<u64>>| None).await;
        assert!(deleted.is_err());
        assert!(db.db.get(key).unwrap().is_some());
    }

    #[test]
    fn the_two_emojis_of_a_round_are_never_the_same_entry() {
        for first in 0..EMOJIS.len() {
            for offset in 0..EMOJIS.len() - 1 {
                let (first, second) = distinct_pair(first, offset);
                assert_ne!(first, second);
                assert!(second < EMOJIS.len());
            }
        }
    }
}
