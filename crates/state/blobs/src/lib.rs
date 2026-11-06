// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bytes stored once per E3 and named by their Keccak-256 hash. The chain adapter stores published
//! ciphertexts, the network adapter what peers send, and the job runner what it makes; the
//! protocol only holds references. Each E3 keeps its own copy, so an E3's blobs can go when it
//! ends even if another E3 has the same bytes.

use alloy_primitives::{B256, U256};
use e3_protocol::{BlobRef, E3Id};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("blob {0:?} is not in the store")]
    Missing(BlobRef),
    #[error("the blobs of E3 {0} were deleted")]
    Deleted(E3Id),
    #[error("blob store: {0}")]
    Io(#[from] io::Error),
}

/// Blobs by the E3 whose work made or fetched them.
pub trait BlobStore: Clone + Send + Sync + 'static {
    fn put(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError>;
    fn get(&self, e3: E3Id, blob: &BlobRef) -> Result<Vec<u8>, BlobError>;
    fn has(&self, e3: E3Id, blob: &BlobRef) -> bool;
    /// Deletes the blobs of every E3 that `keep` rejects.
    fn retain(&self, keep: impl Fn(&E3Id) -> bool) -> Result<(), BlobError>;

    fn of(&self, e3: E3Id) -> E3Blobs<Self> {
        E3Blobs {
            store: self.clone(),
            e3,
        }
    }
}

/// The blobs of one E3, for code that works on one.
pub trait Blobs {
    fn put(&self, bytes: &[u8]) -> Result<BlobRef, BlobError>;
    fn get(&self, blob: &BlobRef) -> Result<Vec<u8>, BlobError>;
    fn has(&self, blob: &BlobRef) -> bool;
}

#[derive(Clone)]
pub struct E3Blobs<S> {
    store: S,
    e3: E3Id,
}

impl<S: BlobStore> Blobs for E3Blobs<S> {
    fn put(&self, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        self.store.put(self.e3, bytes)
    }

    fn get(&self, blob: &BlobRef) -> Result<Vec<u8>, BlobError> {
        self.store.get(self.e3, blob)
    }

    fn has(&self, blob: &BlobRef) -> bool {
        self.store.has(self.e3, blob)
    }
}

/// Blobs in memory; clones share them.
#[derive(Clone, Default)]
pub struct MemoryBlobs(Arc<Mutex<HashMap<BlobKey, Vec<u8>>>>);

type BlobKey = (E3Id, B256);

impl BlobStore for MemoryBlobs {
    fn put(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        let blob = BlobRef::of(bytes);
        let mut blobs = self.0.lock().expect("no holder of the lock panics");
        blobs
            .entry((e3, blob.hash))
            .or_insert_with(|| bytes.to_vec());
        Ok(blob)
    }

    fn get(&self, e3: E3Id, blob: &BlobRef) -> Result<Vec<u8>, BlobError> {
        let blobs = self.0.lock().expect("no holder of the lock panics");
        blobs
            .get(&(e3, blob.hash))
            .cloned()
            .ok_or(BlobError::Missing(*blob))
    }

    fn has(&self, e3: E3Id, blob: &BlobRef) -> bool {
        let blobs = self.0.lock().expect("no holder of the lock panics");
        blobs.contains_key(&(e3, blob.hash))
    }

    fn retain(&self, keep: impl Fn(&E3Id) -> bool) -> Result<(), BlobError> {
        let mut blobs = self.0.lock().expect("no holder of the lock panics");
        blobs.retain(|(e3, _), _| keep(e3));
        Ok(())
    }
}

/// Blobs as files, one directory per E3, each file named by its hash. A step that names a blob is
/// journaled after `put` returns, so `put` returns only once the file is complete on disk.
///
/// A job or fetch can finish after its E3 ended, so the store refuses to store blobs for an E3
/// whose blobs it deleted, instead of making its directory again.
#[derive(Clone)]
pub struct FileBlobs {
    dir: PathBuf,
    deleted: Arc<Mutex<Deleted>>,
}

/// The E3s whose blobs the store deleted lately.
#[derive(Default)]
struct Deleted {
    e3s: BTreeSet<E3Id>,
    order: VecDeque<E3Id>,
}

const DELETED_MEMORY: usize = 4_096;

impl Deleted {
    fn insert(&mut self, e3: E3Id) {
        if self.e3s.insert(e3) {
            self.order.push_back(e3);
        }
        while self.order.len() > DELETED_MEMORY {
            if let Some(oldest) = self.order.pop_front() {
                self.e3s.remove(&oldest);
            }
        }
    }
}

/// Numbers each write's partial file, so two writers of one blob never share one.
static WRITES: AtomicU64 = AtomicU64::new(0);

impl FileBlobs {
    /// Opens the store in `dir` and removes the partial files a crash left.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, BlobError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        for e3 in fs::read_dir(&dir)? {
            let e3 = e3?.path();
            if !e3.is_dir() {
                continue;
            }
            for entry in fs::read_dir(e3)? {
                let path = entry?.path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "partial")
                {
                    fs::remove_file(path)?;
                }
            }
        }
        Ok(Self {
            dir,
            deleted: Arc::default(),
        })
    }

    fn e3_dir(&self, e3: E3Id) -> PathBuf {
        self.dir.join(format!("{}-{}", e3.chain_id, e3.number))
    }

    fn path(&self, e3: E3Id, hash: &B256) -> PathBuf {
        self.e3_dir(e3).join(hash.to_string())
    }
}

impl BlobStore for FileBlobs {
    fn put(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        let deleted = self.deleted.lock().expect("no holder of the lock panics");
        if deleted.e3s.contains(&e3) {
            return Err(BlobError::Deleted(e3));
        }
        drop(deleted);
        let blob = BlobRef::of(bytes);
        let path = self.path(e3, &blob.hash);
        if path.exists() {
            return Ok(blob);
        }
        let dir = self.e3_dir(e3);
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
            File::open(&self.dir)?.sync_all()?;
        }
        let write = WRITES.fetch_add(1, Ordering::Relaxed);
        let partial = path.with_extension(format!("{}-{write}.partial", std::process::id()));
        let mut file = File::create(&partial)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&partial, &path)?;
        File::open(&dir)?.sync_all()?;
        Ok(blob)
    }

    fn get(&self, e3: E3Id, blob: &BlobRef) -> Result<Vec<u8>, BlobError> {
        match fs::read(self.path(e3, &blob.hash)) {
            Ok(bytes) => Ok(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(BlobError::Missing(*blob)),
            Err(error) => Err(error.into()),
        }
    }

    fn has(&self, e3: E3Id, blob: &BlobRef) -> bool {
        self.path(e3, &blob.hash).exists()
    }

    /// Also deletes anything in the store's directory that is not an E3's.
    fn retain(&self, keep: impl Fn(&E3Id) -> bool) -> Result<(), BlobError> {
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            let e3 = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.split_once('-'))
                .and_then(|(chain_id, number)| {
                    Some(E3Id {
                        chain_id: chain_id.parse().ok()?,
                        number: U256::from_str_radix(number, 10).ok()?,
                    })
                });
            match e3 {
                Some(e3) if keep(&e3) => continue,
                Some(e3) => self
                    .deleted
                    .lock()
                    .expect("no holder of the lock panics")
                    .insert(e3),
                None => {}
            }
            match path.is_dir() {
                true => fs::remove_dir_all(path)?,
                false => fs::remove_file(path)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e3(number: u64) -> E3Id {
        E3Id {
            chain_id: 1,
            number: U256::from(number),
        }
    }

    #[test]
    fn a_file_blob_reads_back_after_the_store_is_opened_again() {
        let dir = tempfile::tempdir().unwrap();
        let blob = FileBlobs::open(dir.path())
            .unwrap()
            .put(e3(1), b"share")
            .unwrap();
        let reopened = FileBlobs::open(dir.path()).unwrap();
        assert_eq!(reopened.get(e3(1), &blob).unwrap(), b"share");
        let other = BlobRef::of(b"other");
        assert!(
            matches!(reopened.get(e3(1), &other), Err(BlobError::Missing(missing)) if missing == other)
        );
    }

    /// Peers send the same blob at once: placeholder proofs of one kind have the same bytes.
    #[test]
    fn writers_of_the_same_blob_at_once_all_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = FileBlobs::open(dir.path()).unwrap();
        let bytes = vec![7u8; 64 * 1024];
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..20 {
                        let _ = fs::remove_file(blobs.path(e3(1), &BlobRef::of(&bytes).hash));
                        blobs.put(e3(1), &bytes).unwrap();
                    }
                });
            }
        });
        assert_eq!(blobs.get(e3(1), &BlobRef::of(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn a_blob_stored_after_its_e3_s_blobs_were_deleted_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = FileBlobs::open(dir.path()).unwrap();
        blobs.put(e3(1), b"share").unwrap();
        blobs.retain(|_| false).unwrap();
        assert!(matches!(
            blobs.put(e3(1), b"late"),
            Err(BlobError::Deleted(_))
        ));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// Placeholder proofs of one kind have the same bytes in every E3.
    #[test]
    fn an_ended_e3_s_blobs_go_and_another_e3_keeps_the_same_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = FileBlobs::open(dir.path()).unwrap();
        let blob = blobs.put(e3(1), b"proof").unwrap();
        blobs.put(e3(2), b"proof").unwrap();
        blobs.retain(|kept| *kept == e3(2)).unwrap();
        assert!(!blobs.has(e3(1), &blob));
        assert_eq!(blobs.get(e3(2), &blob).unwrap(), b"proof");
    }
}
