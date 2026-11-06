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
    collections::{BTreeSet, HashMap},
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex, MutexGuard,
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
    /// Deletes the blobs of `e3` and refuses its later ones. A job or fetch can finish after its
    /// E3 ended, so a write under way finishes first and none outlives the deletion.
    fn close(&self, e3: E3Id) -> Result<(), BlobError>;
    /// Closes every E3 with blobs here that `keep` rejects.
    fn retain(&self, keep: impl Fn(&E3Id) -> bool) -> Result<(), BlobError>;

    fn of(&self, e3: E3Id) -> E3Blobs<Self> {
        E3Blobs {
            store: self.clone(),
            e3,
        }
    }
}

/// The blobs of one E3, for code that works on one.
pub trait Blobs: Sync {
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

/// The writes under way by E3, and the closed E3s, whose writes the store refuses for as long as
/// it runs: a job's blocking work can outlast any bound. A restart starts with no writer.
#[derive(Default)]
struct Closing {
    writes: Mutex<Writes>,
    finished: Condvar,
}

#[derive(Default)]
struct Writes {
    running: HashMap<E3Id, usize>,
    closed: BTreeSet<E3Id>,
}

impl Closing {
    fn lock(&self) -> MutexGuard<'_, Writes> {
        self.writes.lock().expect("no holder of the lock panics")
    }

    fn write<T>(
        &self,
        e3: E3Id,
        write: impl FnOnce() -> Result<T, BlobError>,
    ) -> Result<T, BlobError> {
        {
            let mut writes = self.lock();
            if writes.closed.contains(&e3) {
                return Err(BlobError::Deleted(e3));
            }
            *writes.running.entry(e3).or_default() += 1;
        }
        let _running = Running { closing: self, e3 };
        write()
    }

    fn close(&self, e3: E3Id) {
        let mut writes = self.lock();
        writes.closed.insert(e3);
        while writes.running.contains_key(&e3) {
            writes = self
                .finished
                .wait(writes)
                .expect("no holder of the lock panics");
        }
    }
}

/// A write under way, until it ends, even by a panic.
struct Running<'a> {
    closing: &'a Closing,
    e3: E3Id,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut writes = self.closing.lock();
        if let Some(running) = writes.running.get_mut(&self.e3) {
            *running -= 1;
            if *running == 0 {
                writes.running.remove(&self.e3);
            }
        }
        self.closing.finished.notify_all();
    }
}

/// Blobs in memory; clones share them.
#[derive(Clone, Default)]
pub struct MemoryBlobs {
    blobs: Arc<Mutex<HashMap<BlobKey, Vec<u8>>>>,
    closing: Arc<Closing>,
}

type BlobKey = (E3Id, B256);

impl MemoryBlobs {
    fn lock(&self) -> MutexGuard<'_, HashMap<BlobKey, Vec<u8>>> {
        self.blobs.lock().expect("no holder of the lock panics")
    }
}

impl BlobStore for MemoryBlobs {
    fn put(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        self.closing.write(e3, || {
            let blob = BlobRef::of(bytes);
            let mut blobs = self.lock();
            blobs
                .entry((e3, blob.hash))
                .or_insert_with(|| bytes.to_vec());
            Ok(blob)
        })
    }

    fn get(&self, e3: E3Id, blob: &BlobRef) -> Result<Vec<u8>, BlobError> {
        self.lock()
            .get(&(e3, blob.hash))
            .cloned()
            .ok_or(BlobError::Missing(*blob))
    }

    fn has(&self, e3: E3Id, blob: &BlobRef) -> bool {
        self.lock().contains_key(&(e3, blob.hash))
    }

    fn close(&self, e3: E3Id) -> Result<(), BlobError> {
        self.closing.close(e3);
        self.lock().retain(|(held, _), _| *held != e3);
        Ok(())
    }

    fn retain(&self, keep: impl Fn(&E3Id) -> bool) -> Result<(), BlobError> {
        let e3s: BTreeSet<E3Id> = self.lock().keys().map(|(e3, _)| *e3).collect();
        for e3 in e3s.into_iter().filter(|e3| !keep(e3)) {
            self.close(e3)?;
        }
        Ok(())
    }
}

/// Blobs as files, one directory per E3, each file named by its hash. A step that names a blob is
/// journaled after `put` returns, so `put` returns only once the file is complete on disk.
#[derive(Clone)]
pub struct FileBlobs {
    dir: PathBuf,
    closing: Arc<Closing>,
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
            closing: Arc::default(),
        })
    }

    fn e3_dir(&self, e3: E3Id) -> PathBuf {
        self.dir.join(format!("{}-{}", e3.chain_id, e3.number))
    }

    fn path(&self, e3: E3Id, hash: &B256) -> PathBuf {
        self.e3_dir(e3).join(hash.to_string())
    }

    fn write(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError> {
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
}

impl BlobStore for FileBlobs {
    fn put(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        self.closing.write(e3, || self.write(e3, bytes))
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

    fn close(&self, e3: E3Id) -> Result<(), BlobError> {
        self.closing.close(e3);
        match fs::remove_dir_all(self.e3_dir(e3)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
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
                Some(e3) if keep(&e3) => {}
                Some(e3) => self.close(e3)?,
                None if path.is_dir() => fs::remove_dir_all(path)?,
                None => fs::remove_file(path)?,
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

    /// An E3 can end before its first job stores anything.
    #[test]
    fn a_closed_e3_s_blobs_are_refused_even_before_its_first() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = FileBlobs::open(dir.path()).unwrap();
        blobs.put(e3(1), b"share").unwrap();
        blobs.close(e3(1)).unwrap();
        blobs.close(e3(2)).unwrap();
        for e3 in [e3(1), e3(2)] {
            assert!(matches!(blobs.put(e3, b"late"), Err(BlobError::Deleted(_))));
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// A job's blocking work can still be writing when its E3 ends.
    #[test]
    fn closing_waits_for_a_write_under_way() {
        use std::{sync::atomic::AtomicBool, sync::mpsc, thread, time::Duration};
        let closing = Arc::new(Closing::default());
        let (started, write_started) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let writer = thread::spawn({
            let closing = closing.clone();
            move || {
                closing.write(e3(1), || {
                    started.send(()).unwrap();
                    released.recv().unwrap();
                    Ok(())
                })
            }
        });
        write_started.recv().unwrap();
        let closed = Arc::new(AtomicBool::new(false));
        let closer = thread::spawn({
            let (closing, closed) = (closing.clone(), closed.clone());
            move || {
                closing.close(e3(1));
                closed.store(true, Ordering::SeqCst);
            }
        });
        thread::sleep(Duration::from_millis(200));
        assert!(!closed.load(Ordering::SeqCst));
        release.send(()).unwrap();
        writer.join().unwrap().unwrap();
        closer.join().unwrap();
        assert!(closed.load(Ordering::SeqCst));
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
