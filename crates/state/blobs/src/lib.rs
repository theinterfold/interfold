// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What a node stores for each E3, in three spaces. Public blobs are what messages carry, named by
//! their Keccak-256 hash: the only space a peer can read. Sealed secrets are encrypted with the
//! node's cipher, have their own reference type, and no network path reaches them. Kept values are
//! what a job saved to resume from after a restart. Each E3 keeps its own copy, so an E3's data can
//! go when it ends even if another E3 has the same bytes.

use alloy_primitives::{keccak256, B256, U256};
use e3_protocol::{BlobRef, E3Id, SealedRef};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex, MutexGuard,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("item {0} is not in the store")]
    Missing(B256),
    #[error("item {0} no longer held its bytes, so the store removed it")]
    Corrupt(B256),
    #[error("the blobs of E3 {0} were deleted")]
    Deleted(E3Id),
    #[error("blob store: {0}")]
    Io(#[from] io::Error),
}

/// What a node stores, by the E3 whose work made or fetched it.
pub trait BlobStore: Clone + Send + Sync + 'static {
    fn put(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError>;
    fn get(&self, e3: E3Id, blob: &BlobRef) -> Result<Vec<u8>, BlobError>;
    fn has(&self, e3: E3Id, blob: &BlobRef) -> bool;
    /// The public blob of `e3` with this hash, for a peer that asks. This is the only way out of
    /// the store for the network.
    fn serve(&self, e3: E3Id, hash: &B256) -> Option<Vec<u8>>;
    /// Stores bytes that the node's cipher already sealed.
    fn put_sealed(&self, e3: E3Id, bytes: &[u8]) -> Result<SealedRef, BlobError>;
    fn get_sealed(&self, e3: E3Id, secret: &SealedRef) -> Result<Vec<u8>, BlobError>;
    /// Saves a value a job can resume from under `key`; the value is complete on disk on return.
    fn keep(&self, e3: E3Id, key: &B256, value: &[u8]) -> Result<(), BlobError>;
    fn kept(&self, e3: E3Id, key: &B256) -> Result<Option<Vec<u8>>, BlobError>;
    /// Deletes everything of `e3` and refuses its later writes. A job or fetch can finish after
    /// its E3 ended, so a write under way finishes first and none outlives the deletion.
    fn close(&self, e3: E3Id) -> Result<(), BlobError>;
    /// Closes every E3 with data here that `keep` rejects.
    fn retain(&self, keep: impl Fn(&E3Id) -> bool) -> Result<(), BlobError>;

    fn of(&self, e3: E3Id) -> E3Blobs<Self> {
        E3Blobs {
            store: self.clone(),
            e3,
        }
    }
}

/// The store of one E3, for code that works on one.
pub trait Blobs: Sync {
    fn put(&self, bytes: &[u8]) -> Result<BlobRef, BlobError>;
    fn get(&self, blob: &BlobRef) -> Result<Vec<u8>, BlobError>;
    fn has(&self, blob: &BlobRef) -> bool;
    fn put_sealed(&self, bytes: &[u8]) -> Result<SealedRef, BlobError>;
    fn get_sealed(&self, secret: &SealedRef) -> Result<Vec<u8>, BlobError>;
    fn keep(&self, key: &B256, value: &[u8]) -> Result<(), BlobError>;
    fn kept(&self, key: &B256) -> Result<Option<Vec<u8>>, BlobError>;
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

    fn put_sealed(&self, bytes: &[u8]) -> Result<SealedRef, BlobError> {
        self.store.put_sealed(self.e3, bytes)
    }

    fn get_sealed(&self, secret: &SealedRef) -> Result<Vec<u8>, BlobError> {
        self.store.get_sealed(self.e3, secret)
    }

    fn keep(&self, key: &B256, value: &[u8]) -> Result<(), BlobError> {
        self.store.keep(self.e3, key, value)
    }

    fn kept(&self, key: &B256) -> Result<Option<Vec<u8>>, BlobError> {
        self.store.kept(self.e3, key)
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

/// The three spaces of a store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Space {
    Public,
    Sealed,
    Kept,
}

impl Space {
    const ALL: [Space; 3] = [Space::Public, Space::Sealed, Space::Kept];

    fn folder(self) -> &'static str {
        match self {
            Space::Public => "public",
            Space::Sealed => "sealed",
            Space::Kept => "kept",
        }
    }
}

/// Everything in memory; clones share it.
#[derive(Clone, Default)]
pub struct MemoryBlobs {
    items: Arc<Mutex<HashMap<ItemKey, Vec<u8>>>>,
    closing: Arc<Closing>,
}

type ItemKey = (E3Id, Space, B256);

impl MemoryBlobs {
    fn lock(&self) -> MutexGuard<'_, HashMap<ItemKey, Vec<u8>>> {
        self.items.lock().expect("no holder of the lock panics")
    }

    fn insert(&self, e3: E3Id, space: Space, name: B256, bytes: &[u8]) -> Result<(), BlobError> {
        self.closing.write(e3, || {
            self.lock()
                .entry((e3, space, name))
                .or_insert_with(|| bytes.to_vec());
            Ok(())
        })
    }

    fn read(&self, e3: E3Id, space: Space, name: &B256) -> Option<Vec<u8>> {
        self.lock().get(&(e3, space, *name)).cloned()
    }
}

impl BlobStore for MemoryBlobs {
    fn put(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        let blob = BlobRef::of(bytes);
        self.insert(e3, Space::Public, blob.hash, bytes)?;
        Ok(blob)
    }

    fn get(&self, e3: E3Id, blob: &BlobRef) -> Result<Vec<u8>, BlobError> {
        self.read(e3, Space::Public, &blob.hash)
            .ok_or(BlobError::Missing(blob.hash))
    }

    fn has(&self, e3: E3Id, blob: &BlobRef) -> bool {
        self.lock().contains_key(&(e3, Space::Public, blob.hash))
    }

    fn serve(&self, e3: E3Id, hash: &B256) -> Option<Vec<u8>> {
        self.read(e3, Space::Public, hash)
    }

    fn put_sealed(&self, e3: E3Id, bytes: &[u8]) -> Result<SealedRef, BlobError> {
        let secret = SealedRef::of(bytes);
        self.insert(e3, Space::Sealed, secret.hash, bytes)?;
        Ok(secret)
    }

    fn get_sealed(&self, e3: E3Id, secret: &SealedRef) -> Result<Vec<u8>, BlobError> {
        self.read(e3, Space::Sealed, &secret.hash)
            .ok_or(BlobError::Missing(secret.hash))
    }

    fn keep(&self, e3: E3Id, key: &B256, value: &[u8]) -> Result<(), BlobError> {
        self.closing.write(e3, || {
            self.lock().insert((e3, Space::Kept, *key), value.to_vec());
            Ok(())
        })
    }

    fn kept(&self, e3: E3Id, key: &B256) -> Result<Option<Vec<u8>>, BlobError> {
        Ok(self.read(e3, Space::Kept, key))
    }

    fn close(&self, e3: E3Id) -> Result<(), BlobError> {
        self.closing.close(e3);
        self.lock().retain(|(held, _, _), _| *held != e3);
        Ok(())
    }

    fn retain(&self, keep: impl Fn(&E3Id) -> bool) -> Result<(), BlobError> {
        let e3s: BTreeSet<E3Id> = self.lock().keys().map(|(e3, _, _)| *e3).collect();
        for e3 in e3s.into_iter().filter(|e3| !keep(e3)) {
            self.close(e3)?;
        }
        Ok(())
    }
}

/// Files, one directory per E3 with one folder per space, each file named by its hash or key. A
/// step that names an item is journaled after the write returns, so a write returns only once the
/// file is complete on disk.
#[derive(Clone)]
pub struct FileBlobs {
    dir: PathBuf,
    closing: Arc<Closing>,
}

/// Numbers each write's partial file, so two writers of one item never share one.
static WRITES: AtomicU64 = AtomicU64::new(0);

/// How many bytes of a kept file are the hash of its value.
const KEPT_CHECK: usize = 32;

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
            for space in Space::ALL {
                remove_partial_files(&e3.join(space.folder()))?;
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

    fn path(&self, e3: E3Id, space: Space, name: &B256) -> PathBuf {
        self.e3_dir(e3).join(space.folder()).join(name.to_string())
    }

    fn write(&self, e3: E3Id, space: Space, name: &B256, bytes: &[u8]) -> Result<(), BlobError> {
        let path = self.path(e3, space, name);
        let folder = path.parent().expect("an item's path has a folder");
        if !folder.exists() {
            fs::create_dir_all(folder)?;
            sync_dir(&self.e3_dir(e3))?;
            sync_dir(&self.dir)?;
        }
        let write = WRITES.fetch_add(1, Ordering::Relaxed);
        let partial = path.with_extension(format!("{}-{write}.partial", std::process::id()));
        let mut file = File::create(&partial)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&partial, &path)?;
        sync_dir(folder)?;
        Ok(())
    }

    /// The bytes named by their hash. A file that no longer holds them, as after a disk fault, is
    /// removed: the store then lacks the item, and a fetch can bring it again.
    fn read_named(&self, e3: E3Id, space: Space, hash: &B256) -> Result<Vec<u8>, BlobError> {
        let path = self.path(e3, space, hash);
        match fs::read(&path) {
            Ok(bytes) if keccak256(&bytes) == *hash => Ok(bytes),
            Ok(_) => {
                fs::remove_file(&path)?;
                Err(BlobError::Corrupt(*hash))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(BlobError::Missing(*hash)),
            Err(error) => Err(error.into()),
        }
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn remove_partial_files(folder: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(folder) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        entries => entries?,
    };
    for entry in entries {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "partial")
        {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

impl BlobStore for FileBlobs {
    fn put(&self, e3: E3Id, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        let blob = BlobRef::of(bytes);
        if !self.has(e3, &blob) {
            self.closing
                .write(e3, || self.write(e3, Space::Public, &blob.hash, bytes))?;
        }
        Ok(blob)
    }

    fn get(&self, e3: E3Id, blob: &BlobRef) -> Result<Vec<u8>, BlobError> {
        self.read_named(e3, Space::Public, &blob.hash)
    }

    /// Whether a file of the blob's length is here; `get` checks its bytes.
    fn has(&self, e3: E3Id, blob: &BlobRef) -> bool {
        fs::metadata(self.path(e3, Space::Public, &blob.hash))
            .is_ok_and(|file| file.len() == blob.len)
    }

    fn serve(&self, e3: E3Id, hash: &B256) -> Option<Vec<u8>> {
        self.read_named(e3, Space::Public, hash).ok()
    }

    fn put_sealed(&self, e3: E3Id, bytes: &[u8]) -> Result<SealedRef, BlobError> {
        let secret = SealedRef::of(bytes);
        self.closing
            .write(e3, || self.write(e3, Space::Sealed, &secret.hash, bytes))?;
        Ok(secret)
    }

    fn get_sealed(&self, e3: E3Id, secret: &SealedRef) -> Result<Vec<u8>, BlobError> {
        self.read_named(e3, Space::Sealed, &secret.hash)
    }

    fn keep(&self, e3: E3Id, key: &B256, value: &[u8]) -> Result<(), BlobError> {
        let file = [keccak256(value).as_slice(), value].concat();
        self.closing
            .write(e3, || self.write(e3, Space::Kept, key, &file))
    }

    /// A kept value that no longer matches its check, as after a disk fault, is gone: its job
    /// makes it again.
    fn kept(&self, e3: E3Id, key: &B256) -> Result<Option<Vec<u8>>, BlobError> {
        let path = self.path(e3, Space::Kept, key);
        let file = match fs::read(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        match file.split_at_checked(KEPT_CHECK) {
            Some((check, value)) if keccak256(value).as_slice() == check => {
                Ok(Some(value.to_vec()))
            }
            _ => {
                fs::remove_file(&path)?;
                Ok(None)
            }
        }
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

    fn public(blobs: &FileBlobs, blob: &BlobRef) -> PathBuf {
        blobs.path(e3(1), Space::Public, &blob.hash)
    }

    /// A peer that learned a secret's hash still gets nothing: serving reads the public space only.
    #[test]
    fn a_sealed_secret_cannot_be_served_even_by_its_hash() {
        let dir = tempfile::tempdir().unwrap();
        let files = FileBlobs::open(dir.path()).unwrap();
        let secret = files.put_sealed(e3(1), b"sealed key share").unwrap();
        assert_eq!(files.serve(e3(1), &secret.hash), None);
        assert_eq!(
            files.get_sealed(e3(1), &secret).unwrap(),
            b"sealed key share"
        );

        let memory = MemoryBlobs::default();
        let secret = memory.put_sealed(e3(1), b"sealed key share").unwrap();
        assert_eq!(memory.serve(e3(1), &secret.hash), None);
        assert_eq!(
            memory.get_sealed(e3(1), &secret).unwrap(),
            b"sealed key share"
        );
    }

    /// A node serves what it stored after a restart too, and nothing can push it out.
    #[test]
    fn a_public_blob_is_served_after_the_store_is_opened_again() {
        let dir = tempfile::tempdir().unwrap();
        let blob = FileBlobs::open(dir.path())
            .unwrap()
            .put(e3(1), b"proof")
            .unwrap();
        let reopened = FileBlobs::open(dir.path()).unwrap();
        assert_eq!(reopened.serve(e3(1), &blob.hash).unwrap(), b"proof");
        reopened.close(e3(1)).unwrap();
        assert_eq!(reopened.serve(e3(1), &blob.hash), None);
    }

    /// A job resumes from what it kept, and a value a disk fault changed reads as absent.
    #[test]
    fn a_kept_value_survives_a_restart_and_reads_as_absent_when_damaged() {
        let dir = tempfile::tempdir().unwrap();
        let key = B256::repeat_byte(7);
        let blobs = FileBlobs::open(dir.path()).unwrap();
        assert_eq!(blobs.kept(e3(1), &key).unwrap(), None);
        blobs.keep(e3(1), &key, b"finished proof").unwrap();
        let reopened = FileBlobs::open(dir.path()).unwrap();
        assert_eq!(
            reopened.kept(e3(1), &key).unwrap().as_deref(),
            Some(b"finished proof".as_slice())
        );
        fs::write(reopened.path(e3(1), Space::Kept, &key), b"damaged").unwrap();
        assert_eq!(reopened.kept(e3(1), &key).unwrap(), None);
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
            matches!(reopened.get(e3(1), &other), Err(BlobError::Missing(missing)) if missing == other.hash)
        );
    }

    /// A disk fault can change a stored file; the store gives no wrong bytes, and a put after the
    /// fault restores the blob.
    #[test]
    fn a_blob_whose_file_changed_reads_as_corrupt_then_missing_until_put_again() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = FileBlobs::open(dir.path()).unwrap();
        let blob = blobs.put(e3(1), b"share").unwrap();
        fs::write(public(&blobs, &blob), b"shark").unwrap();
        assert!(blobs.has(e3(1), &blob));
        assert!(
            matches!(blobs.get(e3(1), &blob), Err(BlobError::Corrupt(corrupt)) if corrupt == blob.hash)
        );
        assert!(!blobs.has(e3(1), &blob));
        assert!(matches!(
            blobs.get(e3(1), &blob),
            Err(BlobError::Missing(_))
        ));

        assert_eq!(blobs.put(e3(1), b"share").unwrap(), blob);
        assert_eq!(blobs.get(e3(1), &blob).unwrap(), b"share");
        fs::write(public(&blobs, &blob), b"sha").unwrap();
        assert!(!blobs.has(e3(1), &blob));
        blobs.put(e3(1), b"share").unwrap();
        assert_eq!(blobs.get(e3(1), &blob).unwrap(), b"share");
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
                        let _ = fs::remove_file(public(&blobs, &BlobRef::of(&bytes)));
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
