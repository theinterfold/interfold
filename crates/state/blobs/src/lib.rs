// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bytes stored once and named by their Keccak-256 hash. The chain adapter stores published
//! ciphertexts, the network adapter what peers send, and the job runner what it makes; the
//! protocol only holds references.

use alloy_primitives::B256;
use e3_protocol::BlobRef;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("blob {0:?} is not in the store")]
    Missing(BlobRef),
    #[error("blob store: {0}")]
    Io(#[from] io::Error),
}

pub trait Blobs {
    fn put(&self, bytes: &[u8]) -> Result<BlobRef, BlobError>;
    fn get(&self, blob: &BlobRef) -> Result<Vec<u8>, BlobError>;
}

/// Blobs in memory; clones share them.
#[derive(Clone, Default)]
pub struct MemoryBlobs(Arc<Mutex<HashMap<B256, Vec<u8>>>>);

impl Blobs for MemoryBlobs {
    fn put(&self, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        let blob = BlobRef::of(bytes);
        let mut blobs = self.0.lock().expect("no holder of the lock panics");
        blobs.entry(blob.hash).or_insert_with(|| bytes.to_vec());
        Ok(blob)
    }

    fn get(&self, blob: &BlobRef) -> Result<Vec<u8>, BlobError> {
        let blobs = self.0.lock().expect("no holder of the lock panics");
        blobs
            .get(&blob.hash)
            .cloned()
            .ok_or(BlobError::Missing(*blob))
    }
}

/// Blobs as files in one directory, each named by its hash. A step that names a blob is journaled
/// after `put` returns, so `put` returns only once the file is complete on disk.
#[derive(Clone)]
pub struct FileBlobs {
    dir: PathBuf,
}

impl FileBlobs {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, BlobError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, hash: &B256) -> PathBuf {
        self.dir.join(hash.to_string())
    }
}

impl Blobs for FileBlobs {
    fn put(&self, bytes: &[u8]) -> Result<BlobRef, BlobError> {
        let blob = BlobRef::of(bytes);
        let path = self.path(&blob.hash);
        if path.exists() {
            return Ok(blob);
        }
        // A crash leaves at most a partial file under a name no blob has.
        let partial = path.with_extension("partial");
        let mut file = File::create(&partial)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&partial, &path)?;
        File::open(&self.dir)?.sync_all()?;
        Ok(blob)
    }

    fn get(&self, blob: &BlobRef) -> Result<Vec<u8>, BlobError> {
        match fs::read(self.path(&blob.hash)) {
            Ok(bytes) => Ok(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(BlobError::Missing(*blob)),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_blob_reads_back_after_the_store_is_opened_again() {
        let dir = tempfile::tempdir().unwrap();
        let blob = FileBlobs::open(dir.path()).unwrap().put(b"share").unwrap();
        let reopened = FileBlobs::open(dir.path()).unwrap();
        assert_eq!(reopened.get(&blob).unwrap(), b"share");
        let other = BlobRef::of(b"other");
        assert!(
            matches!(reopened.get(&other), Err(BlobError::Missing(missing)) if missing == other)
        );
    }
}
