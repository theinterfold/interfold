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
    sync::{Arc, Mutex},
};

#[derive(Debug, thiserror::Error)]
#[error("blob {0:?} is not in the store")]
pub struct MissingBlob(pub BlobRef);

pub trait Blobs {
    fn put(&self, bytes: &[u8]) -> BlobRef;
    fn get(&self, blob: &BlobRef) -> Result<Vec<u8>, MissingBlob>;
}

/// Blobs in memory; clones share them.
#[derive(Clone, Default)]
pub struct MemoryBlobs(Arc<Mutex<HashMap<B256, Vec<u8>>>>);

impl Blobs for MemoryBlobs {
    fn put(&self, bytes: &[u8]) -> BlobRef {
        let blob = BlobRef::of(bytes);
        let mut blobs = self.0.lock().expect("no holder of the lock panics");
        blobs.entry(blob.hash).or_insert_with(|| bytes.to_vec());
        blob
    }

    fn get(&self, blob: &BlobRef) -> Result<Vec<u8>, MissingBlob> {
        let blobs = self.0.lock().expect("no holder of the lock panics");
        blobs.get(&blob.hash).cloned().ok_or(MissingBlob(*blob))
    }
}
