// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::JobError;
use alloy_primitives::B256;
use e3_protocol::BlobRef;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Bytes stored once and named by their Keccak-256 hash, shared with the network adapter, which
/// stores what peers send.
pub trait Blobs {
    fn put(&self, bytes: &[u8]) -> BlobRef;
    fn get(&self, blob: &BlobRef) -> Result<Vec<u8>, JobError>;
}

/// Blobs in memory; clones share them.
#[derive(Clone, Default)]
pub struct MemoryBlobs(Arc<Mutex<HashMap<B256, Vec<u8>>>>);

impl Blobs for MemoryBlobs {
    fn put(&self, bytes: &[u8]) -> BlobRef {
        let blob = BlobRef::of(bytes);
        let mut blobs = self
            .0
            .lock()
            .expect("no job panics while it holds the blobs");
        blobs.entry(blob.hash).or_insert_with(|| bytes.to_vec());
        blob
    }

    fn get(&self, blob: &BlobRef) -> Result<Vec<u8>, JobError> {
        let blobs = self
            .0
            .lock()
            .expect("no job panics while it holds the blobs");
        blobs
            .get(&blob.hash)
            .cloned()
            .ok_or(JobError::MissingBlob(*blob))
    }
}
