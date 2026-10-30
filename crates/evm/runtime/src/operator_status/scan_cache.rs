// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Saved progress of the committee obligation scan.
//!
//! One JSON file holds the scan of one operator in one bonding registry: the last block that the
//! scan read, the hash of that block when it was read, and the obligations that were open after
//! it. The file repeats its key, so a file of another deployment, of another format, or one that
//! does not parse is ignored, and the scan starts again from the deploy block.

use alloy::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// Version of the file format. A file of another version is ignored.
const FORMAT: u32 = 1;

/// The history that one saved scan covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ScanKey {
    pub(super) chain_id: u64,
    pub(super) bonding_registry: Address,
    /// First block of the scan: the deploy block of the bonding registry.
    pub(super) deploy_block: u64,
    pub(super) operator: Address,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct SavedScan {
    format: u32,
    key: ScanKey,
    /// Last block that the scan read.
    pub(super) block: u64,
    /// Hash of `block` when the scan read it.
    pub(super) block_hash: B256,
    /// Obligations open after `block`: the E3 ID, and the registry that opened the obligation.
    open: Vec<(U256, Address)>,
}

impl SavedScan {
    pub(super) fn new(
        key: &ScanKey,
        block: u64,
        block_hash: B256,
        open: &BTreeMap<U256, Address>,
    ) -> Self {
        Self {
            format: FORMAT,
            key: key.clone(),
            block,
            block_hash,
            open: open
                .iter()
                .map(|(e3_id, registry)| (*e3_id, *registry))
                .collect(),
        }
    }

    /// The saved scan of `key` in `dir`, or `None` when there is no usable file.
    pub(super) fn load(dir: &Path, key: &ScanKey) -> Option<Self> {
        let bytes = fs::read(file_path(dir, key)).ok()?;
        let saved: Self = serde_json::from_slice(&bytes).ok()?;
        (saved.format == FORMAT && saved.key == *key).then_some(saved)
    }

    /// Write the scan to `dir`. A reader sees the earlier file or this one, never a part of it.
    pub(super) fn save(&self, dir: &Path) -> io::Result<()> {
        // The daemon runs commands concurrently, so the temporary name is unique in the process
        // as well as across processes.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        fs::create_dir_all(dir)?;
        let path = file_path(dir, &self.key);
        let tmp = path.with_extension(format!(
            "{}.{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let written = serde_json::to_vec(self)
            .map_err(io::Error::from)
            .and_then(|bytes| fs::write(&tmp, bytes))
            .and_then(|()| fs::rename(&tmp, &path));
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written
    }

    pub(super) fn into_open(self) -> BTreeMap<U256, Address> {
        self.open.into_iter().collect()
    }
}

fn file_path(dir: &Path, key: &ScanKey) -> PathBuf {
    dir.join(format!(
        "committee-scan-{}-{:#x}-{:#x}.json",
        key.chain_id, key.bonding_registry, key.operator
    ))
}
