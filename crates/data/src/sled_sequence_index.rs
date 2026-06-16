// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::path::PathBuf;

use anyhow::{Context, Result};
use e3_events::SequenceIndex;
use sled::Tree;

use crate::sled_utils::{clear_all_caches, get_or_open_db_tree};

pub struct SledSequenceIndex {
    db: Tree,
}

impl SledSequenceIndex {
    pub fn new(path: &PathBuf, tree: &str) -> Result<Self> {
        let db = get_or_open_db_tree(path, tree)?;
        Ok(Self { db })
    }

    pub fn close_all_connections() {
        clear_all_caches()
    }
}

impl SequenceIndex for SledSequenceIndex {
    fn get(&self, key: u128) -> Result<Option<u64>> {
        self.db
            .get(key.to_be_bytes())
            .context(format!("Failed to fetch timestamp: {}", key))?
            .map(|v| Ok(u64::from_be_bytes(v.as_ref().try_into()?)))
            .transpose()
    }

    fn insert(&mut self, key: u128, value: u64) -> Result<()> {
        self.db
            .insert(key.to_be_bytes(), value.to_be_bytes().to_vec())
            .context(format!("Failed to insert key: {}", key))?;
        Ok(())
    }

    fn seek(&self, key: u128) -> Result<Option<u64>> {
        let key_bytes = key.to_be_bytes();
        self.db
            .range(key_bytes..)
            .next()
            .transpose()
            .context(format!("Failed to seek: {}", key))?
            .map(|(_, v)| Ok(u64::from_be_bytes(v.as_ref().try_into()?)))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn seek_finds_nearest_key_at_or_after_target() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let mut index = SledSequenceIndex::new(&path, "test_tree").unwrap();

        index.insert(100, 1).unwrap();
        index.insert(200, 2).unwrap();
        index.insert(300, 3).unwrap();

        // Before all keys (returns first)
        assert_eq!(index.seek(50).unwrap(), Some(1));

        // Exact matches
        assert_eq!(index.seek(100).unwrap(), Some(1));
        assert_eq!(index.seek(200).unwrap(), Some(2));
        assert_eq!(index.seek(300).unwrap(), Some(3));

        // Between keys (returns next)
        assert_eq!(index.seek(150).unwrap(), Some(2));
        assert_eq!(index.seek(250).unwrap(), Some(3));

        // After all keys
        assert_eq!(index.seek(999).unwrap(), None);
    }
}
