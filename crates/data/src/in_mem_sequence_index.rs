// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_events::SequenceIndex;
use std::collections::BTreeMap;

pub struct InMemSequenceIndex {
    index: BTreeMap<u128, u64>,
}

impl Default for InMemSequenceIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemSequenceIndex {
    pub fn new() -> Self {
        Self {
            index: BTreeMap::new(),
        }
    }
}

impl SequenceIndex for InMemSequenceIndex {
    fn seek(&self, key: u128) -> Result<Option<u64>> {
        Ok(self.index.range(key..).next().map(|(_, &v)| v))
    }

    fn insert(&mut self, key: u128, value: u64) -> Result<()> {
        self.index.insert(key, value);
        Ok(())
    }

    fn get(&self, key: u128) -> Result<Option<u64>> {
        Ok(self.index.get(&key).copied())
    }
}

#[cfg(test)]
mod tests {
    use crate::InMemSequenceIndex;
    use e3_events::SequenceIndex;

    #[test]
    fn seek_finds_nearest_key_at_or_after_target() {
        let mut index = InMemSequenceIndex::new();
        index.insert(100, 1).unwrap();
        index.insert(200, 2).unwrap();
        index.insert(300, 3).unwrap();

        assert_eq!(index.seek(50).unwrap(), Some(1));

        // Exact matches
        assert_eq!(index.seek(100).unwrap(), Some(1));
        assert_eq!(index.seek(200).unwrap(), Some(2));
        assert_eq!(index.seek(300).unwrap(), Some(3));

        // Between keys (returns next)
        assert_eq!(index.seek(150).unwrap(), Some(2));
        assert_eq!(index.seek(250).unwrap(), Some(3));

        assert_eq!(index.seek(999).unwrap(), None);
    }
}
