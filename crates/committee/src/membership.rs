// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Ordered list of committee members where index == party_id.
///
/// Provides O(1) address→party_id lookups via an internal index.
/// The index is eagerly rebuilt when the struct is deserialized.
///
/// `PartialEq` compares only the `members` vec (the canonical data);
/// the `index` is a derived cache.
#[derive(Clone, Debug, Serialize)]
pub struct Committee {
    /// Ordered member list — index == party_id.
    members: Vec<String>,
    /// Lowercased-address → party_id for O(1) lookup.
    #[serde(skip)]
    index: HashMap<String, u64>,
}

impl PartialEq for Committee {
    fn eq(&self, other: &Self) -> bool {
        self.members == other.members
    }
}

impl Eq for Committee {}

impl<'de> Deserialize<'de> for Committee {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Inner {
            members: Vec<String>,
        }
        let inner = Inner::deserialize(deserializer)?;
        Ok(Committee::new(inner.members))
    }
}

impl Committee {
    pub fn new(members: Vec<String>) -> Self {
        let index = members
            .iter()
            .enumerate()
            .map(|(i, addr)| (addr.to_lowercase(), i as u64))
            .collect();

        Self { members, index }
    }

    /// Resolve an address to its party_id (position in the committee list).
    pub fn party_id_for(&self, addr: &str) -> Option<u64> {
        self.index.get(&addr.to_lowercase()).copied()
    }

    /// Check if an address is a committee member.
    pub fn contains(&self, addr: &str) -> bool {
        self.party_id_for(addr).is_some()
    }

    /// The ordered member list (index == party_id).
    pub fn members(&self) -> &[String] {
        &self.members
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_bytes_rebuild_lookup_without_sorting_or_serializing_the_cache() {
        // Encoded by e3-events::Committee at 26023af50 before extraction.
        let hex = "04000000000000000500000000000000307842624205000000000000003078616161050000000000000030786242620200000000000000c4b0";
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let c: Committee = bincode::deserialize(&bytes).unwrap();
        assert_eq!(c.members(), ["0xBbB", "0xaaa", "0xbBb", "İ"]);
        assert_eq!(c.party_id_for("0xBBB"), Some(2));
        assert_eq!(c.party_id_for("i\u{307}"), Some(3));
        assert!(c.contains("0xAAA"));
        assert_eq!(c.party_id_for("missing"), None);
        assert_eq!(c.len(), 4);
        assert!(!c.is_empty());
        assert_eq!(bincode::serialize(&c).unwrap(), bytes);
        let json = serde_json::json!({"members": ["0xBbB", "0xaaa", "0xbBb", "İ"]});
        assert_eq!(serde_json::to_value(&c).unwrap(), json);
        let from_json: Committee = serde_json::from_value(json).unwrap();
        assert_eq!(from_json, c);
        assert_eq!(from_json.party_id_for("0xBBB"), Some(2));
        let empty = Committee::new(vec![]);
        assert!(empty.is_empty());
        assert!(!empty.contains("0xaaa"));
    }
}
