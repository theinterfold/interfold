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

    pub fn is_active_aggregator(&self, my_addr: &str, expelled: &[u64]) -> bool {
        (0..self.members.len() as u64)
            .find(|party_id| !expelled.contains(party_id))
            .and_then(|party_id| self.members.get(party_id as usize))
            .map(|addr| addr.eq_ignore_ascii_case(my_addr))
            .unwrap_or(false)
    }

    /// The party_id of the active aggregator given a set of `skipped` party_ids
    /// (the union of on-chain-expelled members and any locally presumed-down
    /// members during failover). Returns the lowest party_id not in `skipped`,
    /// or `None` if every member is skipped.
    ///
    /// Because the committee order is deterministic for all nodes and `skipped`
    /// is derived from shared signals, every node computes the same aggregator,
    /// so failover needs no leader-election protocol.
    pub fn active_aggregator_party_id(&self, skipped: &[u64]) -> Option<u64> {
        (0..self.members.len() as u64).find(|party_id| !skipped.contains(party_id))
    }

    /// Whether `my_addr` is the active aggregator once both on-chain-expelled and
    /// locally-presumed-unresponsive members are skipped. This is the failover
    /// generalisation of [`Self::is_active_aggregator`]: passing an empty
    /// `unresponsive` slice reproduces the original behaviour exactly.
    pub fn effective_aggregator(
        &self,
        my_addr: &str,
        expelled: &[u64],
        unresponsive: &[u64],
    ) -> bool {
        let skipped: Vec<u64> = expelled
            .iter()
            .chain(unresponsive.iter())
            .copied()
            .collect();
        self.active_aggregator_party_id(&skipped)
            .and_then(|party_id| self.members.get(party_id as usize))
            .map(|addr| addr.eq_ignore_ascii_case(my_addr))
            .unwrap_or(false)
    }

    /// Ordered standby list `[(party_id, address), ...]` of members eligible to
    /// take over aggregation, in promotion order, excluding `skipped` members.
    /// The first entry is the current active aggregator; subsequent entries are
    /// the standbys promoted in turn as predecessors are presumed down.
    pub fn aggregator_standbys(&self, skipped: &[u64], limit: usize) -> Vec<(u64, String)> {
        (0..self.members.len() as u64)
            .filter(|party_id| !skipped.contains(party_id))
            .take(limit)
            .filter_map(|party_id| {
                self.members
                    .get(party_id as usize)
                    .map(|addr| (party_id, addr.clone()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Committee;

    #[test]
    fn picks_lowest_non_expelled_party_in_sorted_committee_as_aggregator() {
        // Committee order is already score-sorted before it is stored.
        let committee = Committee::new(vec![
            "0xbbb".to_string(),
            "0xccc".to_string(),
            "0xaaa".to_string(),
        ]);

        assert!(committee.is_active_aggregator("0xBbB", &[]));
        assert!(committee.is_active_aggregator("0xccc", &[0]));
        assert!(committee.is_active_aggregator("0xaaa", &[0, 1]));
        assert!(!committee.is_active_aggregator("0xaaa", &[0, 1, 2]));
    }

    fn committee() -> Committee {
        Committee::new(vec![
            "0xbbb".to_string(),
            "0xccc".to_string(),
            "0xaaa".to_string(),
        ])
    }

    #[test]
    fn effective_aggregator_promotes_next_standby_when_primary_unresponsive() {
        let c = committee();
        assert!(c.effective_aggregator("0xbbb", &[], &[]));
        assert!(!c.effective_aggregator("0xccc", &[], &[]));

        // Primary (party 0) presumed unresponsive: party 1 (0xccc) takes over.
        assert!(!c.effective_aggregator("0xbbb", &[], &[0]));
        assert!(c.effective_aggregator("0xccc", &[], &[0]));

        // Expelled and unresponsive combine: 0 expelled, 1 unresponsive -> party 2.
        assert!(c.effective_aggregator("0xaaa", &[0], &[1]));
    }

    #[test]
    fn effective_aggregator_matches_legacy_when_no_unresponsive() {
        let c = committee();
        for (addr, expelled) in [
            ("0xbbb", &[][..]),
            ("0xccc", &[0][..]),
            ("0xaaa", &[0, 1][..]),
        ] {
            assert_eq!(
                c.effective_aggregator(addr, expelled, &[]),
                c.is_active_aggregator(addr, expelled),
            );
        }
    }

    #[test]
    fn active_aggregator_party_id_skips_in_order() {
        let c = committee();
        assert_eq!(c.active_aggregator_party_id(&[]), Some(0));
        assert_eq!(c.active_aggregator_party_id(&[0]), Some(1));
        assert_eq!(c.active_aggregator_party_id(&[0, 1]), Some(2));
        assert_eq!(c.active_aggregator_party_id(&[0, 1, 2]), None);
    }

    #[test]
    fn aggregator_standbys_are_ordered_and_filtered() {
        let c = committee();
        assert_eq!(
            c.aggregator_standbys(&[], 10),
            vec![
                (0, "0xbbb".to_string()),
                (1, "0xccc".to_string()),
                (2, "0xaaa".to_string()),
            ]
        );
        assert_eq!(
            c.aggregator_standbys(&[0], 10),
            vec![(1, "0xccc".to_string()), (2, "0xaaa".to_string())]
        );
        assert_eq!(
            c.aggregator_standbys(&[], 1),
            vec![(0, "0xbbb".to_string())]
        );
    }
}
