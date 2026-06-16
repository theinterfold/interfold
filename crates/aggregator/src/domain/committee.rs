// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::Address;
use anyhow::{anyhow, Result};
use e3_events::OrderedSet;
use std::collections::HashMap;
use std::str::FromStr;

/// Parse committee node strings from an [`OrderedSet`] (address-sorted iteration).
///
/// Prefer [`committee_addresses_in_party_order`] for ZK / on-chain committee-hash binding.
pub fn committee_addresses_from_nodes(nodes: &OrderedSet<String>) -> Result<Vec<Address>> {
    nodes
        .iter()
        .map(|s| {
            Address::from_str(s).map_err(|e| anyhow!("invalid committee node address {s}: {e}"))
        })
        .collect()
}

/// Build committee addresses in ascending `party_id` order (runtime score-sorted committee).
///
/// Must match `CommitteeHashLib.hash(c.topNodes)` after on-chain finalization sorts
/// `topNodes` by ascending ticket score.
pub fn committee_addresses_in_party_order(
    party_ids: &[u64],
    party_nodes: &HashMap<u64, String>,
) -> Result<Vec<Address>> {
    party_ids
        .iter()
        .map(|party_id| {
            let node = party_nodes
                .get(party_id)
                .ok_or_else(|| anyhow!("missing committee node for party_id {party_id}"))?;
            Address::from_str(node)
                .map_err(|e| anyhow!("invalid committee node address {node}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use e3_committee_hash::hash_committee_addresses;

    #[test]
    fn party_order_differs_from_address_sorted_set() {
        let party_nodes = HashMap::from([
            (
                0u64,
                "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc".to_string(),
            ),
            (
                1u64,
                "0x90F79bf6EB2c4f870365E785982E1f101E93b906".to_string(),
            ),
            (
                2u64,
                "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65".to_string(),
            ),
        ]);
        let party_ids = vec![0, 1, 2];

        let party_order = committee_addresses_in_party_order(&party_ids, &party_nodes).unwrap();
        let mut nodes = OrderedSet::new();
        for node in party_nodes.values() {
            nodes.insert(node.clone());
        }
        let address_order = committee_addresses_from_nodes(&nodes).unwrap();

        assert_ne!(party_order, address_order);
        assert_eq!(
            hash_committee_addresses(&party_order),
            hash_committee_addresses(&[
                address!("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"),
                address!("0x90F79bf6EB2c4f870365E785982E1f101E93b906"),
                address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
            ])
        );
    }
}
