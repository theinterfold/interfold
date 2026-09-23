// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::ticket::{calculate_best_ticket_for_node, RegisteredNode, WinnerTicket};
use alloy::primitives::Address;
use anyhow::{Context, Result};
use e3_events::{E3id, Seed};
use std::collections::{hash_map::Entry, HashMap};

/// Calculate the buffer size for committee selection based on the threshold ratio.
///
/// This buffer allows backup nodes to submit tickets in case primary committee
/// members are unavailable or fail to submit.
///
/// # Formula
/// ```text
/// buffer = (threshold_n - threshold_m) + safety_margin
/// ```
///
/// Where safety_margin is determined by the threshold ratio:
/// - ratio >= 0.8: safety_margin = 3 (tight threshold, need more backup)
/// - ratio >= 0.6: safety_margin = 2 (moderate backup)
/// - ratio < 0.6:  safety_margin = 1 (already fault-tolerant)
///
/// # Parameters
/// - `threshold_m`: Polynomial threshold `T`; decryption requires `T + 1` shares
/// - `threshold_n`: Requested committee size
///
/// # Returns
/// The number of additional nodes that should be selected as backup
///
/// # Examples
/// ```
/// use e3_sortition::calculate_buffer_size;
///
/// // High security requirement (4 of 5)
/// let buffer = calculate_buffer_size(4, 5);
/// assert_eq!(buffer, 4); // 1 + 3 safety margin
///
/// // Balanced (3 of 5)
/// let buffer = calculate_buffer_size(3, 5);
/// assert_eq!(buffer, 4); // 2 + 2 safety margin
///
/// // High fault tolerance (3 of 10)
/// let buffer = calculate_buffer_size(3, 10);
/// assert_eq!(buffer, 8); // 7 + 1 safety margin
/// ```
pub fn calculate_buffer_size(threshold_m: usize, threshold_n: usize) -> usize {
    if threshold_n == 0 {
        return 0;
    }

    // Preserve the legacy candidate-buffer formula based on N - T.
    let base_buffer = threshold_n.saturating_sub(threshold_m);

    // Calculate threshold ratio to determine safety margin
    let ratio = threshold_m as f64 / threshold_n as f64;

    // Determine safety margin based on how tight the threshold is
    let safety_margin = if ratio >= 0.8 {
        3 // Tight threshold (e.g., 4/5), need more backup
    } else if ratio >= 0.6 {
        2 // Moderate threshold (e.g., 3/5), balanced backup
    } else {
        1 // Loose threshold (e.g., 3/10), minimal backup needed
    };

    base_buffer + safety_margin
}

/// Deterministic committee selection based on ticket scores.
///
/// This struct encapsulates the logic to:
/// - Compute each node’s lowest-score ticket using the given round `seed`.
/// - Ensure only one winning ticket per node is considered.
/// - Sort all node winners globally by `(score, ticket_id)` in ascending order.
/// - Select the top `N` nodes as the final committee.
pub struct ScoreSortition {
    /// Desired committee size (N).
    pub size: usize,
}

impl ScoreSortition {
    /// Construct a new `ScoreSortition` for a given committee size.
    pub fn new(size: usize) -> Self {
        Self { size }
    }

    /// Shortlist distinct owners and retain their operators as submission fallbacks.
    /// Finalization ranks visit each owner's best operator before its backup operators.
    pub fn get_owner_candidates(
        &self,
        e3_id: E3id,
        seed: Seed,
        nodes: &[RegisteredNode],
        owners: &HashMap<Address, Address>,
    ) -> Result<Vec<WinnerTicket>> {
        let mut winners = Self::new(nodes.len()).get_committee(e3_id, seed, nodes)?;
        // Match the capped contract's tie-break between different operators.
        winners.sort_unstable_by(|a, b| a.score.cmp(&b.score).then(a.address.cmp(&b.address)));
        let mut groups: HashMap<Address, (usize, usize)> = HashMap::new();
        let mut candidates = Vec::new();
        for winner in winners {
            let owner = owners
                .get(&winner.address)
                .context("missing request-time bond owner")?;
            let next_rank = groups.len();
            let (owner_rank, member_rank) = groups.entry(*owner).or_insert((next_rank, 0));
            if *owner_rank < self.size {
                candidates.push(((*member_rank, *owner_rank), winner));
                *member_rank += 1;
            }
        }
        candidates.sort_unstable_by_key(|(rank, _)| *rank);
        Ok(candidates.into_iter().map(|(_, winner)| winner).collect())
    }

    /// Determine the top-N committee members from a list of registered nodes.
    ///
    /// # Parameters
    /// - `e3_id`: The E3 computation ID.
    /// - `seed`: Round seed used for deterministic ticket scoring.
    /// - `nodes`: Snapshot of all registered nodes (each with its tickets).
    ///
    /// # Returns
    /// A sorted vector of `WinnerTicket`s representing the selected committee.
    /// Returns an empty vector if no nodes have tickets or if `size == 0`.
    pub fn get_committee(
        &self,
        e3_id: E3id,
        seed: Seed,
        nodes: &[RegisteredNode],
    ) -> Result<Vec<WinnerTicket>> {
        if nodes.is_empty() || self.size == 0 {
            return Ok(Vec::new());
        }

        let mut best_map: HashMap<Address, WinnerTicket> = HashMap::with_capacity(nodes.len());

        for n in nodes {
            if n.tickets.is_empty() {
                continue;
            }

            let w = calculate_best_ticket_for_node(e3_id.clone(), seed, n)?;
            match best_map.entry(w.address) {
                Entry::Vacant(v) => {
                    v.insert(w);
                }
                Entry::Occupied(mut o) => {
                    let cur = o.get_mut();
                    if w.score < cur.score || (w.score == cur.score && w.ticket_id < cur.ticket_id)
                    {
                        *cur = w;
                    }
                }
            }
        }

        let mut items: Vec<WinnerTicket> = best_map.into_values().collect();

        // Sort ascending by (score, ticket_id)
        items.sort_unstable_by(|a, b| {
            a.score
                .cmp(&b.score)
                .then(a.ticket_id.cmp(&b.ticket_id))
                .then(a.address.as_slice().cmp(b.address.as_slice()))
        });

        let k = self.size.min(items.len());
        items.truncate(k);
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::ticket::{RegisteredNode, Ticket, WinnerTicket};
    use crate::domain::ticket_sortition::ScoreSortition;
    use alloy::primitives::{keccak256, Address, Uint};
    use e3_events::{E3id, Seed};
    use std::collections::HashSet;

    fn ticket_count(i: u64) -> u64 {
        let h = keccak256([b"tickets".as_slice(), &i.to_be_bytes()].concat());
        (u128::from_be_bytes(h.0[0..16].try_into().unwrap()) % 7 + 1) as u64
    }

    fn address(i: u64) -> Address {
        let h = keccak256([b"addr".as_slice(), &i.to_be_bytes()].concat());
        let mut bytes20 = [0u8; 20];
        bytes20.copy_from_slice(&h.0[12..32]);
        Address::from(bytes20)
    }

    fn build_nodes() -> Vec<RegisteredNode> {
        let mut next_ticket_id: u64 = 1;
        (0u64..10)
            .map(|i| {
                let address = address(i);
                let t = ticket_count(i);
                let mut tickets = Vec::with_capacity(t as usize);
                for _ in 0..t {
                    tickets.push(Ticket {
                        ticket_id: next_ticket_id,
                    });
                    next_ticket_id += 1;
                }
                RegisteredNode { address, tickets }
            })
            .collect()
    }

    #[test]
    fn test_ticket_sortition() {
        let committee_size: usize = 3;
        let e3_id = E3id::new("42", 42);
        let seed = Seed::from(Uint::from(0xA1B2_C3D4_E5F6_7789u64));

        let nodes = build_nodes();
        assert_eq!(nodes.len(), 10);
        assert!(nodes.iter().all(|n| !n.tickets.is_empty()));

        println!("NODES {:#?}", nodes);

        let mut all_ids = HashSet::new();
        for n in &nodes {
            for t in &n.tickets {
                assert!(all_ids.insert(t.ticket_id));
            }
        }

        let committee: Vec<WinnerTicket> = ScoreSortition::new(committee_size)
            .get_committee(e3_id, seed, &nodes)
            .expect("score sortition should succeed");
        assert_eq!(committee.len(), committee_size);

        // Check winners deterministically for the given seed
        assert_eq!(committee[0].address, nodes[9].address);
        assert_eq!(committee[1].address, nodes[2].address);
        assert_eq!(committee[2].address, nodes[1].address);

        println!("COMMITTEE {:#?}", committee);
    }

    #[test]
    fn test_buffer_calculation() {
        // Edge cases
        assert_eq!(super::calculate_buffer_size(0, 0), 0);
        assert_eq!(super::calculate_buffer_size(5, 5), 3); // ratio=1.0, safety=3
        assert_eq!(super::calculate_buffer_size(1, 1), 3); // ratio=1.0, safety=3

        // Tight threshold (ratio >= 0.8) - safety margin = 3
        assert_eq!(super::calculate_buffer_size(4, 5), 4); // 80%: base=1, safety=3
        assert_eq!(super::calculate_buffer_size(8, 10), 5); // 80%: base=2, safety=3
        assert_eq!(super::calculate_buffer_size(9, 10), 4); // 90%: base=1, safety=3

        // Moderate threshold (0.6 <= ratio < 0.8) - safety margin = 2
        assert_eq!(super::calculate_buffer_size(3, 5), 4); // 60%: base=2, safety=2
        assert_eq!(super::calculate_buffer_size(7, 10), 5); // 70%: base=3, safety=2

        // Loose threshold (ratio < 0.6) - safety margin = 1
        assert_eq!(super::calculate_buffer_size(2, 5), 4); // 40%: base=3, safety=1
        assert_eq!(super::calculate_buffer_size(3, 10), 8); // 30%: base=7, safety=1
        assert_eq!(super::calculate_buffer_size(5, 20), 16); // 25%: base=15, safety=1

        // Real-world scenarios
        let cases = [
            (4, 5, 9, "Small committee, high security"),
            (7, 10, 15, "Medium committee, balanced"),
            (10, 30, 51, "Large committee, high fault tolerance"),
        ];

        for (threshold_m, threshold_n, expected_total, desc) in cases {
            let buffer = super::calculate_buffer_size(threshold_m, threshold_n);
            let total = threshold_n + buffer;
            assert_eq!(
                total, expected_total,
                "{}: Need {}/{} nodes, expected {} total",
                desc, threshold_m, threshold_n, expected_total
            );
        }
    }

    #[test]
    fn owner_shortlist_retains_backups_and_spreads_finalization_ranks() {
        let id = E3id::new("42", 1);
        let seed = Seed([42; 32]);
        let nodes = (1..=68)
            .map(|i| RegisteredNode {
                address: address(i),
                tickets: vec![Ticket { ticket_id: 1 }],
            })
            .collect::<Vec<_>>();
        // Put the 28-node owner first in the score order to exercise the crowded prefix.
        let winners = ScoreSortition::new(nodes.len())
            .get_committee(id.clone(), seed, &nodes)
            .unwrap();
        let shared_owner = address(1000);
        let owners = winners
            .iter()
            .enumerate()
            .map(|(rank, winner)| {
                (
                    winner.address,
                    if rank < 28 {
                        shared_owner
                    } else {
                        winner.address
                    },
                )
            })
            .collect();
        let candidates = ScoreSortition::new(30)
            .get_owner_candidates(id, seed, &nodes, &owners)
            .unwrap();
        assert_eq!(candidates.len(), 57); // 28 operators plus 29 other owners, not all 68.
        assert_eq!(
            candidates[..30]
                .iter()
                .map(|w| owners[&w.address])
                .collect::<HashSet<_>>()
                .len(),
            30
        );
        assert_eq!(
            candidates
                .iter()
                .filter(|w| owners[&w.address] == shared_owner)
                .count(),
            28
        );

        // The best operator is offline, together with five whole backup owner groups.
        let offline_owner_groups = candidates[25..30]
            .iter()
            .map(|w| owners[&w.address])
            .collect::<HashSet<_>>();
        let online = candidates.iter().filter(|w| {
            w.address != winners[0].address && !offline_owner_groups.contains(&owners[&w.address])
        });
        let remaining_owners = online.map(|w| owners[&w.address]).collect::<HashSet<_>>();
        assert!(remaining_owners.contains(&shared_owner));
        assert_eq!(remaining_owners.len(), 25);
    }

    #[test]
    fn independent_owners_keep_the_existing_candidate_buffer() {
        let nodes = build_nodes();
        let owners = nodes
            .iter()
            .map(|node| (node.address, node.address))
            .collect();
        let id = E3id::new("9", 1);
        let seed = Seed([9; 32]);
        let selection = ScoreSortition::new(7);
        let before = selection.get_committee(id.clone(), seed, &nodes).unwrap();
        let after = selection
            .get_owner_candidates(id, seed, &nodes, &owners)
            .unwrap();
        assert_eq!(
            before.iter().map(|w| w.address).collect::<Vec<_>>(),
            after.iter().map(|w| w.address).collect::<Vec<_>>()
        );
    }
}
