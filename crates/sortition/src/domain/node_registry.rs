// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure domain logic for the sortition node registry.
//!
//! This module owns the per-chain node bookkeeping (`NodeStateStore`) and every
//! state transition that operates on it. It is deliberately free of any actor,
//! persistence, networking, or event-bus concerns so the rules can be reasoned
//! about and unit-tested in isolation. The [`Sortition`](crate::Sortition) actor
//! is a thin shell that loads persisted state, calls into [`NodeRegistry`], and
//! writes the result back.

use alloy::primitives::U256;
use e3_events::E3id;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

/// State for a single ciphernode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeState {
    /// Current ticket balance for this node.
    pub ticket_balance: U256,
    /// Number of active E3 jobs this node is currently participating in.
    pub active_jobs: u64,
    /// Whether this node is active (has met minimum requirements).
    pub active: bool,
}

impl Default for NodeState {
    fn default() -> Self {
        Self {
            ticket_balance: U256::ZERO,
            active_jobs: 0,
            active: false,
        }
    }
}

/// Unified state for all nodes across all chains.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodeStateStore {
    /// Map of `node_address -> node state`.
    pub nodes: HashMap<String, NodeState>,
    /// Current ticket price.
    pub ticket_price: U256,
    /// Map of `E3 ID -> committee nodes` for that E3.
    ///
    /// Tracks which nodes are participating in which E3 jobs so that active-job
    /// counters can be released when the E3 completes or fails.
    pub e3_committees: HashMap<String, Vec<String>>,
}

impl NodeStateStore {
    /// Get available tickets for a node, accounting for active jobs.
    ///
    /// The available ticket count is `floor(balance / price) - active_jobs`,
    /// saturating at zero. Inactive nodes and a zero ticket price both yield `0`.
    pub fn available_tickets(&self, address: &str) -> u64 {
        if self.ticket_price.is_zero() {
            warn!("Ticket price is zero, returning 0 tickets, Please make sure this is the correct behavior");
            return 0;
        }

        let Some(node) = self.nodes.get(address) else {
            return 0;
        };

        let total_tickets = (node.ticket_balance / self.ticket_price)
            .try_into()
            .unwrap_or(0u64);
        total_tickets.saturating_sub(node.active_jobs)
    }

    /// Get all active nodes that currently have at least one available ticket.
    pub fn get_nodes_with_tickets(&self) -> Vec<(String, u64)> {
        self.nodes
            .iter()
            .filter(|(_, node_state)| node_state.active)
            .map(|(addr, _)| (addr.clone(), self.available_tickets(addr)))
            .filter(|(_, tickets)| *tickets > 0)
            .collect()
    }
}

/// Canonical key used to track a committee within a [`NodeStateStore`].
///
/// Combines the chain id with the on-chain E3 id so committees never collide
/// across chains.
pub fn committee_key(e3_id: &E3id) -> String {
    format!("{}:{}", e3_id.chain_id(), e3_id.e3_id())
}

/// Pure transition logic over the per-chain [`NodeStateStore`] map.
///
/// Every method takes the full `chain_id -> NodeStateStore` map by mutable
/// reference and applies a single, well-defined transition. There is no I/O,
/// persistence, or messaging here — callers are responsible for loading and
/// saving the map and for publishing any downstream events.
pub struct NodeRegistry;

impl NodeRegistry {
    /// Register a node on a chain, creating chain/node entries as needed.
    pub fn add_node(store: &mut HashMap<u64, NodeStateStore>, chain_id: u64, address: String) {
        let chain_state = store.entry(chain_id).or_default();
        chain_state.nodes.entry(address.clone()).or_default();
        info!(address = %address, chain_id = chain_id, "Node added to sortition state");
    }

    /// Remove a node from a chain. No-op if the chain or node is unknown.
    pub fn remove_node(store: &mut HashMap<u64, NodeStateStore>, chain_id: u64, address: &str) {
        if let Some(chain_state) = store.get_mut(&chain_id) {
            chain_state.nodes.remove(address);
        }
        info!(address = %address, chain_id = chain_id, "Node removed from sortition state");
    }

    /// Set the ticket balance for an operator on a chain.
    pub fn set_ticket_balance(
        store: &mut HashMap<u64, NodeStateStore>,
        chain_id: u64,
        operator: String,
        new_balance: U256,
    ) {
        let chain_state = store.entry(chain_id).or_default();
        let node = chain_state.nodes.entry(operator.clone()).or_default();
        node.ticket_balance = new_balance;
        info!(
            operator = %operator,
            chain_id = chain_id,
            new_balance = ?new_balance,
            "Updated ticket balance"
        );
    }

    /// Update an operator's active status across every chain it appears on.
    pub fn set_operator_active(
        store: &mut HashMap<u64, NodeStateStore>,
        operator: String,
        active: bool,
    ) {
        for chain_state in store.values_mut() {
            let node = chain_state.nodes.entry(operator.clone()).or_default();
            node.active = active;
            info!(
                operator = %operator,
                active = active,
                "Updated operator active status"
            );
        }
    }

    /// Set the ticket price for a chain.
    pub fn set_ticket_price(
        store: &mut HashMap<u64, NodeStateStore>,
        chain_id: u64,
        new_price: U256,
    ) {
        let chain_state = store.entry(chain_id).or_default();
        chain_state.ticket_price = new_price;
        info!(
            chain_id = chain_id,
            new_ticket_price = ?new_price,
            "ConfigurationUpdated - ticket price updated"
        );
    }

    /// Record a published committee and increment active-job counters for each
    /// of its members.
    pub fn record_committee_published(
        store: &mut HashMap<u64, NodeStateStore>,
        e3_id: &E3id,
        nodes: &[String],
    ) {
        let chain_id = e3_id.chain_id();
        let key = committee_key(e3_id);
        let chain_state = store.entry(chain_id).or_default();

        chain_state.e3_committees.insert(key, nodes.to_vec());

        for node_addr in nodes {
            let node = chain_state.nodes.entry(node_addr.clone()).or_default();
            node.active_jobs += 1;
            info!(
                node = %node_addr,
                chain_id = chain_id,
                e3_id = ?e3_id,
                active_jobs = node.active_jobs,
                "Incremented active jobs for node in committee"
            );
        }
    }

    /// Release a finished E3: remove its committee record and decrement the
    /// active-job counter for every member.
    ///
    /// Idempotent — calling it again after the committee has been released is a
    /// no-op. `reason` is used only for logging.
    pub fn release_committee_jobs(
        store: &mut HashMap<u64, NodeStateStore>,
        e3_id: &E3id,
        reason: &str,
    ) {
        let chain_id = e3_id.chain_id();
        let key = committee_key(e3_id);

        let Some(chain_state) = store.get_mut(&chain_id) else {
            return;
        };

        let Some(committee_nodes) = chain_state.e3_committees.remove(&key) else {
            info!(
                e3_id = ?e3_id,
                reason = reason,
                "No committee found (might have been completed already)"
            );
            return;
        };

        for node_addr in &committee_nodes {
            if let Some(node) = chain_state.nodes.get_mut(node_addr) {
                node.active_jobs = node.active_jobs.saturating_sub(1);
                info!(
                    node = %node_addr,
                    chain_id = chain_id,
                    e3_id = ?e3_id,
                    active_jobs = node.active_jobs,
                    reason = reason,
                    "Decremented active jobs for node"
                );
            }
        }

        info!(
            e3_id = ?e3_id,
            committee_size = committee_nodes.len(),
            reason = reason,
            "E3 completed/failed - decremented active jobs for committee"
        );
    }

    /// Enumerate every committee that still holds active jobs (i.e. has not been
    /// released by a completion/failure event).
    ///
    /// These are the node's "open loops": E3s it is still accounted as busy on.
    /// On a clean shutdown/restart this set should only contain genuinely
    /// in-flight E3s. If it contains an E3 that has already reached a terminal
    /// stage on-chain, the corresponding active-job slot is orphaned and should
    /// be released (see `interfold node validate`). The returned `committee_key`
    /// matches [`committee_key`] so callers can correlate it with an `E3id`.
    pub fn open_committees(store: &HashMap<u64, NodeStateStore>) -> Vec<OpenCommittee> {
        let mut out = Vec::new();
        for (chain_id, chain_state) in store {
            for (key, members) in &chain_state.e3_committees {
                out.push(OpenCommittee {
                    chain_id: *chain_id,
                    committee_key: key.clone(),
                    members: members.clone(),
                });
            }
        }
        out
    }
}

/// A committee that still holds active-job slots in a [`NodeStateStore`].
///
/// Produced by [`NodeRegistry::open_committees`]. `committee_key` is the same
/// `"{chain_id}:{e3_id}"` string used internally (see [`committee_key`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenCommittee {
    /// Chain the committee belongs to.
    pub chain_id: u64,
    /// Canonical committee key (`"{chain_id}:{e3_id}"`).
    pub committee_key: String,
    /// Addresses of the committee members holding the open slot.
    pub members: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e3(chain_id: u64, id: &str) -> E3id {
        E3id::new(id, chain_id)
    }

    #[test]
    fn add_and_remove_node() {
        let mut store = HashMap::new();
        NodeRegistry::add_node(&mut store, 1, "0xabc".into());
        assert!(store[&1].nodes.contains_key("0xabc"));

        NodeRegistry::remove_node(&mut store, 1, "0xabc");
        assert!(!store[&1].nodes.contains_key("0xabc"));

        // Removing an unknown node / chain is a no-op.
        NodeRegistry::remove_node(&mut store, 99, "0xdef");
    }

    #[test]
    fn available_tickets_accounts_for_price_and_jobs() {
        let mut store = HashMap::new();
        NodeRegistry::set_ticket_price(&mut store, 1, U256::from(10));
        NodeRegistry::set_ticket_balance(&mut store, 1, "0xabc".into(), U256::from(55));
        NodeRegistry::set_operator_active(&mut store, "0xabc".into(), true);

        // floor(55 / 10) = 5 tickets, no active jobs yet.
        assert_eq!(store[&1].available_tickets("0xabc"), 5);

        NodeRegistry::record_committee_published(&mut store, &e3(1, "7"), &["0xabc".into()]);
        // One active job now -> 4 available.
        assert_eq!(store[&1].available_tickets("0xabc"), 4);
        assert_eq!(store[&1].nodes["0xabc"].active_jobs, 1);
    }

    #[test]
    fn zero_price_yields_no_tickets() {
        let mut store = HashMap::new();
        NodeRegistry::set_ticket_balance(&mut store, 1, "0xabc".into(), U256::from(100));
        assert_eq!(store[&1].available_tickets("0xabc"), 0);
    }

    #[test]
    fn operator_active_applies_across_chains() {
        let mut store = HashMap::new();
        NodeRegistry::add_node(&mut store, 1, "0xabc".into());
        NodeRegistry::add_node(&mut store, 2, "0xabc".into());
        NodeRegistry::set_operator_active(&mut store, "0xabc".into(), true);
        assert!(store[&1].nodes["0xabc"].active);
        assert!(store[&2].nodes["0xabc"].active);
    }

    #[test]
    fn release_committee_jobs_is_idempotent() {
        let mut store = HashMap::new();
        let id = e3(1, "7");
        NodeRegistry::record_committee_published(
            &mut store,
            &id,
            &["0xabc".into(), "0xdef".into()],
        );
        assert_eq!(store[&1].nodes["0xabc"].active_jobs, 1);
        assert_eq!(store[&1].nodes["0xdef"].active_jobs, 1);

        NodeRegistry::release_committee_jobs(&mut store, &id, "test");
        assert_eq!(store[&1].nodes["0xabc"].active_jobs, 0);
        assert_eq!(store[&1].nodes["0xdef"].active_jobs, 0);
        assert!(!store[&1].e3_committees.contains_key(&committee_key(&id)));

        // Second release does not underflow.
        NodeRegistry::release_committee_jobs(&mut store, &id, "test-again");
        assert_eq!(store[&1].nodes["0xabc"].active_jobs, 0);
    }

    #[test]
    fn get_nodes_with_tickets_filters_inactive_and_empty() {
        let mut store = HashMap::new();
        NodeRegistry::set_ticket_price(&mut store, 1, U256::from(10));
        NodeRegistry::set_ticket_balance(&mut store, 1, "active".into(), U256::from(30));
        NodeRegistry::set_operator_active(&mut store, "active".into(), true);
        // Inactive node with balance is excluded.
        NodeRegistry::set_ticket_balance(&mut store, 1, "inactive".into(), U256::from(30));

        let with_tickets = store[&1].get_nodes_with_tickets();
        assert_eq!(with_tickets.len(), 1);
        assert_eq!(with_tickets[0].0, "active");
        assert_eq!(with_tickets[0].1, 3);
    }

    #[test]
    fn open_committees_lists_only_unreleased() {
        let mut store = HashMap::new();
        let a = e3(1, "1");
        let b = e3(1, "2");
        NodeRegistry::record_committee_published(&mut store, &a, &["0xabc".into()]);
        NodeRegistry::record_committee_published(&mut store, &b, &["0xabc".into(), "0xdef".into()]);

        let open = NodeRegistry::open_committees(&store);
        assert_eq!(open.len(), 2);

        // Releasing one removes it from the open set.
        NodeRegistry::release_committee_jobs(&mut store, &a, "test");
        let open = NodeRegistry::open_committees(&store);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].committee_key, committee_key(&b));
        assert_eq!(open[0].chain_id, 1);
        assert_eq!(
            open[0].members,
            vec!["0xabc".to_string(), "0xdef".to_string()]
        );

        // Fully drained -> empty.
        NodeRegistry::release_committee_jobs(&mut store, &b, "test");
        assert!(NodeRegistry::open_committees(&store).is_empty());
    }
}
