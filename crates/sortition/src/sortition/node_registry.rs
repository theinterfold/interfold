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
use std::collections::{hash_map::Entry, HashMap};
use tracing::{info, warn};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateCheckpoint<T> {
    pub timepoint: u64,
    pub value: T,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SortitionSnapshot {
    pub request_block: u64,
    pub ticket_price: U256,
}

/// State for a single ciphernode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeState {
    /// Current ticket balance for this node.
    pub ticket_balance: U256,
    /// Local count of active E3 jobs used for voluntary load balancing.
    ///
    /// This count does not reserve collateral or change on-chain eligibility.
    pub active_jobs: u64,
    /// Whether this node is active (has met minimum requirements).
    pub active: bool,
    /// Ticket balances indexed by the EIP-6372 timestamp used on-chain.
    pub ticket_balance_history: Vec<StateCheckpoint<U256>>,
    /// Eligibility changes indexed by the EIP-6372 timestamp used on-chain.
    pub active_history: Vec<StateCheckpoint<bool>>,
}

impl Default for NodeState {
    fn default() -> Self {
        Self {
            ticket_balance: U256::ZERO,
            active_jobs: 0,
            active: false,
            ticket_balance_history: Vec::new(),
            active_history: Vec::new(),
        }
    }
}

impl NodeState {
    pub fn ticket_balance_at(&self, timepoint: u64) -> U256 {
        checkpoint_value(&self.ticket_balance_history, timepoint).unwrap_or(U256::ZERO)
    }

    pub fn active_at(&self, timepoint: u64) -> bool {
        checkpoint_value(&self.active_history, timepoint).unwrap_or(false)
    }
}

fn checkpoint_value<T: Copy>(history: &[StateCheckpoint<T>], timepoint: u64) -> Option<T> {
    let index = history.partition_point(|checkpoint| checkpoint.timepoint <= timepoint);
    index.checked_sub(1).map(|index| history[index].value)
}

fn push_checkpoint<T>(history: &mut Vec<StateCheckpoint<T>>, timepoint: u64, value: T) {
    if let Some(last) = history.last_mut() {
        if last.timepoint == timepoint {
            last.value = value;
            return;
        }
        debug_assert!(last.timepoint < timepoint);
    }
    history.push(StateCheckpoint { timepoint, value });
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
    /// Request-boundary price and timepoint for each E3.
    pub sortition_snapshots: HashMap<String, SortitionSnapshot>,
}

impl NodeStateStore {
    /// Get the tickets this node chooses to use after local load balancing.
    ///
    /// The available ticket count is `floor(balance / price) - active_jobs`,
    /// saturating at zero. Inactive nodes and a zero ticket price both yield `0`.
    ///
    /// The contract validates the full ticket range from the snapshotted balance.
    /// Other nodes can ignore this local participation policy.
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

    pub fn sortition_snapshot(&self, e3_id: &E3id) -> Option<SortitionSnapshot> {
        self.sortition_snapshots.get(&committee_key(e3_id)).copied()
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
        timepoint: u64,
    ) {
        let chain_state = store.entry(chain_id).or_default();
        let node = chain_state.nodes.entry(operator.clone()).or_default();
        node.ticket_balance = new_balance;
        push_checkpoint(&mut node.ticket_balance_history, timepoint, new_balance);
        info!(
            operator = %operator,
            chain_id = chain_id,
            new_balance = ?new_balance,
            "Updated ticket balance"
        );
    }

    /// Update an operator's active status on the chain that emitted the event.
    pub fn set_operator_active(
        store: &mut HashMap<u64, NodeStateStore>,
        chain_id: u64,
        operator: String,
        active: bool,
        timepoint: u64,
    ) {
        let chain_state = store.entry(chain_id).or_default();
        let node = chain_state.nodes.entry(operator.clone()).or_default();
        node.active = active;
        push_checkpoint(&mut node.active_history, timepoint, active);
        info!(
            operator = %operator,
            chain_id = chain_id,
            active = active,
            "Updated operator active status"
        );
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

    /// Mark every operator on one chain inactive after an eligibility-policy
    /// update. On-chain status also fails closed until each operator refreshes
    /// against the new policy version.
    pub fn invalidate_operator_activity(
        store: &mut HashMap<u64, NodeStateStore>,
        chain_id: u64,
        timepoint: u64,
    ) {
        let chain_state = store.entry(chain_id).or_default();
        for node in chain_state.nodes.values_mut() {
            node.active = false;
            push_checkpoint(&mut node.active_history, timepoint, false);
        }
        info!(
            chain_id = chain_id,
            "Invalidated operator activity after eligibility-policy update"
        );
    }

    pub fn record_sortition_snapshot(
        store: &mut HashMap<u64, NodeStateStore>,
        e3_id: &E3id,
        request_block: u64,
        ticket_price: U256,
    ) {
        let chain_state = store.entry(e3_id.chain_id()).or_default();
        chain_state.sortition_snapshots.insert(
            committee_key(e3_id),
            SortitionSnapshot {
                request_block,
                ticket_price,
            },
        );
    }

    /// Record a published committee and increment active-job counters for each
    /// of its members.
    ///
    /// Event replay and duplicate publication candidates can report the same
    /// committee more than once. Only the first report changes the counters.
    pub fn record_committee_published(
        store: &mut HashMap<u64, NodeStateStore>,
        e3_id: &E3id,
        nodes: &[String],
    ) {
        let chain_id = e3_id.chain_id();
        let key = committee_key(e3_id);
        let chain_state = store.entry(chain_id).or_default();

        match chain_state.e3_committees.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(nodes.to_vec());
            }
            Entry::Occupied(entry) => {
                if entry.get().as_slice() != nodes {
                    warn!(
                        chain_id,
                        e3_id = ?e3_id,
                        recorded_nodes = ?entry.get(),
                        replayed_nodes = ?nodes,
                        "Ignored a conflicting committee publication replay"
                    );
                } else {
                    info!(
                        chain_id,
                        e3_id = ?e3_id,
                        "Ignored a duplicate committee publication replay"
                    );
                }
                return;
            }
        }

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
        chain_state.sortition_snapshots.remove(&key);

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
#[path = "node_registry_tests.rs"]
mod tests;
