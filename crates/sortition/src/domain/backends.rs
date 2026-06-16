// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::node_registry::NodeStateStore;
use crate::domain::ticket::{RegisteredNode, Ticket};
use crate::domain::ticket_sortition::ScoreSortition;
use alloy::primitives::Address;
use anyhow::Result;
use e3_events::{E3id, Seed};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Minimal interface that all sortition backends must implement.
///
/// Backends can store their own shapes (e.g., a `HashSet<String>` of addresses
/// for Score)
pub trait SortitionList<T> {
    /// Return `true` if `address` appears in the size-`size` committee under `seed`.
    ///
    /// Implementations should return `Ok(false)` if the backend has no nodes
    /// or if `size == 0`.
    fn contains(
        &self,
        e3_id: E3id,
        seed: Seed,
        size: usize,
        address: T,
        chain_id: u64,
        node_state: &NodeStateStore,
    ) -> anyhow::Result<bool>;

    /// Return an index if `address` appears in the committee under `seed`.
    ///
    /// Implementations should return `Ok(None)` if the backend has no nodes
    /// or if `size == 0`.
    fn get_index(
        &self,
        e3_id: E3id,
        seed: Seed,
        size: usize,
        address: String,
        chain_id: u64,
        node_state: &NodeStateStore,
    ) -> Result<Option<(u64, Option<u64>)>>;

    /// Add a node to the backend. Backends should be idempotent on duplicates.
    fn add(&mut self, address: T);

    /// Remove a node from the backend. Removing a non-existent node is a no-op.
    fn remove(&mut self, address: T);

    /// Return all registered node addresses as hex strings.
    fn nodes(&self) -> Vec<String>;
}

/// Score-sortition backend.
///
/// Stores richer `RegisteredNode` entries (address + per-node ticket set).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScoreBackend {
    /// Nodes with their ticket sets (used by score-based committee selection).
    registered: Vec<RegisteredNode>,
}

impl ScoreBackend {
    /// Build a vector of ephemeral nodes from the node state.
    ///
    /// The nodes are built from the node state and the registered nodes.
    fn build_nodes_from_state(
        &self,
        chain_id: u64,
        node_state: &NodeStateStore,
    ) -> Vec<RegisteredNode> {
        info!(
            chain_id = chain_id,
            registered_count = self.registered.len(),
            node_state_count = node_state.nodes.len(),
            "Building nodes from state for score sortition"
        );

        self.registered
            .iter()
            .filter_map(|n| {
                let addr_str = n.address.to_string();
                let Some(ns) = node_state.nodes.get(&addr_str) else {
                    info!(
                        address = %addr_str,
                        chain_id = chain_id,
                        "Node not found in NodeStateStore"
                    );
                    return None;
                };
                if !ns.active {
                    info!(
                        address = %addr_str,
                        "Node is not active"
                    );
                    return None;
                }

                let count = node_state.available_tickets(&addr_str);
                let total_tickets = if node_state.ticket_price.is_zero() {
                    0u64
                } else {
                    (ns.ticket_balance / node_state.ticket_price)
                        .try_into()
                        .unwrap_or(0u64)
                };

                if count == 0 {
                    info!(
                        address = %addr_str,
                        ticket_balance = ?ns.ticket_balance,
                        ticket_price = ?node_state.ticket_price,
                        total_tickets = total_tickets,
                        active_jobs = ns.active_jobs,
                        "Node has no available tickets"
                    );
                    return None;
                }

                let tickets = (1..=count).map(|i| Ticket { ticket_id: i }).collect();
                Some(RegisteredNode {
                    address: n.address,
                    tickets,
                })
            })
            .collect()
    }
}

impl SortitionList<String> for ScoreBackend {
    /// Compute score-based winners (`ScoreSortition`) and check if `address` is included.
    ///
    /// Returns `Ok(false)` if there are no nodes or `size == 0`.
    fn contains(
        &self,
        e3_id: E3id,
        seed: Seed,
        size: usize,
        address: String,
        chain_id: u64,
        node_state: &NodeStateStore,
    ) -> anyhow::Result<bool> {
        if size == 0 {
            return Ok(false);
        }

        let nodes = self.build_nodes_from_state(chain_id, node_state);
        if nodes.is_empty() {
            return Ok(false);
        }

        let winners = ScoreSortition::new(size).get_committee(e3_id.clone(), seed, &nodes)?;

        let selected_nodes: Vec<String> = winners
            .iter()
            .map(|w| format!("{}(ticket:{})", w.address, w.ticket_id))
            .collect();
        info!(
            e3_id = %e3_id,
            chain_id = chain_id,
            committee_size = size,
            selected_count = winners.len(),
            nodes = ?selected_nodes,
            "Sortition completed - selected nodes"
        );

        let want: Address = address.parse()?;
        Ok(winners.iter().any(|w| w.address == want))
    }

    /// Compute score-based winners (`ScoreSortition`) and check if `address` is included.
    ///
    /// Returns `Ok(None)` if there are no nodes or `size == 0`.
    fn get_index(
        &self,
        e3_id: E3id,
        seed: Seed,
        size: usize,
        address: String,
        chain_id: u64,
        node_state: &NodeStateStore,
    ) -> anyhow::Result<Option<(u64, Option<u64>)>> {
        if size == 0 {
            return Ok(None);
        }

        let nodes: Vec<RegisteredNode> = self.build_nodes_from_state(chain_id, node_state);

        if nodes.is_empty() {
            return Ok(None);
        }

        let winners = ScoreSortition::new(size).get_committee(e3_id.clone(), seed, &nodes)?;

        let selected_nodes: Vec<String> = winners
            .iter()
            .map(|w| format!("{}(ticket:{})", w.address, w.ticket_id))
            .collect();
        info!(
            e3_id = %e3_id,
            chain_id = chain_id,
            committee_size = size,
            selected_count = winners.len(),
            nodes = ?selected_nodes,
            "Sortition completed - selected nodes"
        );

        let want: alloy::primitives::Address = address.parse()?;

        let maybe = winners
            .iter()
            .enumerate()
            .find_map(|(i, w)| (w.address == want).then_some((i as u64, Some(w.ticket_id))));
        Ok(maybe)
    }

    /// Add a node, creating an empty ticket set when first seen.
    fn add(&mut self, address: String) {
        match address.parse::<Address>() {
            Ok(addr) => {
                if !self.registered.iter().any(|n| n.address == addr) {
                    self.registered.push(RegisteredNode {
                        address: addr,
                        tickets: Vec::new(),
                    });
                }
            }
            Err(e) => {
                tracing::warn!("Failed to parse address '{}': {}", address, e);
            }
        }
    }

    /// Remove the node (if present).
    ///
    /// Note: `used_ticket_ids` is a legacy field and clearing it here has
    /// no effect on current per-node ticket ID semantics.
    fn remove(&mut self, address: String) {
        if let Ok(addr) = address.parse::<Address>() {
            if let Some(i) = self.registered.iter().position(|n| n.address == addr) {
                self.registered.swap_remove(i);
            }
        }
    }

    /// Return all registered node addresses as hex strings.
    fn nodes(&self) -> Vec<String> {
        self.registered
            .iter()
            .map(|n| n.address.to_string())
            .collect()
    }
}

/// Enum wrapper around the supported backends.
///
/// New chains default to `Score` sortition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SortitionBackend {
    /// Score-based selection (stores `RegisteredNode`s with tickets).
    Score(ScoreBackend),
}

impl Default for SortitionBackend {
    fn default() -> Self {
        SortitionBackend::Score(ScoreBackend::default())
    }
}

impl SortitionBackend {
    pub fn score() -> Self {
        SortitionBackend::Score(ScoreBackend::default())
    }
}

impl SortitionList<String> for SortitionBackend {
    fn contains(
        &self,
        e3_id: E3id,
        seed: Seed,
        size: usize,
        address: String,
        chain_id: u64,
        node_state: &NodeStateStore,
    ) -> anyhow::Result<bool> {
        match self {
            SortitionBackend::Score(b) => {
                b.contains(e3_id, seed, size, address, chain_id, node_state)
            }
        }
    }

    fn get_index(
        &self,
        e3_id: E3id,
        seed: Seed,
        size: usize,
        address: String,
        chain_id: u64,
        node_state: &NodeStateStore,
    ) -> anyhow::Result<Option<(u64, Option<u64>)>> {
        match self {
            SortitionBackend::Score(b) => {
                b.get_index(e3_id, seed, size, address, chain_id, node_state)
            }
        }
    }

    fn add(&mut self, address: String) {
        match self {
            SortitionBackend::Score(backend) => backend.add(address),
        }
    }

    fn remove(&mut self, address: String) {
        match self {
            SortitionBackend::Score(backend) => backend.remove(address),
        }
    }

    fn nodes(&self) -> Vec<String> {
        match self {
            SortitionBackend::Score(backend) => backend.nodes(),
        }
    }
}
