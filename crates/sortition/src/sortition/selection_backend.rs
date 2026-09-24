// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::node_registry::{NodeStateStore, SortitionSnapshot};
use crate::domain::ticket::{RegisteredNode, Ticket};
use crate::domain::ticket_sortition::ScoreSortition;
use crate::BondOwnerState;
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
        snapshot: SortitionSnapshot,
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
        snapshot: SortitionSnapshot,
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
        snapshot: SortitionSnapshot,
    ) -> Vec<RegisteredNode> {
        info!(
            chain_id = chain_id,
            registered_count = self.registered.len(),
            node_state_count = node_state.nodes.len(),
            "Building nodes from state for score sortition"
        );

        let Some(timepoint) = snapshot.request_block.checked_sub(1) else {
            return Vec::new();
        };

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
                if !ns.active_at(timepoint) {
                    info!(
                        address = %addr_str,
                        "Node is not active"
                    );
                    return None;
                }

                let ticket_balance = ns.ticket_balance_at(timepoint);
                let total_tickets = if snapshot.ticket_price.is_zero() {
                    0u64
                } else {
                    (ticket_balance / snapshot.ticket_price)
                        .try_into()
                        .unwrap_or(0u64)
                };
                if total_tickets == 0 {
                    info!(
                        address = %addr_str,
                        ticket_balance = ?ticket_balance,
                        ticket_price = ?snapshot.ticket_price,
                        total_tickets = total_tickets,
                        "Node has no tickets in the request-time sortition view"
                    );
                    return None;
                }

                let tickets = (1..=total_tickets)
                    .map(|i| Ticket { ticket_id: i })
                    .collect();
                Some(RegisteredNode {
                    address: n.address,
                    tickets,
                })
            })
            .collect()
    }

    /// Return whether the local node chooses to accept one more committee duty.
    fn has_local_capacity(
        node_state: &NodeStateStore,
        e3_id: &E3id,
        local_address: Address,
        snapshot: SortitionSnapshot,
    ) -> bool {
        let local_address = local_address.to_string();
        if node_state.has_job_for_e3(e3_id, &local_address) {
            return true;
        }

        let Some(timepoint) = snapshot.request_block.checked_sub(1) else {
            return false;
        };
        let Some(state) = node_state.nodes.get(&local_address) else {
            return false;
        };
        if snapshot.ticket_price.is_zero() {
            return false;
        }

        let total_tickets = (state.ticket_balance_at(timepoint) / snapshot.ticket_price)
            .try_into()
            .unwrap_or(0u64);
        state.active_jobs < total_tickets
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
        snapshot: SortitionSnapshot,
    ) -> anyhow::Result<bool> {
        if size == 0 {
            return Ok(false);
        }

        let want: Address = address.parse()?;
        let nodes = self.build_nodes_from_state(chain_id, node_state, snapshot);
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
        snapshot: SortitionSnapshot,
    ) -> anyhow::Result<Option<(u64, Option<u64>)>> {
        if size == 0 {
            return Ok(None);
        }

        let want: alloy::primitives::Address = address.parse()?;
        let nodes: Vec<RegisteredNode> =
            self.build_nodes_from_state(chain_id, node_state, snapshot);

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

        let maybe = winners
            .iter()
            .enumerate()
            .find_map(|(i, w)| (w.address == want).then_some((i as u64, Some(w.ticket_id))));
        if maybe.is_some() && !Self::has_local_capacity(node_state, &e3_id, want, snapshot) {
            return Ok(None);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::node_registry::{committee_key, NodeState, StateCheckpoint};
    use alloy::primitives::U256;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn ticket_count(nodes: &[RegisteredNode], address: Address) -> Option<usize> {
        nodes
            .iter()
            .find(|node| node.address == address)
            .map(|node| node.tickets.len())
    }

    #[test]
    fn incomplete_owner_history_keeps_all_candidates_and_local_capacity_checks() {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || LogBuffer(writer.clone()))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let mut backend = SortitionBackend::default();
        let mut state = NodeStateStore::default();
        for i in 1..=50u8 {
            let address = Address::from([i; 20]).to_string();
            backend.add(address.clone());
            state.nodes.insert(
                address,
                NodeState {
                    ticket_balance: U256::from(10),
                    active_jobs: 0,
                    ticket_balance_log_index: 0,
                    active_log_index: 0,
                    active: true,
                    ticket_balance_history: vec![StateCheckpoint {
                        timepoint: 1,
                        value: U256::from(10),
                    }],
                    active_history: vec![StateCheckpoint {
                        timepoint: 1,
                        value: true,
                    }],
                },
            );
        }
        let snapshot = SortitionSnapshot {
            request_block: 2,
            ticket_price: U256::from(10),
        };
        let e3_id = E3id::new("1", 1);
        let seed = Seed::from(U256::from(1));
        let mut ranks = Vec::new();
        for address in backend.nodes() {
            let (rank, ticket) = backend
                .get_submission_index(
                    e3_id.clone(),
                    seed,
                    address,
                    1,
                    &state,
                    snapshot,
                    30,
                    &BondOwnerState::default(),
                )
                .unwrap()
                .expect("all eligible nodes must submit");
            assert_eq!(ticket, Some(1));
            ranks.push(rank);
        }
        ranks.sort();
        assert_eq!(ranks, (0..50).collect::<Vec<_>>());
        let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(output.contains("sortition_owner_history_fallback"));
        assert!(output.contains("missing_owners=50"));
        assert!(output.contains("eligible_operators=50"));
        assert!(output.contains("timepoint=1"));
        assert!(output.contains("e3_id="));

        let local = backend.nodes()[0].clone();
        state.nodes.get_mut(&local).unwrap().active_jobs = 1;
        assert_eq!(
            backend
                .get_submission_index(
                    e3_id.clone(),
                    seed,
                    local.clone(),
                    1,
                    &state,
                    snapshot,
                    30,
                    &BondOwnerState::default()
                )
                .unwrap(),
            None
        );
        state
            .e3_committees
            .insert(committee_key(&e3_id), vec![local.clone()]);
        assert!(
            backend
                .get_submission_index(
                    e3_id,
                    seed,
                    local,
                    1,
                    &state,
                    snapshot,
                    30,
                    &BondOwnerState::default()
                )
                .unwrap()
                .is_some(),
            "a restart keeps its existing reservation"
        );
    }

    #[test]
    fn owner_shortlist_preserves_request_boundaries_and_overlapping_reservations() {
        let mut backend = SortitionBackend::default();
        let mut state = NodeStateStore::default();
        let mut owners = BondOwnerState::default();
        let shared_owner = Address::from([99; 20]);
        for i in 1..=5u8 {
            let address = Address::from([i; 20]);
            backend.add(address.to_string());
            state.nodes.insert(
                address.to_string(),
                NodeState {
                    ticket_balance: U256::from(10),
                    active: true,
                    ticket_balance_history: vec![StateCheckpoint {
                        timepoint: 1,
                        value: U256::from(10),
                    }],
                    active_history: vec![StateCheckpoint {
                        timepoint: 1,
                        value: true,
                    }],
                    ..Default::default()
                },
            );
            owners
                .record(
                    &e3_events::BondOwnerSet {
                        operator: address.to_string(),
                        bond_owner: shared_owner.to_string(),
                        chain_id: 1,
                    },
                    1,
                )
                .unwrap();
        }
        let first = E3id::new("1", 1);
        let second = E3id::new("2", 1);
        let seed = Seed::from(U256::from(1));
        let snapshot = SortitionSnapshot {
            request_block: 10,
            ticket_price: U256::from(10),
        };
        let rank = |e3: &E3id,
                    node: &str,
                    state: &NodeStateStore,
                    view,
                    owners: &BondOwnerState| {
            backend
                .get_submission_index(e3.clone(), seed, node.to_owned(), 1, state, view, 1, owners)
                .unwrap()
        };
        let mut original = backend
            .nodes()
            .into_iter()
            .map(|node| {
                let ticket = rank(&first, &node, &state, snapshot, &owners).unwrap();
                (node, ticket)
            })
            .collect::<Vec<_>>();
        original.sort_by_key(|(_, (rank, _))| *rank);
        let (backup, ticket) = original.last().unwrap();
        owners
            .record(
                &e3_events::BondOwnerSet {
                    operator: backup.clone(),
                    bond_owner: Address::from([88; 20]).to_string(),
                    chain_id: 1,
                },
                10,
            )
            .unwrap();
        let restarted: BondOwnerState =
            bincode::deserialize(&bincode::serialize(&owners).unwrap()).unwrap();
        assert_eq!(
            rank(&first, backup, &state, snapshot, &restarted),
            Some(*ticket)
        );
        assert_eq!(
            rank(
                &first,
                backup,
                &state,
                SortitionSnapshot {
                    request_block: 11,
                    ..snapshot
                },
                &restarted
            ),
            None
        );

        // A local reservation must not remove this node from its existing request or
        // change another node's rank. It only stops this node from accepting a new job.
        state.nodes.get_mut(backup).unwrap().active_jobs = 1;
        state
            .e3_committees
            .insert(committee_key(&first), vec![backup.clone()]);
        assert_eq!(
            rank(&first, backup, &state, snapshot, &restarted),
            Some(*ticket)
        );
        assert_eq!(rank(&second, backup, &state, snapshot, &restarted), None);
        for (node, expected) in &original {
            assert_eq!(
                rank(&first, node, &state, snapshot, &restarted),
                Some(*expected)
            );
        }
        state.e3_committees.remove(&committee_key(&first));
        state.nodes.get_mut(backup).unwrap().active_jobs = 0;
        assert!(rank(&second, backup, &state, snapshot, &restarted).is_some());
    }

    #[test]
    fn active_jobs_do_not_change_the_canonical_ticket_ranges() {
        let local = Address::from([0x11; 20]);
        let remote = Address::from([0x22; 20]);
        let mut backend = ScoreBackend::default();
        backend.add(local.to_string());
        backend.add(remote.to_string());

        let mut state = NodeStateStore {
            ticket_price: U256::from(10),
            ..Default::default()
        };
        state.nodes.insert(
            local.to_string(),
            NodeState {
                ticket_balance: U256::from(30),
                active_jobs: 2,
                ticket_balance_log_index: 0,
                active_log_index: 0,
                active: true,
                ticket_balance_history: vec![StateCheckpoint {
                    timepoint: 1,
                    value: U256::from(30),
                }],
                active_history: vec![StateCheckpoint {
                    timepoint: 1,
                    value: true,
                }],
            },
        );
        state.nodes.insert(
            remote.to_string(),
            NodeState {
                ticket_balance: U256::from(30),
                active_jobs: 3,
                ticket_balance_log_index: 0,
                active_log_index: 0,
                active: true,
                ticket_balance_history: vec![StateCheckpoint {
                    timepoint: 1,
                    value: U256::from(30),
                }],
                active_history: vec![StateCheckpoint {
                    timepoint: 1,
                    value: true,
                }],
            },
        );

        let snapshot = SortitionSnapshot {
            request_block: 2,
            ticket_price: U256::from(10),
        };

        let nodes = backend.build_nodes_from_state(1, &state, snapshot);
        assert_eq!(ticket_count(&nodes, local), Some(3));
        assert_eq!(ticket_count(&nodes, remote), Some(3));
    }

    #[test]
    fn selected_node_remains_a_member_when_local_capacity_is_exhausted() {
        let local = Address::from([0x11; 20]);
        let mut backend = ScoreBackend::default();
        backend.add(local.to_string());

        let mut state = NodeStateStore::default();
        state.nodes.insert(
            local.to_string(),
            NodeState {
                ticket_balance: U256::from(30),
                active_jobs: 3,
                ticket_balance_log_index: 0,
                active_log_index: 0,
                active: true,
                ticket_balance_history: vec![StateCheckpoint {
                    timepoint: 1,
                    value: U256::from(30),
                }],
                active_history: vec![StateCheckpoint {
                    timepoint: 1,
                    value: true,
                }],
            },
        );
        let snapshot = SortitionSnapshot {
            request_block: 2,
            ticket_price: U256::from(10),
        };
        let e3_id = E3id::new("1", 1);
        let seed = Seed::from(U256::from(1));

        assert!(backend
            .contains(
                e3_id.clone(),
                seed,
                1,
                local.to_string(),
                1,
                &state,
                snapshot,
            )
            .unwrap());
        assert_eq!(
            backend
                .get_index(
                    e3_id.clone(),
                    seed,
                    1,
                    local.to_string(),
                    1,
                    &state,
                    snapshot,
                )
                .unwrap(),
            None
        );

        state.nodes.get_mut(&local.to_string()).unwrap().active_jobs = 2;
        assert!(backend
            .get_index(
                e3_id.clone(),
                seed,
                1,
                local.to_string(),
                1,
                &state,
                snapshot,
            )
            .unwrap()
            .is_some());

        state.nodes.get_mut(&local.to_string()).unwrap().active_jobs = 3;
        state
            .e3_committees
            .insert(committee_key(&e3_id), vec![local.to_string()]);
        assert!(backend
            .get_index(e3_id, seed, 1, local.to_string(), 1, &state, snapshot,)
            .unwrap()
            .is_some());
    }

    #[test]
    fn uses_the_request_boundary_instead_of_same_timestamp_state() {
        let address = Address::from([0x33; 20]);
        let mut backend = ScoreBackend::default();
        backend.add(address.to_string());

        let mut state = NodeStateStore {
            ticket_price: U256::from(1),
            ..Default::default()
        };
        state.nodes.insert(
            address.to_string(),
            NodeState {
                ticket_balance: U256::from(100),
                active_jobs: 0,
                ticket_balance_log_index: 0,
                active_log_index: 0,
                active: true,
                ticket_balance_history: vec![
                    StateCheckpoint {
                        timepoint: 9,
                        value: U256::from(30),
                    },
                    StateCheckpoint {
                        timepoint: 10,
                        value: U256::from(100),
                    },
                ],
                active_history: vec![StateCheckpoint {
                    timepoint: 9,
                    value: true,
                }],
            },
        );

        let nodes = backend.build_nodes_from_state(
            1,
            &state,
            SortitionSnapshot {
                request_block: 10,
                ticket_price: U256::from(10),
            },
        );

        assert_eq!(ticket_count(&nodes, address), Some(3));
    }

    #[test]
    fn excludes_activation_at_the_request_timestamp() {
        let address = Address::from([0x44; 20]);
        let mut backend = ScoreBackend::default();
        backend.add(address.to_string());

        let mut state = NodeStateStore::default();
        state.nodes.insert(
            address.to_string(),
            NodeState {
                ticket_balance: U256::from(100),
                active_jobs: 0,
                ticket_balance_log_index: 0,
                active_log_index: 0,
                active: true,
                ticket_balance_history: vec![StateCheckpoint {
                    timepoint: 9,
                    value: U256::from(100),
                }],
                active_history: vec![StateCheckpoint {
                    timepoint: 10,
                    value: true,
                }],
            },
        );

        let nodes = backend.build_nodes_from_state(
            1,
            &state,
            SortitionSnapshot {
                request_block: 10,
                ticket_price: U256::from(10),
            },
        );

        assert!(nodes.is_empty());
    }

    #[test]
    fn keeps_nodes_that_were_active_at_the_request_boundary() {
        let address = Address::from([0x55; 20]);
        let mut backend = ScoreBackend::default();
        backend.add(address.to_string());

        let mut state = NodeStateStore::default();
        state.nodes.insert(
            address.to_string(),
            NodeState {
                ticket_balance: U256::from(100),
                active_jobs: 0,
                ticket_balance_log_index: 0,
                active_log_index: 0,
                active: false,
                ticket_balance_history: vec![StateCheckpoint {
                    timepoint: 9,
                    value: U256::from(100),
                }],
                active_history: vec![
                    StateCheckpoint {
                        timepoint: 9,
                        value: true,
                    },
                    StateCheckpoint {
                        timepoint: 11,
                        value: false,
                    },
                ],
            },
        );

        let nodes = backend.build_nodes_from_state(
            1,
            &state,
            SortitionSnapshot {
                request_block: 10,
                ticket_price: U256::from(10),
            },
        );

        assert_eq!(ticket_count(&nodes, address), Some(10));
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

    /// Apply the candidate limit to owners, without excluding their fallback operators.
    pub fn get_submission_index(
        &self,
        e3_id: E3id,
        seed: Seed,
        address: String,
        chain_id: u64,
        node_state: &NodeStateStore,
        snapshot: SortitionSnapshot,
        candidate_owners: usize,
        owner_state: &BondOwnerState,
    ) -> Result<Option<(u64, Option<u64>)>> {
        let want: Address = address.parse()?;
        if !ScoreBackend::has_local_capacity(node_state, &e3_id, want, snapshot) {
            return Ok(None);
        }
        let Self::Score(backend) = self;
        let nodes = backend.build_nodes_from_state(chain_id, node_state, snapshot);
        let Some(timepoint) = snapshot.request_block.checked_sub(1) else {
            return Ok(None);
        };
        let owners: std::collections::HashMap<_, _> = nodes
            .iter()
            .filter_map(|node| {
                owner_state
                    .owner_at(chain_id, node.address, timepoint)
                    .map(|owner| (node.address, owner))
            })
            .collect();
        let missing_owners = nodes.len() - owners.len();
        let winners = if missing_owners == 0 {
            ScoreSortition::new(candidate_owners)
                .get_owner_candidates(e3_id, seed, &nodes, &owners)?
        } else {
            // Incomplete historical data must not remove another owner's only candidate.
            // The contract still enforces the cap on every submitted ticket.
            tracing::warn!(
                chain_id,
                e3_id = %e3_id,
                timepoint,
                missing_owners,
                eligible_operators = nodes.len(),
                event = "sortition_owner_history_fallback",
                "Bond-owner history is incomplete; submitting without the owner shortlist"
            );
            ScoreSortition::new(nodes.len()).get_committee(e3_id, seed, &nodes)?
        };
        Ok(winners.iter().enumerate().find_map(|(rank, winner)| {
            (winner.address == want).then_some((rank as u64, Some(winner.ticket_id)))
        }))
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
        snapshot: SortitionSnapshot,
    ) -> anyhow::Result<bool> {
        match self {
            SortitionBackend::Score(b) => {
                b.contains(e3_id, seed, size, address, chain_id, node_state, snapshot)
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
        snapshot: SortitionSnapshot,
    ) -> anyhow::Result<Option<(u64, Option<u64>)>> {
        match self {
            SortitionBackend::Score(b) => {
                b.get_index(e3_id, seed, size, address, chain_id, node_state, snapshot)
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
