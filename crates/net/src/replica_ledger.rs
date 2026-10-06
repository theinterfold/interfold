// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The DHT records that other peers stored on this node, by the peer that sent each one.
//!
//! An inbound replica is evicted to make room instead of the new record being refused: the sender
//! at its own limit gives up its oldest replica, and under node-wide pressure the sender over its
//! fair share gives up its oldest. This node's own publications and the documents that it restored
//! are never in the ledger, so they are never evicted for a replica.

use crate::ingress_limits::eviction_owner;
use libp2p::PeerId;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Limits on the inbound replicas that one node keeps.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReplicaLimits {
    /// Replicas from one sender.
    pub per_owner: usize,
    /// Replicas in total.
    pub records: usize,
    /// Value bytes of all replicas.
    pub bytes: usize,
}

struct Replica {
    owner: PeerId,
    bytes: usize,
    order: u64,
}

pub(crate) struct ReplicaLedger {
    limits: ReplicaLimits,
    replicas: HashMap<Vec<u8>, Replica>,
    /// Each owner's replicas, oldest first. Every entry has a replica, and every replica has one
    /// entry.
    by_owner: HashMap<PeerId, BTreeMap<u64, Vec<u8>>>,
    bytes: usize,
    next_order: u64,
}

impl ReplicaLedger {
    pub(crate) fn new(limits: ReplicaLimits) -> Self {
        Self {
            limits,
            replicas: HashMap::new(),
            by_owner: HashMap::new(),
            bytes: 0,
            next_order: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, key: &[u8]) -> bool {
        self.replicas.contains_key(key)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.replicas.len()
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    pub(crate) fn owned_by(&self, owner: &PeerId) -> usize {
        self.by_owner.get(owner).map_or(0, BTreeMap::len)
    }

    /// Record a new replica from `owner`. A key that the ledger holds keeps its owner and place.
    pub(crate) fn insert(&mut self, key: Vec<u8>, owner: PeerId, bytes: usize) {
        if self.replicas.contains_key(&key) {
            return;
        }
        let order = self.next_order;
        self.next_order += 1;
        self.by_owner
            .entry(owner)
            .or_default()
            .insert(order, key.clone());
        self.bytes = self.bytes.saturating_add(bytes);
        self.replicas.insert(
            key,
            Replica {
                owner,
                bytes,
                order,
            },
        );
    }

    /// Forget a replica, because the store removed it or the node now publishes it itself.
    pub(crate) fn remove(&mut self, key: &[u8]) -> bool {
        let Some(replica) = self.replicas.remove(key) else {
            return false;
        };
        self.bytes = self.bytes.saturating_sub(replica.bytes);
        if let Some(keys) = self.by_owner.get_mut(&replica.owner) {
            keys.remove(&replica.order);
            if keys.is_empty() {
                self.by_owner.remove(&replica.owner);
            }
        }
        true
    }

    /// Forget the replicas that the store no longer holds as replicas, for example after Kademlia
    /// removed an expired record during a lookup.
    pub(crate) fn retain(&mut self, mut held: impl FnMut(&[u8]) -> bool) {
        let gone: Vec<_> = self
            .replicas
            .keys()
            .filter(|key| !held(key))
            .cloned()
            .collect();
        for key in gone {
            self.remove(&key);
        }
    }

    /// The replicas to evict so that a new one of `bytes` from `owner` fits, with `free_records`
    /// records free in the store, or `None` when it cannot fit. Nothing changes until the caller
    /// removes them.
    pub(crate) fn room_for(
        &self,
        owner: PeerId,
        bytes: usize,
        free_records: usize,
    ) -> Option<Vec<Vec<u8>>> {
        if bytes > self.limits.bytes {
            return None;
        }
        let mut evicted = Evicted::default();
        // A sender at its own limit gives up its oldest replica.
        let own = self.by_owner.get(&owner).map_or(0, BTreeMap::len);
        for _ in self.limits.per_owner.saturating_sub(1)..own {
            self.evict_oldest_of(&owner, &mut evicted)?;
        }
        loop {
            let records = self.replicas.len() - evicted.keys.len() + 1;
            let room = free_records + evicted.keys.len();
            let short_of_bytes = self.bytes - evicted.bytes + bytes > self.limits.bytes;
            if records <= self.limits.records && room >= 1 && !short_of_bytes {
                return Some(evicted.keys);
            }
            // The sender over its share in the dimension that is short gives up its oldest.
            let (weights, capacity): (Vec<_>, _) = if short_of_bytes {
                (
                    self.weights(&evicted, |replica| replica.bytes),
                    self.limits.bytes,
                )
            } else {
                (self.weights(&evicted, |_| 1), self.limits.records)
            };
            let chosen = eviction_owner(
                Some(owner),
                weights.iter().map(|(peer, weight)| (Some(*peer), *weight)),
                capacity,
            );
            let victim_owner = chosen
                .filter(|peer| {
                    weights
                        .iter()
                        .any(|(other, weight)| other == peer && *weight > 0)
                })
                .or_else(|| {
                    weights
                        .iter()
                        .filter(|(_, weight)| *weight > 0)
                        .max_by_key(|(_, weight)| *weight)
                        .map(|(peer, _)| *peer)
                })?;
            self.evict_oldest_of(&victim_owner, &mut evicted)?;
        }
    }

    /// The replica to evict so that one more local record fits in a full store: the oldest of the
    /// owner with the most replicas.
    pub(crate) fn room_for_local(&self) -> Option<Vec<u8>> {
        let (_, keys) = self.by_owner.iter().max_by_key(|(_, keys)| keys.len())?;
        keys.values().next().cloned()
    }

    /// Each owner's remaining weight, without the replicas already chosen.
    fn weights(
        &self,
        evicted: &Evicted,
        weight: impl Fn(&Replica) -> usize,
    ) -> Vec<(PeerId, usize)> {
        self.by_owner
            .iter()
            .map(|(peer, keys)| {
                let remaining = keys
                    .values()
                    .filter(|key| !evicted.chosen.contains(*key))
                    .filter_map(|key| self.replicas.get(key))
                    .map(&weight)
                    .sum();
                (*peer, remaining)
            })
            .collect()
    }

    fn evict_oldest_of(&self, owner: &PeerId, evicted: &mut Evicted) -> Option<()> {
        let key = self
            .by_owner
            .get(owner)?
            .values()
            .find(|key| !evicted.chosen.contains(*key))?;
        let replica = self.replicas.get(key)?;
        evicted.bytes += replica.bytes;
        evicted.chosen.insert(key.clone());
        evicted.keys.push(key.clone());
        Some(())
    }
}

#[derive(Default)]
struct Evicted {
    keys: Vec<Vec<u8>>,
    chosen: HashSet<Vec<u8>>,
    bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(per_owner: usize, records: usize, bytes: usize) -> ReplicaLimits {
        ReplicaLimits {
            per_owner,
            records,
            bytes,
        }
    }

    fn key(index: u8) -> Vec<u8> {
        vec![index]
    }

    #[test]
    fn a_sender_at_its_limit_gives_up_its_oldest_replica() {
        let (sender, other) = (PeerId::random(), PeerId::random());
        let mut ledger = ReplicaLedger::new(limits(2, 10, 1_000));
        ledger.insert(key(1), sender, 10);
        ledger.insert(key(2), other, 10);
        ledger.insert(key(3), sender, 10);

        assert_eq!(ledger.room_for(sender, 10, 5), Some(vec![key(1)]));
        assert_eq!(ledger.room_for(other, 10, 5), Some(vec![]));
    }

    #[test]
    fn under_node_wide_pressure_the_largest_sender_gives_up_its_oldest() {
        let (large, small, incoming) = (PeerId::random(), PeerId::random(), PeerId::random());
        let mut ledger = ReplicaLedger::new(limits(10, 4, 1_000));
        ledger.insert(key(1), small, 10);
        ledger.insert(key(2), large, 10);
        ledger.insert(key(3), large, 10);
        ledger.insert(key(4), large, 10);

        assert_eq!(ledger.room_for(incoming, 10, 5), Some(vec![key(2)]));
        // A full store needs room too, also below the replica limit.
        ledger.remove(&key(4));
        assert_eq!(ledger.room_for(incoming, 10, 0), Some(vec![key(2)]));
    }

    #[test]
    fn a_large_replica_evicts_as_many_small_ones_as_its_bytes_need() {
        let (small, incoming) = (PeerId::random(), PeerId::random());
        let mut ledger = ReplicaLedger::new(limits(100, 100, 50));
        for index in 0..10 {
            ledger.insert(key(index), small, 5);
        }

        let victims = ledger.room_for(incoming, 25, 50).unwrap();
        assert_eq!(victims, (0..5).map(key).collect::<Vec<_>>());
        // A replica larger than the whole budget never fits, and nothing is chosen.
        assert_eq!(ledger.room_for(incoming, 51, 50), None);
        assert_eq!(ledger.len(), 10);
    }

    #[test]
    fn a_full_store_without_replicas_refuses_a_new_one() {
        let ledger = ReplicaLedger::new(limits(10, 10, 100));
        assert_eq!(ledger.room_for(PeerId::random(), 10, 0), None);
        assert_eq!(ledger.room_for_local(), None);
    }

    #[test]
    fn insertions_removals_and_reconciliation_keep_one_entry_per_replica() {
        let (owner, other) = (PeerId::random(), PeerId::random());
        let mut ledger = ReplicaLedger::new(limits(10, 10, 100));
        ledger.insert(key(1), owner, 10);
        // A refresh keeps the owner and the place.
        ledger.insert(key(1), other, 30);
        assert_eq!(
            (ledger.len(), ledger.bytes(), ledger.owned_by(&owner)),
            (1, 10, 1)
        );
        assert_eq!(ledger.owned_by(&other), 0);

        // A removed and inserted key is the newest, not evicted through its old place.
        ledger.insert(key(2), owner, 10);
        ledger.remove(&key(1));
        ledger.insert(key(1), owner, 10);
        assert_eq!(ledger.room_for_local(), Some(key(2)));

        ledger.retain(|key| key == [1]);
        assert_eq!((ledger.len(), ledger.bytes()), (1, 10));
        assert!(ledger.contains(&key(1)) && !ledger.contains(&key(2)));
        ledger.remove(&key(1));
        assert_eq!(
            (ledger.len(), ledger.bytes(), ledger.owned_by(&owner)),
            (0, 0, 0)
        );
        assert!(ledger.by_owner.is_empty());
    }
}
