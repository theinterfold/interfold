// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Capacity planning for four concurrent N=19, H=14 committees, with a 2x margin.

pub(crate) const COMMITTEE_SIZE: usize = 19;
const CONCURRENT_E3S: usize = 4;
const MARGIN: usize = 2;
// C0 keys, recipient C2/C3 bundles, and C4 bundles.
const DOCUMENTS_PER_E3: usize = COMMITTEE_SIZE * (COMMITTEE_SIZE - 1) + 2 * COMMITTEE_SIZE;
// Six Ready updates per party, C1, NodeFold, C6, roster, and public-key result.
const PUBLICATIONS_PER_E3: usize = DOCUMENTS_PER_E3 + 9 * COMMITTEE_SIZE + 2;
const PUBLICATION_ROUND: usize = CONCURRENT_E3S * PUBLICATIONS_PER_E3 * MARGIN;
// Reserve the initial round and the three retries before the five-minute retry interval.
pub(crate) const SEEN_BURST: usize = 4 * PUBLICATION_ROUND;
pub(crate) const SEEN_RATE: usize = PUBLICATION_ROUND.div_ceil(5 * 60);
// A node holds the replicas of the documents of the other dealers: with replication factor 20
// and committees of 19, every node is among the closest peers of every key.
const DOCUMENTS_PER_DEALER: usize = DOCUMENTS_PER_E3 / COMMITTEE_SIZE;
pub(crate) const REPLICAS_PER_PEER: usize = DOCUMENTS_PER_DEALER * CONCURRENT_E3S * MARGIN;
pub(crate) const REPLICAS: usize = DOCUMENTS_PER_E3 * CONCURRENT_E3S * MARGIN;
/// A memory ceiling, not the whole load: four E3s of threshold-share documents near their
/// historical 1.78 MB need about 2.3 GB of replicas, so at that load a node keeps the newest 2 GiB
/// and evicts the oldest. The dealers keep their own documents, and other closest peers keep
/// replicas too.
pub(crate) const REPLICA_BYTES: usize = 2 * 1024 * 1024 * 1024;
// Before selection the receiver does not yet know which recipient bundles it needs.
pub(crate) const EARLY_NOTIFICATIONS: usize = CONCURRENT_E3S * DOCUMENTS_PER_E3 * MARGIN;
// Each selected node needs three remote documents from each other dealer.
pub(crate) const WAITING_FETCHES: usize =
    (CONCURRENT_E3S * 3 * (COMMITTEE_SIZE - 1) * MARGIN).next_power_of_two();

/// Choose the owner that makes room at capacity. Peers below their share reclaim borrowed space.
pub(crate) fn eviction_owner(
    incoming: Option<libp2p::PeerId>,
    owners: impl Iterator<Item = (Option<libp2p::PeerId>, usize)>,
    capacity: usize,
) -> Option<libp2p::PeerId> {
    let (mut own, mut count, mut largest) = (0, 0, (None, 0));
    for (peer, size) in owners {
        count += 1;
        if peer == incoming {
            own = size;
        }
        if size > largest.1 {
            largest = (peer, size);
        }
    }
    let share = (capacity / (count + usize::from(own == 0))).max(1);
    if own >= share {
        incoming
    } else {
        largest.0
    }
}
