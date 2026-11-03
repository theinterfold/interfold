// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use libp2p::{swarm::ConnectionId, Multiaddr, PeerId};

use crate::{
    events::PeerRejectionKind,
    inbound_ip_limits::{address_group, AddressGroup},
};

const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(30);
/// The inbound connections from remote addresses that may wait for Identify at once, so that
/// connections that never identify hold few of the inbound slots. A new connection over the limit
/// does not wait for one to end: the oldest waiting connection of the address group with the most
/// waiting connections closes instead, which keeps a flood from one group from shutting out new
/// peers. Loopback connections do not count.
pub(crate) const MAX_STAGED_INBOUND: usize = 16;
const PERMANENT_REJECTION_TTL: Duration = Duration::from_secs(10 * 60);
const TRANSIENT_REJECTION_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub(crate) struct PendingPeer {
    pub(crate) connection_id: ConnectionId,
    pub(crate) remote_address: Multiaddr,
    pub(crate) direction: &'static str,
    pub(crate) connections: u32,
    established_at: Instant,
}

impl PendingPeer {
    /// The address group that this connection counts against while it waits, if it is inbound.
    fn inbound_group(&self) -> Option<AddressGroup> {
        (self.direction == "inbound")
            .then(|| address_group(&self.remote_address))
            .flatten()
    }
}

#[derive(Default)]
pub(crate) struct PeerAdmission {
    pending: HashMap<PeerId, Vec<PendingPeer>>,
    admitted: HashSet<PeerId>,
    rejected_until: HashMap<PeerId, (PeerRejectionKind, Instant)>,
}

impl PeerAdmission {
    /// Stage a connection until its peer completes Identify. Returns the staged inbound connection
    /// that must close to keep the waiting inbound connections within `MAX_STAGED_INBOUND`.
    pub(crate) fn stage(
        &mut self,
        peer: PeerId,
        pending: PendingPeer,
    ) -> Result<Option<(PeerId, ConnectionId)>, PeerRejectionKind> {
        self.prune_rejections();
        if let Some(kind) = self.rejection_kind(&peer) {
            return Err(kind);
        }
        let connections = self.pending.entry(peer).or_default();
        if connections
            .iter()
            .any(|current| current.connection_id == pending.connection_id)
        {
            return Ok(None);
        }
        connections.push(pending);
        Ok(self.evict_staged_inbound())
    }

    fn evict_staged_inbound(&mut self) -> Option<(PeerId, ConnectionId)> {
        let staged: Vec<_> = self
            .pending
            .iter()
            .flat_map(|(peer, connections)| {
                connections.iter().filter_map(move |connection| {
                    let group = connection.inbound_group()?;
                    Some((*peer, connection, group))
                })
            })
            .collect();
        if staged.len() <= MAX_STAGED_INBOUND {
            return None;
        }
        let mut per_group = HashMap::<AddressGroup, usize>::new();
        for (_, _, group) in &staged {
            *per_group.entry(*group).or_default() += 1;
        }
        let (peer, connection_id) = staged
            .iter()
            .max_by_key(|(_, connection, group)| {
                (per_group[group], Reverse(connection.established_at))
            })
            .map(|(peer, connection, _)| (*peer, connection.connection_id))?;
        self.unstage(&peer, connection_id);
        Some((peer, connection_id))
    }

    pub(crate) fn pending(
        connection_id: ConnectionId,
        remote_address: Multiaddr,
        direction: &'static str,
        connections: u32,
    ) -> PendingPeer {
        PendingPeer {
            connection_id,
            remote_address,
            direction,
            connections,
            established_at: Instant::now(),
        }
    }

    pub(crate) fn admit(&mut self, peer: PeerId) -> Option<Vec<PendingPeer>> {
        let pending = self.pending.remove(&peer)?;
        self.rejected_until.remove(&peer);
        self.admitted.insert(peer);
        Some(pending)
    }

    pub(crate) fn pending_connections(&self, peer: &PeerId) -> Vec<PendingPeer> {
        self.pending.get(peer).cloned().unwrap_or_default()
    }

    /// Reject a peer and return true for the first rejection in the TTL window.
    pub(crate) fn reject(&mut self, peer: PeerId, kind: PeerRejectionKind) -> bool {
        self.pending.remove(&peer);
        self.admitted.remove(&peer);
        let first = !self.is_rejected(&peer);
        let ttl = match kind {
            PeerRejectionKind::Transient => TRANSIENT_REJECTION_TTL,
            PeerRejectionKind::Permanent => PERMANENT_REJECTION_TTL,
        };
        self.rejected_until
            .insert(peer, (kind, Instant::now() + ttl));
        first
    }

    pub(crate) fn is_admitted(&self, peer: &PeerId) -> bool {
        self.admitted.contains(peer)
    }

    pub(crate) fn closed(
        &mut self,
        peer: &PeerId,
        connection_id: ConnectionId,
        remaining_connections: u32,
    ) {
        self.unstage(peer, connection_id);
        if remaining_connections == 0 {
            self.admitted.remove(peer);
        }
    }

    fn unstage(&mut self, peer: &PeerId, connection_id: ConnectionId) {
        if let Some(connections) = self.pending.get_mut(peer) {
            connections.retain(|pending| pending.connection_id != connection_id);
            if connections.is_empty() {
                self.pending.remove(peer);
            }
        }
    }

    pub(crate) fn expired_pending(&mut self) -> Vec<(PeerId, Vec<PendingPeer>)> {
        let now = Instant::now();
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                pending.iter().any(|connection| {
                    now.duration_since(connection.established_at) >= IDENTIFY_TIMEOUT
                })
            })
            .map(|(peer, pending)| (*peer, pending.clone()))
            .collect();
        for (peer, _) in &expired {
            self.reject(*peer, PeerRejectionKind::Transient);
        }
        expired
    }

    pub(crate) fn is_rejected(&self, peer: &PeerId) -> bool {
        self.rejected_until
            .get(peer)
            .is_some_and(|(_, until)| *until > Instant::now())
    }

    fn rejection_kind(&self, peer: &PeerId) -> Option<PeerRejectionKind> {
        self.rejected_until
            .get(peer)
            .filter(|(_, until)| *until > Instant::now())
            .map(|(kind, _)| *kind)
    }

    fn prune_rejections(&mut self) {
        let now = Instant::now();
        self.rejected_until.retain(|_, (_, until)| *until > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_peer_is_not_staged_again_during_ttl() {
        let peer = PeerId::random();
        let mut admission = PeerAdmission::default();
        assert!(admission.reject(peer, PeerRejectionKind::Permanent));
        assert!(!admission.reject(peer, PeerRejectionKind::Permanent));
        assert_eq!(
            admission.stage(
                peer,
                PeerAdmission::pending(
                    ConnectionId::new_unchecked(1),
                    "/ip4/127.0.0.1/udp/1/quic-v1".parse().unwrap(),
                    "inbound",
                    1,
                )
            ),
            Err(PeerRejectionKind::Permanent)
        );
    }

    #[test]
    fn stages_all_simultaneous_connections_for_one_peer() {
        let peer = PeerId::random();
        let mut admission = PeerAdmission::default();
        for connection in 1_u32..=2 {
            admission
                .stage(
                    peer,
                    PeerAdmission::pending(
                        ConnectionId::new_unchecked(connection as usize),
                        format!("/ip4/127.0.0.1/udp/{connection}/quic-v1")
                            .parse()
                            .unwrap(),
                        "inbound",
                        connection,
                    ),
                )
                .unwrap();
        }

        let pending = admission.admit(peer).unwrap();
        assert_eq!(pending.len(), 2);
    }

    /// Stages one connection of a new peer, `age_ms` milliseconds after `start`.
    fn stage_at(
        admission: &mut PeerAdmission,
        start: Instant,
        age_ms: u64,
        id: usize,
        address: &str,
        direction: &'static str,
    ) -> (PeerId, Option<(PeerId, ConnectionId)>) {
        let peer = PeerId::random();
        let mut pending = PeerAdmission::pending(
            ConnectionId::new_unchecked(id),
            address.parse().unwrap(),
            direction,
            1,
        );
        pending.established_at = start + Duration::from_millis(age_ms);
        (peer, admission.stage(peer, pending).unwrap())
    }

    #[test]
    fn a_full_staging_pool_closes_the_oldest_connection_of_the_largest_address_group() {
        let start = Instant::now();
        let mut admission = PeerAdmission::default();
        let half = MAX_STAGED_INBOUND / 2;
        for id in 0..half {
            let address = format!("/ip4/203.0.113.{id}/udp/1/quic-v1");
            let (_, evicted) = stage_at(&mut admission, start, id as u64, id, &address, "inbound");
            assert_eq!(evicted, None);
        }
        let mut flood = Vec::new();
        for id in half..MAX_STAGED_INBOUND {
            let address = format!("/ip4/198.51.100.9/udp/{id}/quic-v1");
            let (peer, evicted) =
                stage_at(&mut admission, start, id as u64, id, &address, "inbound");
            assert_eq!(evicted, None);
            flood.push(peer);
        }

        // The other addresses hold the oldest connections, but the flood's address holds the most.
        let (newest, evicted) = stage_at(
            &mut admission,
            start,
            100,
            100,
            "/ip4/203.0.113.100/udp/1/quic-v1",
            "inbound",
        );
        assert_eq!(evicted, Some((flood[0], ConnectionId::new_unchecked(half))));
        assert!(admission.pending_connections(&flood[0]).is_empty());
        assert_eq!(admission.pending_connections(&newest).len(), 1);

        // When every address holds the same number, the oldest connection closes.
        let mut admission = PeerAdmission::default();
        let mut first = None;
        for id in 0..=MAX_STAGED_INBOUND {
            let address = format!("/ip4/203.0.113.{id}/udp/1/quic-v1");
            let (peer, evicted) =
                stage_at(&mut admission, start, id as u64, id, &address, "inbound");
            first.get_or_insert(peer);
            let expected = (id == MAX_STAGED_INBOUND)
                .then(|| (first.unwrap(), ConnectionId::new_unchecked(0)));
            assert_eq!(evicted, expected);
        }
    }

    #[test]
    fn loopback_and_outbound_connections_do_not_fill_the_staging_pool() {
        let start = Instant::now();
        let mut admission = PeerAdmission::default();
        for id in 0..4 * MAX_STAGED_INBOUND {
            let loopback = format!("/ip4/127.0.0.1/udp/{id}/quic-v1");
            let (_, evicted) = stage_at(&mut admission, start, 0, id, &loopback, "inbound");
            assert_eq!(evicted, None);
            let remote = format!("/ip4/203.0.113.7/udp/{id}/quic-v1");
            let (_, evicted) = stage_at(&mut admission, start, 0, 1000 + id, &remote, "outbound");
            assert_eq!(evicted, None);
        }
    }

    #[test]
    fn identify_timeout_uses_a_transient_rejection() {
        let peer = PeerId::random();
        let mut admission = PeerAdmission::default();
        let mut pending = PeerAdmission::pending(
            ConnectionId::new_unchecked(1),
            "/ip4/127.0.0.1/udp/1/quic-v1".parse().unwrap(),
            "inbound",
            1,
        );
        pending.established_at = Instant::now() - IDENTIFY_TIMEOUT;
        admission.stage(peer, pending).unwrap();

        assert_eq!(admission.expired_pending().len(), 1);
        assert_eq!(
            admission.rejection_kind(&peer),
            Some(PeerRejectionKind::Transient)
        );
    }
}
