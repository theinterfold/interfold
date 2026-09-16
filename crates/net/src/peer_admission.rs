// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use libp2p::{swarm::ConnectionId, Multiaddr, PeerId};

use crate::events::PeerRejectionKind;

const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(30);
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

#[derive(Default)]
pub(crate) struct PeerAdmission {
    pending: HashMap<PeerId, Vec<PendingPeer>>,
    admitted: HashSet<PeerId>,
    rejected_until: HashMap<PeerId, (PeerRejectionKind, Instant)>,
}

impl PeerAdmission {
    pub(crate) fn stage(
        &mut self,
        peer: PeerId,
        pending: PendingPeer,
    ) -> Result<(), PeerRejectionKind> {
        self.prune_rejections();
        if let Some(kind) = self.rejection_kind(&peer) {
            return Err(kind);
        }
        let connections = self.pending.entry(peer).or_default();
        if !connections
            .iter()
            .any(|current| current.connection_id == pending.connection_id)
        {
            connections.push(pending);
        }
        Ok(())
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
        if let Some(connections) = self.pending.get_mut(peer) {
            connections.retain(|pending| pending.connection_id != connection_id);
            if connections.is_empty() {
                self.pending.remove(peer);
            }
        }
        if remaining_connections == 0 {
            self.admitted.remove(peer);
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
