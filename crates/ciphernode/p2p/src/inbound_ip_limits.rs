// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The inbound connection limits per remote address group.
//!
//! A peer ID costs nothing to make, so the per-peer limit does not stop one host from holding every
//! inbound slot. This behaviour counts the pending and established inbound connections of each IPv4
//! address and each IPv6 /56 prefix, and refuses a new connection at the limit before it is
//! established. Until its peer identifies on this network, an established inbound connection also
//! waits in a bounded set; past the bound, the oldest waiting connection of the group with the
//! most waiting closes, so a few hosts cannot fill the inbound slots with peers that never
//! identify. Loopback connections do not count: they come from this host, and local networks run
//! many nodes on one address.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    fmt,
    net::{IpAddr, Ipv6Addr},
    task::{Context, Poll, Waker},
};

use libp2p::{
    core::{transport::PortUse, Endpoint},
    multiaddr::Protocol,
    swarm::{
        behaviour::ListenFailure, dummy, CloseConnection, ConnectionClosed, ConnectionDenied,
        ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent,
        ToSwarm,
    },
    Multiaddr, PeerId,
};

/// The inbound connections, pending and established, that one address group may hold. The
/// go-libp2p resource manager uses the same default for one IPv4 address.
pub(crate) const MAX_INBOUND_PER_ADDRESS_GROUP: usize = 8;
/// One host can use every address of its IPv6 allocation, so a group covers a /56 prefix.
const IPV6_GROUP_PREFIX_BITS: u32 = 56;
/// The established inbound connections that may wait for their peers to identify at once.
pub(crate) const MAX_WAITING_FOR_IDENTIFY: usize = 16;

/// An IPv4 address, or an IPv6 address masked to its /56 prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct AddressGroup(IpAddr);

impl fmt::Display for AddressGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            IpAddr::V4(ip) => write!(f, "{ip}"),
            IpAddr::V6(ip) => write!(f, "{ip}/{IPV6_GROUP_PREFIX_BITS}"),
        }
    }
}

/// The group that a remote address counts against. A loopback address, and an address that does
/// not start with an IP address, count against none.
pub(crate) fn address_group(address: &Multiaddr) -> Option<AddressGroup> {
    let ip = match address.iter().next()? {
        Protocol::Ip4(ip) => IpAddr::V4(ip),
        // A dual-stack listener reports an IPv4 client as an IPv4-mapped IPv6 address.
        Protocol::Ip6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        _ => return None,
    };
    if ip.is_loopback() {
        return None;
    }
    Some(AddressGroup(match ip {
        IpAddr::V6(ip) => {
            let mask = u128::MAX << (128 - IPV6_GROUP_PREFIX_BITS);
            IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask))
        }
        ip => ip,
    }))
}

/// The reason for an inbound connection that the address-group limit refuses.
#[derive(Debug)]
pub(crate) struct AddressGroupLimit(AddressGroup);

impl fmt::Display for AddressGroupLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} already holds {MAX_INBOUND_PER_ADDRESS_GROUP} inbound connections",
            self.0
        )
    }
}

impl std::error::Error for AddressGroupLimit {}

/// Public only because the swarm's behaviour, which holds it, needs it to be.
#[derive(Default)]
pub struct InboundIpLimits {
    /// The address group of each pending or established inbound connection that counts.
    connections: HashMap<ConnectionId, AddressGroup>,
    /// The established inbound connections whose peers have not identified yet, oldest first.
    waiting: VecDeque<(ConnectionId, PeerId, AddressGroup)>,
    /// Waiting connections closed to make room, for the swarm to close.
    closing: VecDeque<(PeerId, ConnectionId)>,
    waker: Option<Waker>,
}

impl InboundIpLimits {
    /// `peer` identified on this network: its connections no longer wait.
    pub(crate) fn identified(&mut self, peer: &PeerId) {
        self.waiting.retain(|(_, waiting, _)| waiting != peer);
    }

    /// Closes the oldest waiting connection of the address group with the most waiting.
    fn make_room(&mut self) {
        let mut counts: HashMap<AddressGroup, usize> = HashMap::new();
        for (_, _, group) in &self.waiting {
            *counts.entry(*group).or_default() += 1;
        }
        let most = counts.values().copied().max().unwrap_or_default();
        let oldest = self
            .waiting
            .iter()
            .position(|(_, _, group)| counts[group] == most);
        if let Some((connection, peer, _)) = oldest.and_then(|index| self.waiting.remove(index)) {
            self.closing.push_back((peer, connection));
            if let Some(waker) = self.waker.take() {
                waker.wake();
            }
        }
    }
}

/// The swarm calls the pending check of every inbound connection before its handshake, and reports
/// a connection that does not become established, for any reason, as a listen failure.
impl NetworkBehaviour for InboundIpLimits {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        let Some(group) = address_group(remote) else {
            return Ok(());
        };
        let held = self
            .connections
            .values()
            .filter(|held| **held == group)
            .count();
        if held >= MAX_INBOUND_PER_ADDRESS_GROUP {
            return Err(ConnectionDenied::new(AddressGroupLimit(group)));
        }
        self.connections.insert(connection_id, group);
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if let Some(group) = address_group(remote) {
            self.waiting.push_back((connection_id, peer, group));
            if self.waiting.len() > MAX_WAITING_FOR_IDENTIFY {
                self.make_room();
            }
        }
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionClosed(ConnectionClosed { connection_id, .. })
            | FromSwarm::ListenFailure(ListenFailure { connection_id, .. }) => {
                self.connections.remove(&connection_id);
                self.waiting
                    .retain(|(waiting, ..)| *waiting != connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some((peer_id, connection)) = self.closing.pop_front() {
            return Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection: CloseConnection::One(connection),
            });
        }
        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{core::ConnectedPoint, swarm::ListenError};

    use super::*;

    fn quic(ip: &str, port: usize) -> Multiaddr {
        let ip = if ip.contains(':') {
            format!("/ip6/{ip}")
        } else {
            format!("/ip4/{ip}")
        };
        format!("{ip}/udp/{port}/quic-v1").parse().unwrap()
    }

    fn open(limits: &mut InboundIpLimits, id: usize, ip: &str) -> Result<(), ConnectionDenied> {
        limits.handle_pending_inbound_connection(
            ConnectionId::new_unchecked(id),
            &quic("0.0.0.0", 9091),
            &quic(ip, 4000 + id),
        )
    }

    #[test]
    fn an_address_holds_at_most_the_limit_until_one_of_its_connections_ends() {
        let mut limits = InboundIpLimits::default();
        for id in 0..MAX_INBOUND_PER_ADDRESS_GROUP {
            open(&mut limits, id, "203.0.113.7").unwrap();
        }
        let refused = open(&mut limits, 100, "203.0.113.7").unwrap_err();
        assert!(refused.downcast_ref::<AddressGroupLimit>().is_some());
        open(&mut limits, 101, "203.0.113.8").unwrap();
        for id in 200..240 {
            open(&mut limits, id, "127.0.0.1").unwrap();
        }

        let local = quic("0.0.0.0", 9091);
        let remote = quic("203.0.113.7", 4000);
        limits.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: PeerId::random(),
            connection_id: ConnectionId::new_unchecked(0),
            endpoint: &ConnectedPoint::Listener {
                local_addr: local.clone(),
                send_back_addr: remote.clone(),
            },
            cause: None,
            remaining_established: 0,
        }));
        open(&mut limits, 102, "203.0.113.7").unwrap();
        open(&mut limits, 103, "203.0.113.7").unwrap_err();

        limits.on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
            local_addr: &local,
            send_back_addr: &remote,
            error: &ListenError::Aborted,
            connection_id: ConnectionId::new_unchecked(1),
            peer_id: None,
        }));
        open(&mut limits, 104, "203.0.113.7").unwrap();
    }

    fn established(limits: &mut InboundIpLimits, id: usize, ip: &str) -> PeerId {
        open(limits, id, ip).unwrap();
        let peer = PeerId::random();
        let (local, remote) = (quic("0.0.0.0", 9091), quic(ip, 4000 + id));
        let id = ConnectionId::new_unchecked(id);
        limits
            .handle_established_inbound_connection(id, peer, &local, &remote)
            .unwrap();
        peer
    }

    fn closed(limits: &mut InboundIpLimits) -> Vec<ConnectionId> {
        let mut cx = Context::from_waker(Waker::noop());
        let mut closed = Vec::new();
        while let Poll::Ready(ToSwarm::CloseConnection {
            connection: CloseConnection::One(id),
            ..
        }) = limits.poll(&mut cx)
        {
            closed.push(id);
        }
        closed
    }

    #[test]
    fn a_connection_past_the_identify_limit_closes_the_oldest_of_the_busiest_group() {
        let mut limits = InboundIpLimits::default();
        for id in 0..8 {
            established(&mut limits, id, "203.0.113.1");
        }
        for id in 8..12 {
            established(&mut limits, id, "203.0.113.2");
        }
        let identifies = established(&mut limits, 12, "203.0.113.3");
        for id in 13..MAX_WAITING_FOR_IDENTIFY {
            established(&mut limits, id, "203.0.113.3");
        }
        for id in 100..110 {
            established(&mut limits, id, "127.0.0.1");
        }
        assert!(closed(&mut limits).is_empty());

        established(&mut limits, 16, "203.0.113.4");
        assert_eq!(closed(&mut limits), [ConnectionId::new_unchecked(0)]);
        limits.identified(&identifies);
        established(&mut limits, 17, "203.0.113.4");
        assert!(closed(&mut limits).is_empty());
    }

    #[test]
    fn a_group_is_one_ipv4_address_or_one_ipv6_56_prefix_and_loopback_is_none() {
        let group = |ip| address_group(&quic(ip, 1));
        assert_eq!(group("2001:db8:0:ff::1"), group("2001:db8:0:1::2"));
        assert_ne!(group("2001:db8:0:100::1"), group("2001:db8:0:1::1"));
        assert_eq!(group("::ffff:203.0.113.7"), group("203.0.113.7"));
        assert_ne!(group("203.0.113.7"), group("203.0.113.8"));
        assert_eq!(group("127.0.0.1"), None);
        assert_eq!(group("::1"), None);
        assert_eq!(
            address_group(&"/dns4/example.com/udp/1/quic-v1".parse().unwrap()),
            None
        );
    }
}
