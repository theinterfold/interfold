// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The QUIC transport of the swarm, wrapped below the DNS layer. Every dial passes here with the
//! concrete address it uses, also a dial of an address that a `/dnsaddr` resolved to.
//!
//! The wrapper refuses a dial that reaches this node: an address this node listens on, or a loopback
//! or unspecified address on one of its ports. Nodes listen on the same default port, and nodes in
//! containers on a default bridge network share interface addresses, so such an address can arrive
//! as another peer's address. That dial also wins the race against the peer's other addresses:
//! libp2p keeps the first connection that completes, and then fails the whole dial with a peer-ID
//! mismatch.
//!
//! The wrapper also keeps the concrete addresses of recent successful dials. When a configured
//! address produces an admitted connection, the node keeps the concrete address, so the
//! configured-peer redial can reach that peer again without DNS. libp2p reads the resolver
//! configuration only when the node starts.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{ready, Context, Poll},
};

use futures::{future::BoxFuture, FutureExt};
use libp2p::{
    core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent},
    multiaddr::Protocol,
    Multiaddr, PeerId,
};

use crate::net_interface::strip_peer_id;

/// How many recent dials the wrapper keeps. It only has to bridge the time between a dial and the
/// admission of its connection.
const RECENT_DIALS: usize = 256;
/// Longer addresses are not kept.
const MAX_KEPT_ADDRESS_BYTES: usize = 256;

/// The concrete address of the most recent successful dial of each peer, for at most
/// `RECENT_DIALS` peers. The transport writes it and the swarm loop reads it.
#[derive(Clone, Default)]
pub(crate) struct RecentDials(Arc<Mutex<Recent>>);

#[derive(Default)]
struct Recent {
    /// Each peer's address, with the sequence number of the dial that recorded it.
    peers: HashMap<PeerId, (Multiaddr, u64)>,
    next: u64,
}

impl RecentDials {
    pub(crate) fn record(&self, peer: PeerId, address: Multiaddr) {
        if address.len() > MAX_KEPT_ADDRESS_BYTES {
            return;
        }
        let mut recent = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let sequence = recent.next;
        recent.next += 1;
        recent.peers.insert(peer, (address, sequence));
        if recent.peers.len() > RECENT_DIALS {
            let oldest = recent
                .peers
                .iter()
                .min_by_key(|(_, (_, sequence))| *sequence)
                .map(|(peer, _)| *peer);
            if let Some(oldest) = oldest {
                recent.peers.remove(&oldest);
            }
        }
    }

    /// The concrete address of the most recent successful dial of `peer`, without a peer ID.
    pub(crate) fn get(&self, peer: &PeerId) -> Option<Multiaddr> {
        let recent = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        recent.peers.get(peer).map(|(address, _)| address.clone())
    }
}

/// Refuses dials that reach this node and records the address of every successful dial.
pub(crate) struct DialGuard<T> {
    inner: T,
    /// The addresses and UDP ports this node has listened on, kept for the life of the process.
    listen_addresses: HashSet<(IpAddr, u16)>,
    listen_ports: HashSet<u16>,
    recent: RecentDials,
}

impl<T> DialGuard<T> {
    pub(crate) fn new(inner: T, recent: RecentDials) -> Self {
        Self {
            inner,
            listen_addresses: HashSet::new(),
            listen_ports: HashSet::new(),
            recent,
        }
    }

    fn listened(&mut self, addr: &Multiaddr) {
        // On port 0 the system chooses the port, and the transport reports it as a new address.
        if let Some((ip, port)) = ip_and_udp_port(addr).filter(|(_, port)| *port != 0) {
            self.listen_ports.insert(port);
            if !ip.is_unspecified() {
                self.listen_addresses.insert((ip, port));
            }
        }
    }

    fn reaches_this_node(&self, addr: &Multiaddr) -> bool {
        let Some((ip, port)) = ip_and_udp_port(addr) else {
            return false;
        };
        self.listen_addresses.contains(&(ip, port))
            || (is_local_only(ip) && self.listen_ports.contains(&port))
    }
}

fn ip_and_udp_port(addr: &Multiaddr) -> Option<(IpAddr, u16)> {
    let mut ip = None;
    let mut port = None;
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(v4) => ip = Some(IpAddr::V4(v4)),
            Protocol::Ip6(v6) => ip = Some(IpAddr::V6(v6)),
            Protocol::Udp(udp) => port = Some(udp),
            _ => {}
        }
    }
    Some((ip?, port?))
}

/// A loopback or unspecified address, also in the IPv4-mapped IPv6 form. A dial to it on one of
/// this node's ports reaches this node.
fn is_local_only(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
    }
}

impl<T, M> Transport for DialGuard<T>
where
    T: Transport<Output = (PeerId, M)> + Unpin,
    T::Dial: Send + 'static,
    T::Error: Send + 'static,
    M: Send + 'static,
{
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.listened(&addr);
        self.inner.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        if self.reaches_this_node(&addr) {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        let keep = ip_and_udp_port(&addr).is_some_and(|(ip, _)| !is_local_only(ip));
        let dial = self.inner.dial(addr.clone(), opts)?;
        let recent = self.recent.clone();
        Ok(async move {
            let (peer, connection) = dial.await?;
            // The swarm checks the peer ID afterwards; record the identity that answered.
            if keep {
                recent.record(peer, strip_peer_id(addr));
            }
            Ok((peer, connection))
        }
        .boxed())
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let this = self.get_mut();
        let event = ready!(Pin::new(&mut this.inner).poll(cx));
        if let TransportEvent::NewAddress { listen_addr, .. } = &event {
            this.listened(listen_addr);
        }
        Poll::Ready(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::{poll_fn, ready, Ready};
    use libp2p::core::{transport::PortUse, Endpoint};
    use std::collections::VecDeque;

    type Answer = Ready<Result<(PeerId, ()), std::io::Error>>;

    /// Answers every dial at once as `peer`, records the addresses it was asked to dial, and
    /// reports the queued listener events.
    struct AnsweringTransport {
        peer: PeerId,
        dialed: Arc<Mutex<Vec<Multiaddr>>>,
        events: VecDeque<TransportEvent<Answer, std::io::Error>>,
    }

    impl Transport for AnsweringTransport {
        type Output = (PeerId, ());
        type Error = std::io::Error;
        type ListenerUpgrade = Answer;
        type Dial = Answer;

        fn listen_on(
            &mut self,
            _: ListenerId,
            _: Multiaddr,
        ) -> Result<(), TransportError<Self::Error>> {
            Ok(())
        }

        fn remove_listener(&mut self, _: ListenerId) -> bool {
            false
        }

        fn dial(
            &mut self,
            addr: Multiaddr,
            _: DialOpts,
        ) -> Result<Self::Dial, TransportError<Self::Error>> {
            self.dialed.lock().unwrap().push(addr);
            Ok(ready(Ok((self.peer, ()))))
        }

        fn poll(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
            match self.events.pop_front() {
                Some(event) => Poll::Ready(event),
                None => Poll::Pending,
            }
        }
    }

    type Guard = DialGuard<AnsweringTransport>;
    type DialResult = Result<<Guard as Transport>::Dial, TransportError<std::io::Error>>;

    fn guard() -> (Guard, PeerId, Arc<Mutex<Vec<Multiaddr>>>) {
        let peer = PeerId::random();
        let dialed = Arc::new(Mutex::new(Vec::new()));
        let inner = AnsweringTransport {
            peer,
            dialed: dialed.clone(),
            events: VecDeque::new(),
        };
        (DialGuard::new(inner, RecentDials::default()), peer, dialed)
    }

    fn dial(guard: &mut Guard, address: &str) -> DialResult {
        guard.dial(
            address.parse().unwrap(),
            DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            },
        )
    }

    fn is_refused(result: DialResult) -> bool {
        matches!(result, Err(TransportError::MultiaddrNotSupported(_)))
    }

    async fn report_new_address(guard: &mut Guard, address: &str) {
        guard.inner.events.push_back(TransportEvent::NewAddress {
            listener_id: ListenerId::next(),
            listen_addr: address.parse().unwrap(),
        });
        poll_fn(|cx| Pin::new(&mut *guard).poll(cx)).await;
    }

    const PUBLIC: &str = "/ip4/34.192.113.100/udp/9501/quic-v1";

    #[tokio::test]
    async fn refuses_local_only_dials_to_its_own_port() {
        let (mut guard, _, dialed) = guard();
        guard
            .listen_on(
                ListenerId::next(),
                "/ip4/0.0.0.0/udp/9091/quic-v1".parse().unwrap(),
            )
            .unwrap();

        for address in [
            "/ip4/127.0.0.1/udp/9091/quic-v1",
            "/ip6/::1/udp/9091/quic-v1",
            "/ip4/0.0.0.0/udp/9091/quic-v1",
            "/ip6/::ffff:127.0.0.1/udp/9091/quic-v1",
        ] {
            assert!(is_refused(dial(&mut guard, address)), "{address}");
        }
        assert!(dialed.lock().unwrap().is_empty());

        // Another node on this host listens on another port.
        dial(&mut guard, "/ip4/127.0.0.1/udp/9092/quic-v1")
            .unwrap()
            .await
            .unwrap();
        assert_eq!(dialed.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refuses_its_own_interface_address() {
        let (mut guard, _, dialed) = guard();
        report_new_address(&mut guard, "/ip4/172.17.0.2/udp/9091/quic-v1").await;

        assert!(is_refused(dial(
            &mut guard,
            "/ip4/172.17.0.2/udp/9091/quic-v1"
        )));
        // The same port on another host is another node.
        dial(&mut guard, "/ip4/172.17.0.3/udp/9091/quic-v1")
            .unwrap()
            .await
            .unwrap();
        assert_eq!(dialed.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn learns_a_port_that_the_system_chose() {
        let (mut guard, _, _) = guard();
        report_new_address(&mut guard, "/ip4/127.0.0.1/udp/40123/quic-v1").await;

        assert!(is_refused(dial(
            &mut guard,
            "/ip4/127.0.0.1/udp/40123/quic-v1"
        )));
    }

    #[tokio::test]
    async fn a_successful_dial_keeps_its_address_for_the_answering_peer() {
        let (mut guard, peer, _) = guard();

        dial(&mut guard, &format!("{PUBLIC}/p2p/{peer}"))
            .unwrap()
            .await
            .unwrap();

        assert_eq!(guard.recent.get(&peer), Some(PUBLIC.parse().unwrap()));
    }

    #[tokio::test]
    async fn a_loopback_dial_is_not_kept() {
        let (mut guard, peer, _) = guard();

        dial(&mut guard, "/ip4/127.0.0.1/udp/9092/quic-v1")
            .unwrap()
            .await
            .unwrap();

        assert_eq!(guard.recent.get(&peer), None);
    }

    #[test]
    fn keeps_at_most_the_recent_dials_and_short_addresses() {
        let recent = RecentDials::default();
        let first = PeerId::random();
        recent.record(first, PUBLIC.parse().unwrap());
        for _ in 0..RECENT_DIALS {
            recent.record(PeerId::random(), PUBLIC.parse().unwrap());
        }
        assert_eq!(recent.get(&first), None);
        assert_eq!(recent.0.lock().unwrap().peers.len(), RECENT_DIALS);

        let peer = PeerId::random();
        let mut long: Multiaddr = PUBLIC.parse().unwrap();
        while long.len() <= MAX_KEPT_ADDRESS_BYTES {
            long.push(Protocol::P2p(PeerId::random()));
        }
        recent.record(peer, long);
        assert_eq!(recent.get(&peer), None);
    }
}
