// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Who the node dials and keeps connected. As a network behaviour it sees every outbound dial,
//! also those of other behaviours such as a Kademlia query, so its rules bind them all.
//!
//! - The peers the operator configured are dialed until they connect, less often the longer they
//!   stay away, and each at its own moment: nodes restarted together do not dial together.
//! - A peer must identify on this network in time. One that does not, or that identifies as
//!   another network or release, is dropped and not dialed again for a while.
//! - A peer that takes part in messages must subscribe to their topic. One that stays connected
//!   without it is disconnected, so a fresh connection can repeat the subscription, and is dialed
//!   less and less often.

use libp2p::{
    core::{transport::PortUse, Endpoint},
    multiaddr::Protocol,
    swarm::{
        dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
    Multiaddr, PeerId,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fmt,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tracing::{debug, warn};

/// The first wait before a configured peer is dialed again; each failed dial doubles it.
const FIRST_REDIAL: Duration = Duration::from_secs(15);
/// The longest wait: a peer that stays away for hours costs a dial every few minutes.
const LONGEST_REDIAL: Duration = Duration::from_secs(5 * 60);
/// At most this share of a wait is added, so nodes do not dial in step.
const REDIAL_JITTER_PERCENT: u64 = 20;
/// After this many failed dials the operator hears, once, that configured peers are away.
const OUTAGE_DIALS: u32 = 3;

/// How long a connected peer has to identify on this network.
const IDENTIFY_LIMIT: Duration = Duration::from_secs(30);
/// How long a peer that identified as something else stays refused.
const REJECTED_FOR: Duration = Duration::from_secs(10 * 60);
const MAX_REJECTED: usize = 1_024;

/// How long a connected peer may stay without the network's topic.
pub(crate) const SUBSCRIPTION_GRACE: Duration = Duration::from_secs(30);
/// The longest redial backoff, and how long a backoff is kept after it ends.
const MAX_SUBSCRIPTION_BACKOFF: Duration = Duration::from_secs(30 * 60);
const MAX_BACKOFFS: usize = 1_024;

/// The addresses of one peer that the node shares, and their encoded bytes.
const MAX_ADVERTISED: usize = 8;
const MAX_ADVERTISED_BYTES: usize = 2 * 1024;

struct Configured {
    address: Multiaddr,
    /// Named by the address; the node never takes another identity for it.
    pinned: Option<PeerId>,
    /// The peer a connection to an address without an identity showed.
    reached: Option<PeerId>,
    /// The concrete address of its last connection, for when DNS no longer resolves.
    fallback: Option<Multiaddr>,
    failed_dials: u32,
    next_dial: Instant,
}

impl Configured {
    fn peer(&self) -> Option<PeerId> {
        self.pinned.or(self.reached)
    }
}

/// Public only because the swarm's behaviour, which holds it, needs it to be.
pub struct PeerBook {
    me: PeerId,
    configured: Vec<Configured>,
    /// Whether the operator has been told about the configured peers that are away.
    outage_reported: bool,
    /// Each connected peer's connections and the addresses they use.
    connections: HashMap<PeerId, HashMap<ConnectionId, Multiaddr>>,
    /// Peers that have not identified, with their limit.
    awaiting_identify: HashMap<PeerId, Instant>,
    /// Bootstrap peers, which take no part in messages.
    no_messages: HashSet<PeerId>,
    rejected: HashMap<PeerId, Instant>,
    missing_since: HashMap<PeerId, Instant>,
    /// The peers disconnected for not subscribing: such disconnects in a row, and when the node
    /// may dial each again.
    backoff: HashMap<PeerId, (u32, Instant)>,
}

impl PeerBook {
    pub(crate) fn new(me: PeerId, peers: Vec<Multiaddr>, now: Instant) -> Self {
        let configured = peers
            .into_iter()
            .map(|address| Configured {
                pinned: named_peer(&address),
                address,
                reached: None,
                fallback: None,
                failed_dials: 0,
                next_dial: now,
            })
            .collect();
        Self {
            me,
            configured,
            outage_reported: false,
            connections: HashMap::new(),
            awaiting_identify: HashMap::new(),
            no_messages: HashSet::new(),
            rejected: HashMap::new(),
            missing_since: HashMap::new(),
            backoff: HashMap::new(),
        }
    }

    /// The addresses to dial now: each configured peer that is away and whose wait is over.
    pub(crate) fn due_dials(&mut self, now: Instant) -> Vec<Multiaddr> {
        let connected = |peer: &PeerId| self.connections.contains_key(peer);
        let mut due = Vec::new();
        let mut waits = Vec::new();
        for (index, peer) in self.configured.iter().enumerate() {
            if peer.peer().is_some_and(|peer| connected(&peer)) || now < peer.next_dial {
                continue;
            }
            due.push(peer.address.clone());
            due.extend(peer.fallback.clone());
            waits.push(index);
        }
        for index in waits {
            let failed = self.configured[index].failed_dials.saturating_add(1);
            let wait = self.redial_wait(index, failed);
            let peer = &mut self.configured[index];
            peer.failed_dials = failed;
            peer.next_dial = now + wait;
        }
        self.report_outage();
        due
    }

    fn redial_wait(&self, index: usize, failed: u32) -> Duration {
        let doublings = failed.saturating_sub(1).min(16);
        let wait = FIRST_REDIAL
            .saturating_mul(1 << doublings)
            .min(LONGEST_REDIAL);
        let mut seed = Sha256::new();
        seed.update(self.me.to_bytes());
        seed.update(self.configured[index].address.as_ref());
        seed.update(failed.to_be_bytes());
        let seed: [u8; 8] = seed.finalize()[..8].try_into().expect("eight bytes");
        let percent = u64::from_be_bytes(seed) % (REDIAL_JITTER_PERCENT + 1);
        wait + wait.mul_f64(percent as f64 / 100.0)
    }

    /// Tells the operator once when configured peers cannot be reached, and again only after
    /// they came back and went away.
    fn report_outage(&mut self) {
        let away = self
            .configured
            .iter()
            .filter(|peer| peer.failed_dials >= OUTAGE_DIALS)
            .count();
        if away == 0 {
            self.outage_reported = false;
        } else if !self.outage_reported {
            self.outage_reported = true;
            warn!(
                away,
                configured = self.configured.len(),
                "configured peers cannot be reached; the node keeps trying"
            );
        }
    }

    /// A connection came up, by `concrete` if the transport knows the address it dialed.
    pub(crate) fn established(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        address: Multiaddr,
        concrete: Option<Multiaddr>,
        now: Instant,
    ) {
        let bare = strip_peer_id(address.clone());
        for configured in &mut self.configured {
            let dialed = strip_peer_id(configured.address.clone()) == bare;
            if configured.pinned.is_none() && dialed {
                configured.reached = Some(peer);
            }
            if configured.peer() == Some(peer) || dialed {
                configured.failed_dials = 0;
                configured.next_dial = now;
                if concrete.is_some() {
                    configured.fallback.clone_from(&concrete);
                }
            }
        }
        self.connections
            .entry(peer)
            .or_default()
            .insert(connection, address);
        self.awaiting_identify
            .entry(peer)
            .or_insert(now + IDENTIFY_LIMIT);
    }

    pub(crate) fn closed(&mut self, peer: PeerId, connection: ConnectionId) {
        let Some(connections) = self.connections.get_mut(&peer) else {
            return;
        };
        connections.remove(&connection);
        if connections.is_empty() {
            self.connections.remove(&peer);
            self.awaiting_identify.remove(&peer);
            self.no_messages.remove(&peer);
            self.missing_since.remove(&peer);
        }
    }

    /// The peer identified on this network.
    pub(crate) fn identified(&mut self, peer: PeerId, takes_messages: bool) {
        self.awaiting_identify.remove(&peer);
        match takes_messages {
            true => {
                self.no_messages.remove(&peer);
            }
            false => {
                self.no_messages.insert(peer);
            }
        }
    }

    /// The peer identified as another network or release, or lacks what the network needs.
    pub(crate) fn reject(&mut self, peer: PeerId, now: Instant) {
        self.rejected.retain(|_, until| now < *until);
        if self.rejected.len() >= MAX_REJECTED && !self.rejected.contains_key(&peer) {
            let soonest = self.rejected.iter().min_by_key(|(_, until)| **until);
            if let Some(soonest) = soonest.map(|(peer, _)| *peer) {
                self.rejected.remove(&soonest);
            }
        }
        self.rejected.insert(peer, now + REJECTED_FOR);
        self.awaiting_identify.remove(&peer);
    }

    pub(crate) fn is_rejected(&self, peer: &PeerId, now: Instant) -> bool {
        self.rejected.get(peer).is_some_and(|until| now < *until)
    }

    /// The peers whose time to identify ran out.
    pub(crate) fn unidentified(&mut self, now: Instant) -> Vec<PeerId> {
        let late: Vec<PeerId> = self
            .awaiting_identify
            .iter()
            .filter(|(_, limit)| now >= **limit)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in &late {
            self.awaiting_identify.remove(peer);
        }
        late
    }

    /// A dial of `address` reached `obtained`, not the peer it expected. For an address the
    /// operator gave without an identity, the node takes the new one. Whether that was so.
    pub(crate) fn rebind(&mut self, address: &Multiaddr, obtained: PeerId) -> bool {
        let mut pinned_elsewhere = false;
        for configured in &mut self.configured {
            if configured.fallback.as_ref() == Some(address) {
                configured.fallback = None;
            }
            if strip_peer_id(configured.address.clone()) != *address {
                continue;
            }
            match configured.pinned {
                Some(pinned) => {
                    pinned_elsewhere = true;
                    warn!(%address, %pinned, %obtained, "a configured address answers as another peer");
                }
                None => configured.reached = Some(obtained),
            }
        }
        !pinned_elsewhere
    }

    /// The connected peers that take part in messages and stayed without a subscription for the
    /// grace period.
    pub(crate) fn unsubscribed(
        &mut self,
        subscribed: &HashSet<PeerId>,
        now: Instant,
    ) -> Vec<PeerId> {
        self.backoff.retain(|peer, (_, redial)| {
            !subscribed.contains(peer) && now < *redial + MAX_SUBSCRIPTION_BACKOFF
        });
        let expected: HashSet<PeerId> = self
            .connections
            .keys()
            .filter(|peer| {
                !self.no_messages.contains(*peer) && !self.awaiting_identify.contains_key(*peer)
            })
            .copied()
            .collect();
        self.missing_since
            .retain(|peer, _| expected.contains(peer) && !subscribed.contains(peer));
        for peer in expected.difference(subscribed) {
            self.missing_since.entry(*peer).or_insert(now);
        }
        self.missing_since
            .iter()
            .filter(|(_, since)| now.saturating_duration_since(**since) >= SUBSCRIPTION_GRACE)
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// Records that `peer` was disconnected for not subscribing; returns the wait before this node
    /// dials it again.
    pub(crate) fn disconnected_unsubscribed(&mut self, peer: PeerId, now: Instant) -> Duration {
        self.missing_since.remove(&peer);
        if self.backoff.len() >= MAX_BACKOFFS && !self.backoff.contains_key(&peer) {
            let soonest = self.backoff.iter().min_by_key(|(_, (_, redial))| *redial);
            if let Some(soonest) = soonest.map(|(peer, _)| *peer) {
                self.backoff.remove(&soonest);
            }
        }
        let (disconnects, redial) = self.backoff.entry(peer).or_insert((0, now));
        *disconnects = disconnects.saturating_add(1);
        let doublings = disconnects.saturating_sub(1).min(16);
        let wait = SUBSCRIPTION_GRACE
            .saturating_mul(1 << doublings)
            .min(MAX_SUBSCRIPTION_BACKOFF);
        *redial = now + wait;
        wait
    }

    fn may_dial(&self, peer: &PeerId, now: Instant) -> bool {
        !self.is_rejected(peer, now)
            && self
                .backoff
                .get(peer)
                .is_none_or(|(_, redial)| now >= *redial)
    }

    /// The addresses `peer` connects by now.
    pub(crate) fn live_addresses(&self, peer: &PeerId) -> Vec<Multiaddr> {
        self.connections
            .get(peer)
            .map(|connections| connections.values().cloned().collect())
            .unwrap_or_default()
    }
}

/// The identity an address names, if it does.
pub(crate) fn named_peer(address: &Multiaddr) -> Option<PeerId> {
    match address.iter().last() {
        Some(Protocol::P2p(peer)) => Some(peer),
        _ => None,
    }
}

/// `address` without a trailing `/p2p/` identity.
pub(crate) fn strip_peer_id(mut address: Multiaddr) -> Multiaddr {
    if matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        address.pop();
    }
    address
}

/// The addresses the node shares of those a peer gave: routable ones, each once, within
/// `MAX_ADVERTISED` and `MAX_ADVERTISED_BYTES`. The ones the peer connects by now go first: they
/// are known to work, and must stay usable after the connection ends.
pub(crate) fn advertised(
    listeners: &[Multiaddr],
    mut given: Vec<Multiaddr>,
    live: &[Multiaddr],
) -> Vec<Multiaddr> {
    let bare_live: Vec<Multiaddr> = live.iter().cloned().map(strip_peer_id).collect();
    given.sort_by_key(|address| !bare_live.contains(&strip_peer_id(address.clone())));
    let mut kept: Vec<Multiaddr> = Vec::new();
    let mut bytes = 0;
    for address in routable(listeners, given) {
        if kept.contains(&address) || bytes + address.len() > MAX_ADVERTISED_BYTES {
            continue;
        }
        bytes += address.len();
        kept.push(address);
        if kept.len() == MAX_ADVERTISED {
            break;
        }
    }
    kept
}

/// The addresses a peer gave that the node shares through Kademlia. A loopback address reaches
/// the peer only from its own host, so a node that other hosts reach drops it: Kademlia would hand
/// it to remote peers, which then dial themselves. Nodes that listen only on loopback share one
/// host and keep it.
pub(crate) fn routable(
    listeners: &[Multiaddr],
    given: Vec<Multiaddr>,
) -> impl Iterator<Item = Multiaddr> {
    let reached_from_others = listeners
        .iter()
        .any(|address| !is_loopback(address) && !is_unspecified(address));
    given
        .into_iter()
        .filter(move |address| !reached_from_others || !is_loopback(address))
}

fn is_loopback(address: &Multiaddr) -> bool {
    address.iter().any(|protocol| match protocol {
        Protocol::Ip4(ip) => ip.is_loopback(),
        Protocol::Ip6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
        _ => false,
    })
}

fn is_unspecified(address: &Multiaddr) -> bool {
    address.iter().any(|protocol| match protocol {
        Protocol::Ip4(ip) => ip.is_unspecified(),
        Protocol::Ip6(ip) => ip.is_unspecified(),
        _ => false,
    })
}

/// The reason for a dial the book holds back.
#[derive(Debug)]
struct HeldBack(PeerId);

impl fmt::Display for HeldBack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer {} may not be dialed yet", self.0)
    }
}

impl std::error::Error for HeldBack {}

/// Every outbound dial that names a peer passes here. An inbound connection is not held back: the
/// driver drops one from a rejected peer, and an unsubscribed peer can still subscribe on it.
impl NetworkBehaviour for PeerBook {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        match peer {
            Some(peer) if !self.may_dial(&peer, Instant::now()) => {
                debug!(%peer, "holding back a dial");
                Err(ConnectionDenied::new(HeldBack(peer)))
            }
            _ => Ok(Vec::new()),
        }
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
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

    fn on_swarm_event(&mut self, _: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: &str = "/ip4/34.192.113.100/udp/9501/quic-v1";

    fn address(text: &str) -> Multiaddr {
        text.parse().unwrap()
    }

    fn book(peers: Vec<Multiaddr>, now: Instant) -> PeerBook {
        PeerBook::new(PeerId::random(), peers, now)
    }

    #[test]
    fn a_configured_peer_is_dialed_less_often_while_it_stays_away() {
        let start = Instant::now();
        let mut book = book(vec![address(ADDRESS)], start);
        assert_eq!(book.due_dials(start).len(), 1);
        assert!(book.due_dials(start + Duration::from_secs(14)).is_empty());
        let mut at = start;
        let mut waits = Vec::new();
        for _ in 0..8 {
            let wait = book.configured[0].next_dial.saturating_duration_since(at);
            waits.push(wait);
            at = book.configured[0].next_dial;
            assert_eq!(book.due_dials(at).len(), 1);
        }
        assert!(waits[0] >= FIRST_REDIAL && waits[0] <= FIRST_REDIAL * 6 / 5);
        assert!(waits[1] >= FIRST_REDIAL * 2);
        let longest = LONGEST_REDIAL * 6 / 5;
        assert!(waits.iter().all(|wait| *wait <= longest));
        assert!(*waits.last().unwrap() >= LONGEST_REDIAL);
    }

    #[test]
    fn nodes_restarted_together_do_not_dial_in_step() {
        let start = Instant::now();
        let waits: HashSet<Duration> = (0..8)
            .map(|_| {
                let mut book = book(vec![address(ADDRESS)], start);
                book.due_dials(start);
                book.configured[0].next_dial - start
            })
            .collect();
        assert!(waits.len() > 1);
    }

    #[test]
    fn a_connection_ends_the_waiting_and_a_connected_peer_is_not_dialed() {
        let start = Instant::now();
        let mut book = book(vec![address(ADDRESS)], start);
        for dials in 0..3 {
            let at = start + Duration::from_secs(1_000 * dials);
            book.due_dials(at);
        }
        let peer = PeerId::random();
        let connection = ConnectionId::new_unchecked(1);
        book.established(peer, connection, address(ADDRESS), None, start);
        assert_eq!(book.configured[0].failed_dials, 0);
        assert_eq!(book.configured[0].reached, Some(peer));
        assert!(book
            .due_dials(start + Duration::from_secs(9_000))
            .is_empty());
        book.closed(peer, connection);
        assert_eq!(book.due_dials(start + Duration::from_secs(9_000)).len(), 1);
    }

    #[test]
    fn the_last_concrete_address_is_dialed_too() {
        let start = Instant::now();
        let dns = address("/dns4/boot.example/udp/9501/quic-v1");
        let mut book = book(vec![dns.clone()], start);
        let peer = PeerId::random();
        let connection = ConnectionId::new_unchecked(1);
        book.established(peer, connection, dns.clone(), Some(address(ADDRESS)), start);
        book.closed(peer, connection);
        assert_eq!(
            book.due_dials(start + Duration::from_secs(60)),
            [dns, address(ADDRESS)]
        );
    }

    #[test]
    fn an_address_without_an_identity_takes_the_one_that_answers_there_and_a_named_one_does_not() {
        let start = Instant::now();
        let (bare, named_peer_id) = (address(ADDRESS), PeerId::random());
        let named = address(&format!(
            "/ip4/34.192.113.101/udp/9501/quic-v1/p2p/{named_peer_id}"
        ));
        let mut book = book(vec![bare.clone(), named.clone()], start);
        let other = PeerId::random();
        assert!(book.rebind(&bare, other));
        assert_eq!(book.configured[0].reached, Some(other));
        assert!(!book.rebind(&strip_peer_id(named), other));
        assert_eq!(book.configured[1].peer(), Some(named_peer_id));
    }

    #[test]
    fn a_rejected_peer_is_not_dialed_until_its_time_is_over() {
        let start = Instant::now();
        let mut book = book(Vec::new(), start);
        let peer = PeerId::random();
        book.reject(peer, start);
        assert!(!book.may_dial(&peer, start + Duration::from_secs(1)));
        assert!(book.may_dial(&peer, start + REJECTED_FOR));
    }

    #[test]
    fn rejections_are_bounded() {
        let start = Instant::now();
        let mut book = book(Vec::new(), start);
        for offset in 0..(MAX_REJECTED + 8) {
            book.reject(
                PeerId::random(),
                start + Duration::from_millis(offset as u64),
            );
        }
        assert_eq!(book.rejected.len(), MAX_REJECTED);
    }

    #[test]
    fn a_peer_must_identify_in_time() {
        let start = Instant::now();
        let mut book = book(Vec::new(), start);
        let (slow, quick) = (PeerId::random(), PeerId::random());
        book.established(
            slow,
            ConnectionId::new_unchecked(1),
            address(ADDRESS),
            None,
            start,
        );
        book.established(
            quick,
            ConnectionId::new_unchecked(2),
            address(ADDRESS),
            None,
            start,
        );
        book.identified(quick, true);
        assert!(book
            .unidentified(start + IDENTIFY_LIMIT - Duration::from_millis(1))
            .is_empty());
        assert_eq!(book.unidentified(start + IDENTIFY_LIMIT), [slow]);
        assert!(book.unidentified(start + IDENTIFY_LIMIT).is_empty());
    }

    fn connected(book: &mut PeerBook, takes_messages: bool, now: Instant) -> PeerId {
        let peer = PeerId::random();
        book.established(
            peer,
            ConnectionId::new_unchecked(1),
            address(ADDRESS),
            None,
            now,
        );
        book.identified(peer, takes_messages);
        peer
    }

    #[test]
    fn a_member_without_a_subscription_is_dropped_after_the_grace_period() {
        let start = Instant::now();
        let mut book = book(Vec::new(), start);
        let peer = connected(&mut book, true, start);
        let none = HashSet::new();
        assert!(book.unsubscribed(&none, start).is_empty());
        let almost = start + SUBSCRIPTION_GRACE - Duration::from_millis(1);
        assert!(book.unsubscribed(&none, almost).is_empty());
        assert_eq!(book.unsubscribed(&none, start + SUBSCRIPTION_GRACE), [peer]);
    }

    #[test]
    fn a_bootstrap_peer_owes_no_subscription() {
        let start = Instant::now();
        let mut book = book(Vec::new(), start);
        connected(&mut book, false, start);
        let none = HashSet::new();
        assert!(book.unsubscribed(&none, start).is_empty());
        assert!(book
            .unsubscribed(&none, start + SUBSCRIPTION_GRACE)
            .is_empty());
    }

    #[test]
    fn a_subscription_ends_the_wait() {
        let start = Instant::now();
        let mut book = book(Vec::new(), start);
        let peer = connected(&mut book, true, start);
        assert!(book.unsubscribed(&HashSet::new(), start).is_empty());
        assert!(book.unsubscribed(&HashSet::from([peer]), start).is_empty());
        let later = start + SUBSCRIPTION_GRACE;
        assert!(book.unsubscribed(&HashSet::new(), later).is_empty());
    }

    #[test]
    fn a_peer_that_never_subscribes_is_dialed_less_and_less_often() {
        let start = Instant::now();
        let mut book = book(Vec::new(), start);
        let peer = PeerId::random();
        let first = book.disconnected_unsubscribed(peer, start);
        assert_eq!(first, SUBSCRIPTION_GRACE);
        assert!(!book.may_dial(&peer, start));
        let redialed = start + first;
        assert!(book.may_dial(&peer, redialed));
        assert_eq!(
            book.disconnected_unsubscribed(peer, redialed),
            SUBSCRIPTION_GRACE * 2
        );
    }

    #[test]
    fn a_node_that_other_hosts_reach_shares_no_loopback_address() {
        let loopback = address("/ip4/127.0.0.1/udp/9000/quic-v1");
        let mapped = address("/ip6/::ffff:127.0.0.1/udp/9000/quic-v1");
        let lan = address("/ip4/192.168.1.5/udp/9000/quic-v1");
        let given = vec![loopback.clone(), mapped, lan.clone()];
        let one_host: Vec<_> = routable(&[loopback], given.clone()).collect();
        assert_eq!(one_host, given);
        let reached: Vec<_> = routable(std::slice::from_ref(&lan), given).collect();
        assert_eq!(reached, vec![lan]);
    }

    /// A peer's Identify can list the same address again, many addresses, or long ones; the node
    /// shares each once, and few of them.
    #[test]
    fn a_peer_s_addresses_are_shared_once_and_within_bounds() {
        let lan = |port: u16| -> Multiaddr {
            format!("/ip4/192.168.1.5/udp/{port}/quic-v1")
                .parse()
                .unwrap()
        };
        let listeners = [lan(1)];
        let repeated = vec![lan(9000), lan(9000), lan(9001)];
        assert_eq!(
            advertised(&listeners, repeated, &[]),
            vec![lan(9000), lan(9001)]
        );
        let many: Vec<Multiaddr> = (0..20).map(|port| lan(9000 + port)).collect();
        assert_eq!(
            advertised(&listeners, many.clone(), &[]),
            many[..MAX_ADVERTISED]
        );
        let long = |n: usize| -> Multiaddr {
            let name = ["a", "b", "c", "d", "e", "f"]
                .map(|label| label.repeat(60))
                .join(".");
            format!("/dns4/{name}.n{n}.example/udp/9000/quic-v1")
                .parse()
                .unwrap()
        };
        let longs: Vec<Multiaddr> = (0..8).map(long).collect();
        let kept = advertised(&listeners, longs, &[]);
        let bytes: usize = kept.iter().map(|address| address.len()).sum();
        assert!(bytes <= MAX_ADVERTISED_BYTES && !kept.is_empty() && kept.len() < MAX_ADVERTISED);
    }

    /// A connection's own address is known to work, so it stays among the few that are kept.
    #[test]
    fn the_address_a_peer_connects_by_is_kept_first() {
        let lan = |port: u16| -> Multiaddr {
            format!("/ip4/192.168.1.5/udp/{port}/quic-v1")
                .parse()
                .unwrap()
        };
        let listeners = [lan(1)];
        let many: Vec<Multiaddr> = (0..20).map(|port| lan(9000 + port)).collect();
        let live = [lan(9019)];
        let kept = advertised(&listeners, many, &live);
        assert_eq!(kept[0], lan(9019));
        assert_eq!(kept.len(), MAX_ADVERTISED);
    }
}
