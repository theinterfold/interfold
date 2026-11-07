// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The gossip subscriptions of connected peers, and the redial backoff of peers that never
//! subscribe.
//!
//! A connection does not show that a peer takes part in the network's messages. A peer that stays
//! connected without the network's topic for the grace period is disconnected, so a fresh
//! connection can repeat the subscription. Each such disconnect in a row doubles the time before
//! this node dials the peer again, up to half an hour, and only a subscription ends it. As a
//! network behaviour, this type holds back every outbound dial that names the peer during that
//! time, also the dials of other behaviours, such as a Kademlia query.

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fmt,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use libp2p::{
    core::{transport::PortUse, Endpoint},
    swarm::{
        dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
    Multiaddr, PeerId,
};

/// How long a connected peer may stay without the network's topic.
pub(crate) const GRACE: Duration = Duration::from_secs(30);
/// The longest redial backoff, and how long a backoff is kept after it ends.
const MAX_BACKOFF: Duration = Duration::from_secs(30 * 60);

/// Public only because the swarm's behaviour, which holds it, needs it to be.
#[derive(Default)]
pub struct SubscriptionHealth {
    missing_since: HashMap<PeerId, Instant>,
    /// The peers disconnected for not subscribing: such disconnects in a row, and when the node
    /// may dial each again.
    backoff: HashMap<PeerId, (u32, Instant)>,
}

impl SubscriptionHealth {
    /// The connected peers that stayed without a subscription for the grace period.
    pub(crate) fn stale(
        &mut self,
        connected: &HashSet<PeerId>,
        subscribed: &HashSet<PeerId>,
        now: Instant,
    ) -> Vec<PeerId> {
        self.backoff
            .retain(|peer, (_, redial)| !subscribed.contains(peer) && now < *redial + MAX_BACKOFF);
        self.missing_since
            .retain(|peer, _| connected.contains(peer) && !subscribed.contains(peer));
        for peer in connected.difference(subscribed) {
            self.missing_since.entry(*peer).or_insert(now);
        }
        self.missing_since
            .iter()
            .filter(|(_, since)| now.saturating_duration_since(**since) >= GRACE)
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// Records that `peer` was disconnected for not subscribing; returns the wait before this node
    /// dials it again.
    pub(crate) fn disconnected(&mut self, peer: PeerId, now: Instant) -> Duration {
        self.missing_since.remove(&peer);
        let (disconnects, redial) = self.backoff.entry(peer).or_insert((0, now));
        *disconnects = disconnects.saturating_add(1);
        let doublings = disconnects.saturating_sub(1).min(16);
        let wait = GRACE.saturating_mul(1 << doublings).min(MAX_BACKOFF);
        *redial = now + wait;
        wait
    }

    fn may_dial(&self, peer: &PeerId, now: Instant) -> bool {
        self.backoff
            .get(peer)
            .is_none_or(|(_, redial)| now >= *redial)
    }
}

/// The reason for a dial that the backoff holds back.
#[derive(Debug)]
struct Unsubscribed(PeerId);

impl fmt::Display for Unsubscribed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer {} did not subscribe to the network's messages; its backoff has not ended",
            self.0
        )
    }
}

impl std::error::Error for Unsubscribed {}

/// Every outbound dial that names a peer passes here. An inbound connection is not held back: the
/// peer can still subscribe on it.
impl NetworkBehaviour for SubscriptionHealth {
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
                Err(ConnectionDenied::new(Unsubscribed(peer)))
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

    #[test]
    fn a_peer_without_a_subscription_is_stale_after_the_grace_period() {
        let peer = PeerId::random();
        let connected = HashSet::from([peer]);
        let none = HashSet::new();
        let start = Instant::now();
        let mut health = SubscriptionHealth::default();
        assert!(health.stale(&connected, &none, start).is_empty());
        let almost = start + GRACE - Duration::from_millis(1);
        assert!(health.stale(&connected, &none, almost).is_empty());
        assert_eq!(health.stale(&connected, &none, start + GRACE), [peer]);
    }

    #[test]
    fn a_subscription_ends_the_wait() {
        let peer = PeerId::random();
        let connected = HashSet::from([peer]);
        let start = Instant::now();
        let mut health = SubscriptionHealth::default();
        assert!(health.stale(&connected, &HashSet::new(), start).is_empty());
        assert!(health.stale(&connected, &connected, start).is_empty());
        let later = start + GRACE;
        assert!(health.stale(&connected, &HashSet::new(), later).is_empty());
    }

    /// Connects `peer` without a subscription until the grace period ends, then disconnects it.
    fn disconnect_after_grace(
        health: &mut SubscriptionHealth,
        peer: PeerId,
        connected_at: Instant,
    ) -> (Instant, Duration) {
        let connected = HashSet::from([peer]);
        let none = HashSet::new();
        assert!(health.stale(&connected, &none, connected_at).is_empty());
        let stale_at = connected_at + GRACE;
        assert_eq!(health.stale(&connected, &none, stale_at), [peer]);
        (stale_at, health.disconnected(peer, stale_at))
    }

    #[test]
    fn a_peer_that_never_subscribes_is_dialed_less_and_less_often() {
        let peer = PeerId::random();
        let mut health = SubscriptionHealth::default();
        let (first_at, first_wait) = disconnect_after_grace(&mut health, peer, Instant::now());
        assert_eq!(first_wait, GRACE);
        assert!(!health.may_dial(&peer, first_at));
        let redialed = first_at + first_wait;
        assert!(health.may_dial(&peer, redialed));

        let (second_at, second_wait) = disconnect_after_grace(&mut health, peer, redialed);
        assert_eq!(second_wait, GRACE * 2);
        assert!(!health.may_dial(&peer, second_at + first_wait));

        let subscribed_at = second_at + second_wait;
        let both = HashSet::from([peer]);
        assert!(health.stale(&both, &both, subscribed_at).is_empty());
        let (_, third_wait) = disconnect_after_grace(&mut health, peer, subscribed_at);
        assert_eq!(third_wait, GRACE);
    }
}
