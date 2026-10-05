// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Health of the gossip subscriptions of connected peers, and the redial backoff of peers that
//! never subscribe.
//!
//! A peer that stays connected without a gossip subscription for the grace period is disconnected,
//! so a fresh connection can repeat the subscription exchange. Each such disconnect in a row
//! doubles the time before this node dials the peer again. As a network behaviour, this type holds
//! back every outbound dial that names the peer during that time: the configured-peer redial and
//! the dials of the other behaviours, such as a Kademlia query that still has the peer as a
//! candidate. A dial by address alone does not name the peer and is not held back.

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

use crate::backoff::backoff_delay;

/// How long a connected peer may stay without a gossip subscription.
pub(crate) const GOSSIP_SUBSCRIPTION_GRACE: Duration = Duration::from_secs(30);
/// The cap of the redial backoff, and how long the backoff is kept after it ends.
const MAX_REDIAL_BACKOFF: Duration = Duration::from_secs(30 * 60);

/// Public only because `NodeBehaviour` is; the module is private.
#[derive(Default)]
pub struct GossipSubscriptionHealth {
    missing_since: HashMap<PeerId, Instant>,
    /// Peers disconnected because they did not subscribe: the number of such disconnects in a row,
    /// and the time before which no outbound dial that names the peer goes out. An admitted
    /// connection does not
    /// reset it, only a subscription does, so a peer that never subscribes is dialed less and less
    /// often.
    redial_backoff: HashMap<PeerId, (u32, Instant)>,
}

impl GossipSubscriptionHealth {
    /// Returns the connected peers that stayed without a subscription for the grace period.
    pub(crate) fn stale_peers(
        &mut self,
        connected: &HashSet<PeerId>,
        subscribed: &HashSet<PeerId>,
        now: Instant,
    ) -> Vec<PeerId> {
        // Forget the backoff of a peer that subscribes, and a backoff that ended a full
        // `MAX_REDIAL_BACKOFF` ago.
        self.redial_backoff.retain(|peer, (_, redial_after)| {
            !subscribed.contains(peer) && now < *redial_after + MAX_REDIAL_BACKOFF
        });
        self.missing_since
            .retain(|peer, _| connected.contains(peer) && !subscribed.contains(peer));
        for peer in connected.difference(subscribed) {
            self.missing_since.entry(*peer).or_insert(now);
        }
        self.missing_since
            .iter()
            .filter_map(|(peer, since)| {
                (now.saturating_duration_since(*since) >= GOSSIP_SUBSCRIPTION_GRACE)
                    .then_some(*peer)
            })
            .collect()
    }

    /// Records a disconnect because the peer did not subscribe, and returns the delay before this
    /// node dials it again.
    pub(crate) fn disconnected_unsubscribed(&mut self, peer: PeerId, now: Instant) -> Duration {
        self.missing_since.remove(&peer);
        let (disconnects, redial_after) = self.redial_backoff.entry(peer).or_insert((0, now));
        *disconnects = disconnects.saturating_add(1);
        let delay = backoff_delay(GOSSIP_SUBSCRIPTION_GRACE, *disconnects, MAX_REDIAL_BACKOFF);
        *redial_after = now + delay;
        delay
    }

    /// Records a gossip subscription, which ends the peer's backoff.
    pub(crate) fn subscribed(&mut self, peer: &PeerId) {
        self.missing_since.remove(peer);
        self.redial_backoff.remove(peer);
    }

    pub(crate) fn may_redial(&self, peer: &PeerId, now: Instant) -> bool {
        self.redial_backoff
            .get(peer)
            .is_none_or(|(_, redial_after)| now >= *redial_after)
    }
}

/// The reason for a dial that the redial backoff holds back.
#[derive(Debug)]
pub(crate) struct RedialBackoff(PeerId);

impl fmt::Display for RedialBackoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer {} did not subscribe to the gossip topic; its redial backoff has not ended",
            self.0
        )
    }
}

impl std::error::Error for RedialBackoff {}

/// Every outbound dial that names a peer passes here, also the dials of other behaviours. An
/// inbound connection is not held back: the peer can still subscribe on it.
impl NetworkBehaviour for GossipSubscriptionHealth {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        maybe_peer: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        match maybe_peer {
            Some(peer) if !self.may_redial(&peer, Instant::now()) => {
                Err(ConnectionDenied::new(RedialBackoff(peer)))
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
    fn missing_gossip_subscription_becomes_stale_after_grace_period() {
        let peer = PeerId::random();
        let connected = HashSet::from([peer]);
        let subscribed = HashSet::new();
        let started = Instant::now();
        let mut health = GossipSubscriptionHealth::default();

        assert!(health
            .stale_peers(&connected, &subscribed, started)
            .is_empty());
        assert!(health
            .stale_peers(
                &connected,
                &subscribed,
                started + GOSSIP_SUBSCRIPTION_GRACE - Duration::from_millis(1),
            )
            .is_empty());
        assert_eq!(
            health.stale_peers(&connected, &subscribed, started + GOSSIP_SUBSCRIPTION_GRACE),
            vec![peer]
        );
    }

    #[test]
    fn gossip_subscription_clears_missing_peer_state() {
        let peer = PeerId::random();
        let connected = HashSet::from([peer]);
        let started = Instant::now();
        let mut health = GossipSubscriptionHealth::default();

        assert!(health
            .stale_peers(&connected, &HashSet::new(), started)
            .is_empty());
        assert!(health
            .stale_peers(&connected, &HashSet::from([peer]), started)
            .is_empty());
        assert!(health
            .stale_peers(
                &connected,
                &HashSet::new(),
                started + GOSSIP_SUBSCRIPTION_GRACE,
            )
            .is_empty());
    }

    /// Connects the peer without a subscription until the grace period ends, then disconnects it.
    /// Returns the time of the disconnect and the delay before this node may dial it again.
    fn disconnect_after_grace(
        health: &mut GossipSubscriptionHealth,
        peer: PeerId,
        connected_at: Instant,
    ) -> (Instant, Duration) {
        let connected = HashSet::from([peer]);
        assert!(health
            .stale_peers(&connected, &HashSet::new(), connected_at)
            .is_empty());
        let stale_at = connected_at + GOSSIP_SUBSCRIPTION_GRACE;
        assert_eq!(
            health.stale_peers(&connected, &HashSet::new(), stale_at),
            vec![peer]
        );
        (stale_at, health.disconnected_unsubscribed(peer, stale_at))
    }

    #[test]
    fn peer_that_never_subscribes_is_redialed_less_often() {
        let peer = PeerId::random();
        let mut health = GossipSubscriptionHealth::default();

        let (first_at, first_delay) = disconnect_after_grace(&mut health, peer, Instant::now());
        assert!(first_delay >= GOSSIP_SUBSCRIPTION_GRACE);
        assert!(!health.may_redial(&peer, first_at));
        let redialed_at = first_at + first_delay;
        assert!(health.may_redial(&peer, redialed_at));

        // The reconnect is admitted, but only a subscription resets the backoff.
        let (second_at, second_delay) = disconnect_after_grace(&mut health, peer, redialed_at);
        assert!(second_delay >= first_delay.mul_f64(1.8));
        assert!(!health.may_redial(&peer, second_at + first_delay));

        let subscribed_at = second_at + second_delay;
        assert!(health
            .stale_peers(
                &HashSet::from([peer]),
                &HashSet::from([peer]),
                subscribed_at
            )
            .is_empty());
        let (third_at, third_delay) = disconnect_after_grace(&mut health, peer, subscribed_at);
        assert!(third_delay < second_delay);
        assert!(health.may_redial(&peer, third_at + third_delay));
    }
}
