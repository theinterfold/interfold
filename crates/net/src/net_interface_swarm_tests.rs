// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Tests that feed the events of a real swarm to `process_swarm_event` and dial through the real
//! `NodeBehaviour`.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use libp2p::core::transport::{DialOpts, ListenerId, TransportError, TransportEvent};
use libp2p::kad::{store::RecordStore, Record, RecordKey};
use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId, Transport};

/// The state that `start` keeps for one node, so a test can feed swarm events to
/// `process_swarm_event` without the timers of the event loop.
struct TestNode {
    interface: super::Libp2pNetInterface,
    correlator: super::Correlator,
    peer_failures: super::PeerConnectionFailures,
    admission: super::PeerAdmission,
    peer_addresses: HashMap<PeerId, super::PeerAddresses>,
    replicas: super::ReplicaLedger,
    seen_gossip: super::GossipIngress,
    dht_puts: super::DhtPuts,
}

impl TestNode {
    fn new() -> anyhow::Result<Self> {
        Self::with_policy(super::NetworkPolicy::local_unrestricted())
    }

    fn with_policy(policy: super::NetworkPolicy) -> anyhow::Result<Self> {
        let mut interface =
            super::Libp2pNetInterface::new(super::Libp2pKeypair::generate(), vec![], None, policy)?;
        let topic = interface.topic.clone();
        interface
            .swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)?;
        Ok(Self {
            interface,
            correlator: super::Correlator::new(),
            peer_failures: super::PeerConnectionFailures::new(),
            admission: super::PeerAdmission::default(),
            peer_addresses: HashMap::new(),
            replicas: super::ReplicaLedger::new(super::DHT_REPLICA_LIMITS),
            seen_gossip: super::GossipIngress::new(),
            dht_puts: super::DhtPuts::default(),
        })
    }

    fn peer_id(&self) -> PeerId {
        *self.interface.swarm.local_peer_id()
    }

    fn health(&mut self) -> &mut super::GossipSubscriptionHealth {
        &mut self.interface.swarm.behaviour_mut().gossip_health
    }

    async fn next_event(&mut self) -> anyhow::Result<super::SwarmEvent<super::NodeBehaviourEvent>> {
        use libp2p::futures::StreamExt;
        tokio::time::timeout(
            Duration::from_secs(20),
            self.interface.swarm.select_next_some(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("the swarm emitted no event in time"))
    }

    async fn process(
        &mut self,
        event: super::SwarmEvent<super::NodeBehaviourEvent>,
    ) -> anyhow::Result<()> {
        self.process_with_configured(&mut [], event).await
    }

    async fn process_with_configured(
        &mut self,
        configured: &mut [super::ConfiguredPeer],
        event: super::SwarmEvent<super::NodeBehaviourEvent>,
    ) -> anyhow::Result<()> {
        super::process_swarm_event(
            &mut self.interface.swarm,
            &self.interface.event_tx,
            &self.interface.cmd_tx,
            &mut self.correlator,
            &mut self.peer_failures,
            &mut self.admission,
            &mut self.peer_addresses,
            configured,
            &mut self.replicas,
            &mut self.seen_gossip,
            &mut self.dht_puts,
            &self.interface.network,
            &self.interface.recent_dials,
            &self.interface.status,
            event,
        )
        .await
    }

    async fn command(&mut self, command: crate::events::NetCommand) -> anyhow::Result<()> {
        super::process_swarm_command(
            &mut self.interface.swarm,
            &self.interface.event_tx,
            &mut self.correlator,
            &mut self.dht_puts,
            &mut self.replicas,
            &self.admission,
            &self.interface.network,
            command,
        )
        .await
    }

    fn dial(&mut self, peer: PeerId) -> Result<(), libp2p::swarm::DialError> {
        let address: Multiaddr = "/ip4/127.0.0.1/udp/9/quic-v1".parse().expect("address");
        self.interface.swarm.dial(
            libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
                .addresses(vec![address])
                .build(),
        )
    }

    async fn listen(&mut self) -> anyhow::Result<(ListenerId, Multiaddr)> {
        let listener = self
            .interface
            .swarm
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
        loop {
            let event = self.next_event().await?;
            let address = match &event {
                super::SwarmEvent::NewListenAddr { address, .. } => Some(address.clone()),
                _ => None,
            };
            self.process(event).await?;
            if let Some(address) = address {
                return Ok((listener, address));
            }
        }
    }

    async fn identify_with(&mut self, other: &mut Self) -> anyhow::Result<libp2p::identify::Info> {
        let mut identified = None;
        while identified.is_none()
            || !self.admission.is_admitted(&other.peer_id())
            || !other.admission.is_admitted(&self.peer_id())
        {
            tokio::select! {
                event = self.next_event() => {
                    let mut event = event?;
                    if let super::SwarmEvent::Behaviour(super::NodeBehaviourEvent::Identify(
                        libp2p::identify::Event::Received { info, .. },
                    )) = &mut event {
                        // Identify sends a hash set. Give the handler a reproducible address order.
                        info.listen_addrs.sort();
                        identified = Some(info.clone());
                    }
                    self.process(event).await?;
                }
                event = other.next_event() => other.process(event?).await?,
            }
        }
        Ok(identified.expect("received Identify"))
    }

    async fn receive_put(&mut self, sender: &mut Self, record: Record) -> anyhow::Result<Record> {
        let key = record.key.clone();
        let query = sender
            .interface
            .swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, libp2p::kad::Quorum::One)?;
        sender
            .correlator
            .track(query, e3_events::CorrelationId::new());
        loop {
            tokio::select! {
                event = self.next_event() => {
                    let event = event?;
                    let received = match &event {
                        super::SwarmEvent::Behaviour(super::NodeBehaviourEvent::Kademlia(
                            libp2p::kad::Event::InboundRequest {
                                request: libp2p::kad::InboundRequest::PutRecord {
                                    record: Some(record), ..
                                },
                            },
                        )) if record.key == key => Some(record.clone()),
                        _ => None,
                    };
                    self.process(event).await?;
                    if let Some(received) = received {
                        return Ok(received);
                    }
                }
                event = sender.next_event() => sender.process(event?).await?,
            }
        }
    }
}

// Map documentation-range addresses to local QUIC sockets. The behaviour sees a public listener
// and real Identify messages; the dial log records addresses before the transport maps them.
struct AddressTestTransport<T> {
    inner: T,
    dials: Arc<Mutex<Vec<Multiaddr>>>,
}

fn with_ip(address: Multiaddr, ip: Ipv4Addr) -> Multiaddr {
    address
        .iter()
        .map(|part| match part {
            libp2p::multiaddr::Protocol::Ip4(_) => libp2p::multiaddr::Protocol::Ip4(ip),
            part => part,
        })
        .collect()
}

impl<T: Transport + Unpin> Transport for AddressTestTransport<T> {
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, address)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.dials.lock().unwrap().push(address.clone());
        self.inner.dial(with_ip(address, Ipv4Addr::LOCALHOST), opts)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.get_mut().inner)
            .poll(cx)
            .map(|event| match event {
                TransportEvent::NewAddress {
                    listener_id,
                    listen_addr,
                } => TransportEvent::NewAddress {
                    listener_id,
                    listen_addr: with_ip(listen_addr, Ipv4Addr::new(203, 0, 113, 1)),
                },
                event => event,
            })
    }
}

/// A node does not dial a loopback address on its own port, which another node can advertise for a
/// peer: the dial would reach this node and fail the whole dial to that peer. libp2p refuses only an
/// exact listen address, and a routing-table address carries the peer ID.
#[tokio::test]
async fn a_node_does_not_dial_a_loopback_address_on_its_own_port() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let (_, own_address) = node.listen().await?;
    let peer = PeerId::random();

    node.interface.swarm.dial(
        libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
            .addresses(vec![
                own_address.with(libp2p::multiaddr::Protocol::P2p(peer))
            ])
            .build(),
    )?;

    loop {
        match node.next_event().await? {
            super::SwarmEvent::OutgoingConnectionError { error, .. } => {
                assert!(
                    format!("{error:?}").contains("MultiaddrNotSupported"),
                    "the dial reached this node: {error:?}"
                );
                return Ok(());
            }
            super::SwarmEvent::ConnectionEstablished { .. } => {
                anyhow::bail!("the node dialed its own port")
            }
            _ => {}
        }
    }
}

/// A peer-ID mismatch at a configured peer's fallback drops the fallback only. The configured
/// address still names the peer, so an unpinned `/dnsaddr` peer is neither quarantined nor rebound
/// to the identity that answered at an address this node kept.
#[tokio::test]
async fn a_mismatch_at_a_configured_fallback_drops_it() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let peer = PeerId::random();
    let fallback: Multiaddr = "/ip4/192.0.2.7/udp/9501/quic-v1".parse()?;
    let mut configured = [super::ConfiguredPeer::from_address(
        "/dnsaddr/bootstrap.interfold.network".parse()?,
    )];
    configured[0].peer_id = Some(peer);
    configured[0].identity_trusted = true;
    configured[0].fallback = Some(fallback.clone());
    let other: Multiaddr = "/ip4/192.0.2.8/udp/9501/quic-v1".parse()?;
    let kademlia = &mut node.interface.swarm.behaviour_mut().kademlia;
    kademlia.add_address(&peer, fallback.clone());
    kademlia.add_address(&peer, other.clone());

    node.process_with_configured(
        &mut configured,
        super::SwarmEvent::OutgoingConnectionError {
            peer_id: Some(peer),
            connection_id: ConnectionId::new_unchecked(1),
            error: libp2p::swarm::DialError::WrongPeerId {
                obtained: PeerId::random(),
                address: fallback.with(libp2p::multiaddr::Protocol::P2p(peer)),
            },
        },
    )
    .await?;

    assert_eq!(configured[0].fallback, None);
    assert_eq!(configured[0].peer_id, Some(peer));
    assert!(configured[0].identity_trusted);
    assert!(!node.peer_failures.is_identity_quarantined(&peer));
    let routed: Vec<Multiaddr> = node
        .interface
        .swarm
        .behaviour_mut()
        .kademlia
        .kbucket(peer)
        .into_iter()
        .flat_map(|bucket| {
            bucket
                .iter()
                .filter(|entry| entry.node.key.preimage() == &peer)
                .flat_map(|entry| entry.node.value.iter().cloned().collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .map(super::strip_peer_id)
        .collect();
    assert_eq!(routed, vec![other]);
    Ok(())
}

#[tokio::test]
async fn identify_reconnections_dial_only_filtered_addresses() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let mut remote = TestNode::new()?;
    let key = libp2p::identity::Keypair::generate_ed25519();
    let dials = Arc::new(Mutex::new(Vec::new()));
    let transport = AddressTestTransport {
        inner: libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(&key)),
        dials: dials.clone(),
    }
    .map(|(peer, connection), _| (peer, libp2p::core::muxing::StreamMuxerBox::new(connection)))
    .boxed();
    node.interface.swarm = libp2p::Swarm::new(
        transport,
        super::create_behaviour(&key, &node.interface.network)
            .map_err(|error| anyhow::anyhow!("{error}"))?,
        key.public().to_peer_id(),
        libp2p::swarm::Config::with_tokio_executor(),
    );
    node.interface
        .swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&node.interface.topic)?;
    node.listen().await?;
    assert!(super::should_filter_loopback(
        &node.interface.swarm,
        &node.interface.network
    ));
    let (old_listener, loopback) = remote.listen().await?;
    let public = with_ip(loopback.clone(), Ipv4Addr::new(203, 0, 113, 2));
    remote.interface.swarm.add_external_address(public.clone());
    node.interface.swarm.dial(public.clone())?;
    let info = node.identify_with(&mut remote).await?;
    assert!(info.listen_addrs.contains(&loopback));
    assert!(info.listen_addrs.contains(&public));

    let mut events = node.interface.event_tx.subscribe();
    let (_, new_loopback) = remote.listen().await?;
    let mut advertised = vec![public.clone()];
    let mut new_public = public.clone();
    for update in 0..35 {
        for address in advertised.drain(..) {
            remote.interface.swarm.remove_external_address(&address);
        }
        new_public = with_ip(new_loopback.clone(), Ipv4Addr::new(203, 0, 113, update + 3));
        advertised.push(new_public.clone());
        if update == 32 {
            // More short addresses than the count limit, below the byte limit.
            for last in 1..=12 {
                advertised.push(with_ip(
                    new_loopback.clone(),
                    Ipv4Addr::new(192, 0, 2, last),
                ));
            }
        } else if update == 33 {
            // Fewer addresses than the count limit, above the byte limit. The complete
            // Identify message still fits libp2p's message limit.
            for suffix in 0..4 {
                advertised.push(
                    format!(
                        "/dns4/{}-{suffix}.example/udp/1234/quic-v1",
                        "a".repeat(650)
                    )
                    .parse()?,
                );
            }
        }
        for address in &advertised {
            remote.interface.swarm.add_external_address(address.clone());
        }
        remote
            .interface
            .swarm
            .behaviour_mut()
            .identify
            .push([node.peer_id()]);
        let info = node.identify_with(&mut remote).await?;
        assert!(info.listen_addrs.contains(&new_loopback));
        assert!(advertised
            .iter()
            .all(|address| info.listen_addrs.contains(address)));
        assert!(!info.listen_addrs.contains(&public));
        let bucket = node
            .interface
            .swarm
            .behaviour_mut()
            .kademlia
            .kbucket(remote.peer_id())
            .expect("peer bucket");
        let retained = bucket
            .iter()
            .find(|entry| entry.node.key.preimage() == &remote.peer_id())
            .expect("admitted peer in the routing table")
            .node
            .value;
        assert!(
            retained
                .iter()
                .any(|address| super::strip_peer_id(address.clone()) == public),
            "an Identify update removed the live connection address"
        );
        let identified: Vec<_> = retained
            .iter()
            .filter(|address| super::strip_peer_id((*address).clone()) != public)
            .collect();
        assert!(
            identified.len() <= 8,
            "retained too many Identify addresses: {}",
            identified.len()
        );
        assert!(
            identified
                .iter()
                .map(|address| address.len())
                .sum::<usize>()
                <= 2048,
            "retained Identify addresses exceed the byte limit"
        );
        assert!(
            identified.iter().all(|address| {
                let address = super::strip_peer_id((*address).clone());
                !super::is_loopback_addr(&address) && advertised.contains(&address)
            }),
            "retained a superseded or unfiltered Identify address"
        );
    }
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                event,
                super::NetEvent::ConnectionEstablished { .. }
                    | super::NetEvent::ConfiguredDialAdmitted { .. }
            ),
            "an address update must not repeat admission notifications"
        );
    }
    assert!(remote.interface.swarm.remove_listener(old_listener));
    loop {
        let event = remote.next_event().await?;
        let closed = matches!(
            &event,
            super::SwarmEvent::ListenerClosed { listener_id, .. } if *listener_id == old_listener
        );
        remote.process(event).await?;
        if closed {
            break;
        }
    }

    for reconnect in 0..3 {
        if reconnect == 1 {
            for last in 1..=8 {
                let address: Multiaddr = format!("/ip4/192.0.2.{last}/udp/9/quic-v1").parse()?;
                remote.interface.swarm.add_external_address(address.clone());
                advertised.push(address);
            }
            remote
                .interface
                .swarm
                .behaviour_mut()
                .identify
                .push([node.peer_id()]);
            let info = node.identify_with(&mut remote).await?;
            assert_eq!(
                info.listen_addrs
                    .iter()
                    .filter(|address| !super::is_loopback_addr(address))
                    .position(|address| address == &new_public),
                Some(8),
                "the working endpoint must follow eight other eligible addresses"
            );
        }
        node.interface
            .swarm
            .disconnect_peer_id(remote.peer_id())
            .unwrap();
        while node.admission.is_admitted(&remote.peer_id())
            || remote.admission.is_admitted(&node.peer_id())
        {
            tokio::select! {
                event = node.next_event() => node.process(event?).await?,
                event = remote.next_event() => remote.process(event?).await?,
            }
        }
        let bucket = node
            .interface
            .swarm
            .behaviour_mut()
            .kademlia
            .kbucket(remote.peer_id())
            .expect("peer bucket");
        let mut retained: Vec<_> = bucket
            .iter()
            .find(|entry| entry.node.key.preimage() == &remote.peer_id())
            .expect("peer remains available for reconnection")
            .node
            .value
            .iter()
            .cloned()
            .map(super::strip_peer_id)
            .collect();
        assert!(
            retained.contains(&new_public),
            "disconnect removed a working endpoint that the peer still advertises"
        );
        let mut expected: Vec<_> = advertised.iter().take(8).cloned().collect();
        retained.sort();
        expected.sort();
        assert_eq!(
            retained, expected,
            "retain the advertised endpoint, then fill the remaining slots in advertised order"
        );
        dials.lock().unwrap().clear();
        node.interface.swarm.dial(remote.peer_id())?;
        let attempted = dials.lock().unwrap().clone();
        assert!(!attempted.is_empty());
        assert!(
            attempted
                .iter()
                .all(|address| !super::is_loopback_addr(address)),
            "dialed an unfiltered address: {attempted:?}"
        );
        assert!(
            attempted
                .iter()
                .any(|address| super::strip_peer_id(address.clone()) == new_public),
            "the updated public address was not dialed: {attempted:?}"
        );
        let info = node.identify_with(&mut remote).await?;
        assert!(info.listen_addrs.contains(&new_loopback));
        assert!(advertised
            .iter()
            .all(|address| info.listen_addrs.contains(address)));
        assert!(!info.listen_addrs.contains(&public));
    }
    Ok(())
}

async fn check_inbound_put_expiry(published_here: bool) -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let mut remote = TestNode::new()?;
    let (_, address) = remote.listen().await?;
    node.interface.swarm.dial(address)?;
    node.identify_with(&mut remote).await?;
    let value = b"document with a retained expiry".to_vec();
    let key = super::ContentHash::from_content(&value);
    let record_key = RecordKey::new(&key);
    let expires = Some(Instant::now() + Duration::from_secs(3600));
    let mut record = Record {
        key: record_key.clone(),
        value: value.clone(),
        publisher: None,
        expires,
    };
    if published_here {
        super::handle_store_local(
            &mut node.interface.swarm,
            &mut node.replicas,
            &node.interface.event_tx,
            e3_events::CorrelationId::new(),
            key,
            expires,
            e3_utils::ArcBytes::from_bytes(&value),
        )?;
    } else {
        node.receive_put(&mut remote, record.clone()).await?;
    }
    let original = node
        .interface
        .swarm
        .behaviour_mut()
        .kademlia
        .store_mut()
        .get(&record_key)
        .expect("stored document")
        .into_owned();

    record.expires = Some(Instant::now() + Duration::from_secs(60));
    let incoming = node.receive_put(&mut remote, record.clone()).await?;
    assert!(incoming.expires < original.expires);
    let store = node.interface.swarm.behaviour_mut().kademlia.store_mut();
    assert_eq!(store.get(&record_key).as_deref(), Some(&original));
    super::prune_expired_records(store, incoming.expires.unwrap() + Duration::from_secs(1));
    assert_eq!(store.get(&record_key).as_deref(), Some(&original));

    record.expires = Some(Instant::now() + Duration::from_secs(7200));
    let incoming = node.receive_put(&mut remote, record.clone()).await?;
    let stored = node
        .interface
        .swarm
        .behaviour_mut()
        .kademlia
        .store_mut()
        .get(&record_key)
        .unwrap()
        .into_owned();
    if published_here {
        assert_eq!(
            stored, original,
            "only this node controls its published record"
        );
    } else {
        assert!(stored.expires > original.expires);
        assert_eq!(
            stored,
            Record {
                expires: incoming.expires,
                ..original
            }
        );
    }

    // A record without an expiry is not shortened to a finite lifetime.
    let unbounded = Record {
        expires: None,
        ..stored
    };
    node.interface
        .swarm
        .behaviour_mut()
        .kademlia
        .store_mut()
        .put(unbounded.clone())?;
    node.receive_put(&mut remote, record).await?;
    assert_eq!(
        node.interface
            .swarm
            .behaviour_mut()
            .kademlia
            .store_mut()
            .get(&record_key)
            .as_deref(),
        Some(&unbounded)
    );
    Ok(())
}

#[tokio::test]
async fn inbound_put_preserves_locally_published_record() -> anyhow::Result<()> {
    check_inbound_put_expiry(true).await
}

#[tokio::test]
async fn inbound_put_never_shortens_replica_expiry() -> anyhow::Result<()> {
    check_inbound_put_expiry(false).await
}

fn is_redial_backoff(error: &libp2p::swarm::DialError) -> bool {
    matches!(
        error,
        libp2p::swarm::DialError::Denied { cause }
            if cause.downcast_ref::<crate::gossip_subscription_health::RedialBackoff>().is_some()
    )
}

#[tokio::test]
async fn redial_backoff_refuses_outbound_dials_until_a_subscription() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let peer = PeerId::random();
    node.health()
        .disconnected_unsubscribed(peer, Instant::now());

    let refused = node.dial(peer).expect_err("a dial during the backoff");
    assert!(is_redial_backoff(&refused), "{refused}");

    node.health().subscribed(&peer);
    node.dial(peer)?;
    Ok(())
}

/// The health check disconnects an admitted peer that stayed without a gossip subscription for the
/// grace period, and that disconnect starts the redial backoff: the next dial that names the peer
/// is refused.
#[tokio::test]
async fn health_disconnect_starts_redial_backoff() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    node.interface
        .swarm
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
    let address = loop {
        if let super::SwarmEvent::NewListenAddr { address, .. } = node.next_event().await? {
            break address;
        }
    };
    // A compatible peer that never subscribes to the topic.
    let mut remote = super::Libp2pNetInterface::new(
        super::Libp2pKeypair::generate(),
        vec![],
        None,
        super::NetworkPolicy::local_unrestricted(),
    )?;
    let remote_id = *remote.swarm.local_peer_id();
    remote.swarm.dial(address)?;
    let remote_task = tokio::spawn(async move {
        use libp2p::futures::StreamExt;
        loop {
            remote.swarm.select_next_some().await;
        }
    });
    while !node.admission.is_admitted(&remote_id) {
        let event = node.next_event().await?;
        let _ = node.process(event).await;
    }

    // The peer has been connected without a subscription for longer than the grace period.
    let missing_since = Instant::now()
        .checked_sub(super::GOSSIP_SUBSCRIPTION_GRACE + Duration::from_secs(1))
        .ok_or_else(|| anyhow::anyhow!("the monotonic clock is younger than the grace period"))?;
    node.health()
        .stale_peers(&HashSet::from([remote_id]), &HashSet::new(), missing_since);
    super::reconcile_gossip_subscriptions(
        &mut node.interface.swarm,
        &node.admission,
        &node.interface.topic,
        &node.interface.status,
    );
    remote_task.abort();
    loop {
        let event = node.next_event().await?;
        let closed = matches!(
            &event,
            super::SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } if *peer_id == remote_id
        );
        let _ = node.process(event).await;
        if closed {
            break;
        }
    }

    let refused = node.dial(remote_id).expect_err("a dial during the backoff");
    assert!(is_redial_backoff(&refused), "{refused}");
    Ok(())
}

/// A Kademlia query keeps the candidates that it chose before the disconnect, and dials them
/// with addresses from its routing table or the Identify cache. The backoff holds back these
/// dials too.
#[tokio::test]
async fn dht_query_does_not_dial_a_peer_in_redial_backoff() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let peer = PeerId::random();
    let address: Multiaddr = "/ip4/127.0.0.2/udp/9/quic-v1".parse()?;
    let kademlia = &mut node.interface.swarm.behaviour_mut().kademlia;
    kademlia.add_address(&peer, address);
    let query = kademlia.get_closest_peers(PeerId::random());
    node.health()
        .disconnected_unsubscribed(peer, Instant::now());

    loop {
        match node.next_event().await? {
            super::SwarmEvent::Dialing {
                peer_id: Some(dialed),
                ..
            } if dialed == peer => anyhow::bail!("the query dialed a peer in its backoff"),
            super::SwarmEvent::Behaviour(super::NodeBehaviourEvent::Kademlia(
                libp2p::kad::Event::OutboundQueryProgressed { id, .. },
            )) if id == query => return Ok(()),
            _ => {}
        }
    }
}

/// A peer that subscribes after its admission ends its backoff at the subscribe event, so a
/// disconnect before the next health check leaves it free to be dialed at once.
#[tokio::test]
async fn subscribe_event_after_admission_ends_the_redial_backoff() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let peer = PeerId::random();
    let address: Multiaddr = "/ip4/127.0.0.1/udp/9/quic-v1".parse()?;
    node.admission
        .stage(
            peer,
            super::PeerAdmission::pending(ConnectionId::new_unchecked(1), address, "inbound", 1),
        )
        .map_err(|kind| anyhow::anyhow!("staging failed: {kind:?}"))?;
    node.admission.admit(peer);
    node.health()
        .disconnected_unsubscribed(peer, Instant::now());

    let topic = node.interface.topic.hash();
    node.process(super::SwarmEvent::Behaviour(
        super::NodeBehaviourEvent::Gossipsub(libp2p::gossipsub::Event::Subscribed {
            peer_id: peer,
            topic,
        }),
    ))
    .await?;

    node.dial(peer)?;
    Ok(())
}

/// A peer that subscribes before its admission: the node ignores the subscribe event and sees
/// the subscription when Identify admits the peer. That also ends the backoff at once.
#[tokio::test]
async fn subscription_before_admission_ends_the_redial_backoff() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    node.interface
        .swarm
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;
    let address = loop {
        if let super::SwarmEvent::NewListenAddr { address, .. } = node.next_event().await? {
            break address;
        }
    };
    let mut remote = TestNode::new()?;
    let remote_id = remote.peer_id();
    // Read the backoff at its start, so the check below cannot pass because the backoff ran out.
    let backoff_start = Instant::now();
    node.health()
        .disconnected_unsubscribed(remote_id, backoff_start);
    remote.interface.swarm.dial(address)?;
    let remote_task = tokio::spawn(async move {
        use libp2p::futures::StreamExt;
        loop {
            remote.interface.swarm.select_next_some().await;
        }
    });

    // Hold the Identify result back until the subscribe event of the remote was processed.
    let mut identify = None;
    let mut subscribed = false;
    while identify.is_none() || !subscribed {
        match node.next_event().await? {
            event @ super::SwarmEvent::Behaviour(super::NodeBehaviourEvent::Identify(
                libp2p::identify::Event::Received { peer_id, .. },
            )) if peer_id == remote_id && identify.is_none() => identify = Some(event),
            event @ super::SwarmEvent::Behaviour(super::NodeBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Subscribed { peer_id, .. },
            )) if peer_id == remote_id && !subscribed => {
                node.process(event).await?;
                assert!(!node.admission.is_admitted(&remote_id));
                subscribed = true;
            }
            event => {
                let _ = node.process(event).await;
            }
        }
    }
    node.process(identify.expect("held above")).await?;
    remote_task.abort();

    assert!(node.admission.is_admitted(&remote_id));
    assert!(node
        .interface
        .swarm
        .behaviour()
        .gossip_health
        .may_redial(&remote_id, backoff_start));
    Ok(())
}

/// The result of a put that `sender` reports, while both nodes run. The receiver drops inbound
/// puts unless it `stores`, which Kademlia acknowledges all the same. Every event of the put after
/// its result is collected too.
async fn put_through(
    sender: &mut TestNode,
    receiver: &mut TestNode,
    stores: bool,
    command: crate::events::NetCommand,
) -> anyhow::Result<Vec<crate::events::NetEvent>> {
    use crate::events::NetEvent;
    let correlation_id = command
        .correlation_id()
        .expect("a put has a correlation ID");
    let mut events = sender.interface.event_tx.subscribe();
    sender.command(command).await?;
    let mut results = Vec::new();
    let mut quiet_after_result = 0;
    while quiet_after_result < 20 {
        tokio::select! {
            event = sender.next_event() => sender.process(event?).await?,
            event = receiver.next_event() => {
                let event = event?;
                let inbound_put = matches!(
                    &event,
                    super::SwarmEvent::Behaviour(super::NodeBehaviourEvent::Kademlia(
                        libp2p::kad::Event::InboundRequest {
                            request: libp2p::kad::InboundRequest::PutRecord { .. },
                        },
                    ))
                );
                if stores || !inbound_put {
                    receiver.process(event).await?;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)), if !results.is_empty() => {
                quiet_after_result += 1;
            }
        }
        while let Ok(event) = events.try_recv() {
            let ours = matches!(
                &event,
                NetEvent::DhtPutRecordSucceeded { correlation_id: id, .. }
                    | NetEvent::DhtPutRecordError { correlation_id: id, .. } if *id == correlation_id
            );
            if ours {
                results.push(event);
            }
        }
    }
    Ok(results)
}

fn put_command(value: &[u8]) -> (crate::events::NetCommand, e3_events::CorrelationId) {
    let correlation_id = e3_events::CorrelationId::new();
    let command = crate::events::NetCommand::DhtPutRecord {
        correlation_id,
        key: super::ContentHash::from_content(value),
        expires: Some(Instant::now() + Duration::from_secs(3600)),
        value: e3_utils::ArcBytes::from_bytes(value),
        deadline: Instant::now() + Duration::from_secs(240),
    };
    (command, correlation_id)
}

/// Kademlia acknowledges an inbound put before the receiver decides to store the record. A put
/// counts as stored only when the receiver serves the record back. When the receiver drops it, the
/// put fails as not replicated, once, under its own correlation ID.
#[tokio::test]
async fn a_put_counts_only_when_another_peer_serves_the_record_back() -> anyhow::Result<()> {
    use crate::events::{NetEvent, PutOrStoreError};
    for stores in [true, false] {
        let mut sender = TestNode::new()?;
        let mut receiver = TestNode::new()?;
        let (_, address) = receiver.listen().await?;
        sender.interface.swarm.dial(address)?;
        sender.identify_with(&mut receiver).await?;
        let (command, correlation_id) = put_command(b"a replicated document");

        let results = put_through(&mut sender, &mut receiver, stores, command).await?;

        assert_eq!(results.len(), 1, "stores={stores}: {results:?}");
        match &results[0] {
            NetEvent::DhtPutRecordSucceeded {
                correlation_id: id, ..
            } => {
                assert!(stores);
                assert_eq!(*id, correlation_id);
            }
            NetEvent::DhtPutRecordError {
                correlation_id: id,
                error: PutOrStoreError::NotReplicated,
            } => {
                assert!(!stores);
                assert_eq!(*id, correlation_id);
            }
            other => panic!("stores={stores}: unexpected result {other:?}"),
        }
        let summary = sender.dht_puts.take_summary();
        assert_eq!(summary, Some(if stores { (1, 0) } else { (0, 1) }));
        assert!(sender.dht_puts.is_empty(), "stores={stores}");
    }
    Ok(())
}

/// A cancel while the put still looks up its closest peers reports the put cancelled at once. The
/// upload that follows starts no check and counts nothing.
#[tokio::test]
async fn a_put_cancelled_in_its_lookup_reports_once_and_checks_nothing() -> anyhow::Result<()> {
    use crate::events::{NetCommand, NetEvent, PutOrStoreError};
    let mut sender = TestNode::new()?;
    let mut receiver = TestNode::new()?;
    let (_, address) = receiver.listen().await?;
    sender.interface.swarm.dial(address)?;
    sender.identify_with(&mut receiver).await?;
    let value = b"a document whose E3 ended";
    let (command, correlation_id) = put_command(value);
    let mut events = sender.interface.event_tx.subscribe();
    sender.command(command).await?;
    assert!(sender
        .interface
        .swarm
        .behaviour()
        .kademlia
        .iter_queries()
        .any(|query| matches!(
            query.info(),
            libp2p::kad::QueryInfo::PutRecord {
                phase: libp2p::kad::PutRecordPhase::GetClosestPeers,
                ..
            }
        )));
    sender
        .command(NetCommand::DhtCancelPut {
            key: super::ContentHash::from_content(value),
        })
        .await?;
    assert!(matches!(
        events.try_recv(),
        Ok(NetEvent::DhtPutRecordError {
            correlation_id: id,
            error: PutOrStoreError::Cancelled,
        }) if id == correlation_id
    ));

    // The lookup runs on and uploads; its end starts no check.
    let record_key = RecordKey::new(&super::ContentHash::from_content(value));
    while !sender.dht_puts.is_empty() {
        tokio::select! {
            event = sender.next_event() => sender.process(event?).await?,
            event = receiver.next_event() => receiver.process(event?).await?,
        }
        assert!(!sender
            .interface
            .swarm
            .behaviour()
            .kademlia
            .iter_queries()
            .any(|query| matches!(
                query.info(),
                libp2p::kad::QueryInfo::GetRecord { key, .. } if *key == record_key
            )));
    }
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                &event,
                NetEvent::DhtPutRecordSucceeded { correlation_id: id, .. }
                    | NetEvent::DhtPutRecordError { correlation_id: id, .. } if *id == correlation_id
            ),
            "a second result: {event:?}"
        );
    }
    assert_eq!(sender.dht_puts.take_summary(), None);
    Ok(())
}

/// A put command that the interface takes after its caller's deadline reports expired at once and
/// starts nothing.
#[tokio::test]
async fn a_put_taken_after_its_deadline_reports_expired_and_starts_nothing() -> anyhow::Result<()> {
    use crate::events::{NetCommand, NetEvent, PutOrStoreError};
    let mut node = TestNode::new()?;
    let mut events = node.interface.event_tx.subscribe();
    let (
        NetCommand::DhtPutRecord {
            correlation_id,
            key,
            expires,
            value,
            ..
        },
        _,
    ) = put_command(b"a document whose caller stopped waiting")
    else {
        unreachable!();
    };
    node.command(NetCommand::DhtPutRecord {
        correlation_id,
        key,
        expires,
        value,
        deadline: Instant::now(),
    })
    .await?;

    assert!(matches!(
        events.try_recv(),
        Ok(NetEvent::DhtPutRecordError {
            correlation_id: id,
            error: PutOrStoreError::Expired,
        }) if id == correlation_id
    ));
    assert!(node.dht_puts.is_empty());
    assert_eq!(node.dht_puts.take_summary(), Some((0, 1)));
    Ok(())
}

/// The interface runs at most 16 puts. The next one is refused at once.
#[tokio::test]
async fn a_put_beyond_the_capacity_is_refused() -> anyhow::Result<()> {
    use crate::events::{NetEvent, PutOrStoreError};
    let mut node = TestNode::new()?;
    let mut events = node.interface.event_tx.subscribe();
    for index in 0..super::MAX_DHT_PUTS {
        let (command, _) = put_command(format!("document {index}").as_bytes());
        node.command(command).await?;
    }
    let (command, correlation_id) = put_command(b"one document too many");
    node.command(command).await?;

    let mut refused = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let NetEvent::DhtPutRecordError {
            correlation_id: id,
            error: PutOrStoreError::Busy,
        } = event
        {
            refused.push(id);
        }
    }
    assert_eq!(refused, vec![correlation_id]);
    Ok(())
}

/// The lookup that checks a put counts only another peer's copy of the requested record. A record
/// under another key, one whose content does not hash to the key, the requested content under
/// another key, and this node's own copy are ignored; a valid copy reports the put stored once; a check that ends without one reports it not
/// replicated.
#[tokio::test]
async fn a_put_check_counts_only_a_peers_valid_copy_of_the_requested_record() -> anyhow::Result<()>
{
    use crate::events::{NetEvent, PutOrStoreError};
    use libp2p::kad::{GetRecordOk, PeerRecord};
    let mut node = TestNode::new()?;
    let mut events = node.interface.event_tx.subscribe();
    let peer = PeerId::random();
    let now = Instant::now();
    let deadline = now + Duration::from_secs(240);
    let value = b"the requested document".to_vec();
    let key = super::ContentHash::from_content(&value);
    let record = |key: RecordKey, value: &[u8]| Record::new(key, value.to_vec());
    let found = |peer: Option<PeerId>,
                 record: Record|
     -> Result<GetRecordOk, libp2p::kad::GetRecordError> {
        Ok(GetRecordOk::FoundRecord(PeerRecord { peer, record }))
    };
    // A put whose upload ended, now in its check.
    let check_put = |node: &mut TestNode, correlation_id| {
        let kademlia = &mut node.interface.swarm.behaviour_mut().kademlia;
        let upload = kademlia.get_closest_peers(PeerId::random());
        let check = kademlia.get_record(RecordKey::new(&key));
        node.dht_puts
            .start(correlation_id, key.clone(), upload, deadline);
        assert!(node.dht_puts.upload_ended(upload, Ok(())).is_some());
        node.dht_puts.checking(correlation_id, check);
        check
    };
    let results = |events: &mut tokio::sync::broadcast::Receiver<NetEvent>, put| {
        let mut results = Vec::new();
        while let Ok(event) = events.try_recv() {
            match event {
                NetEvent::DhtPutRecordSucceeded { correlation_id, .. } if correlation_id == put => {
                    results.push("stored")
                }
                NetEvent::DhtPutRecordError {
                    correlation_id,
                    error: PutOrStoreError::NotReplicated,
                } if correlation_id == put => results.push("not replicated"),
                _ => {}
            }
        }
        results
    };

    let stored = e3_events::CorrelationId::new();
    let check = check_put(&mut node, stored);
    let other = b"another document";
    let wrong = [
        found(
            Some(peer),
            record(
                RecordKey::new(&super::ContentHash::from_content(other)),
                other,
            ),
        ),
        found(Some(peer), record(RecordKey::new(&key), b"other content")),
        found(
            Some(peer),
            record(
                RecordKey::new(&super::ContentHash::from_content(other)),
                &value,
            ),
        ),
        found(None, record(RecordKey::new(&key), &value)),
    ];
    for result in &wrong {
        super::handle_put_check(
            &mut node.interface.swarm,
            &node.interface.event_tx,
            &mut node.dht_puts,
            check,
            result,
            false,
        )?;
    }
    assert!(results(&mut events, stored).is_empty());
    let valid = found(Some(peer), record(RecordKey::new(&key), &value));
    for last in [false, false, true] {
        super::handle_put_check(
            &mut node.interface.swarm,
            &node.interface.event_tx,
            &mut node.dht_puts,
            check,
            &valid,
            last,
        )?;
    }
    assert_eq!(results(&mut events, stored), vec!["stored"]);

    let missing = e3_events::CorrelationId::new();
    let check = check_put(&mut node, missing);
    for (result, last) in wrong.iter().zip([false, false, false, true]) {
        super::handle_put_check(
            &mut node.interface.swarm,
            &node.interface.event_tx,
            &mut node.dht_puts,
            check,
            result,
            last,
        )?;
    }
    assert_eq!(results(&mut events, missing), vec!["not replicated"]);
    assert!(node.dht_puts.is_empty());
    Ok(())
}

/// Kademlia keeps a finished query, with its record, until the swarm polls it out, and `query()`
/// no longer returns it in between. A cancelled upload keeps its place in the capacity until that
/// last event, however long the swarm is not polled.
#[tokio::test]
async fn a_cancelled_upload_keeps_its_place_until_kademlia_ends_its_query() -> anyhow::Result<()> {
    use crate::events::NetCommand;
    use libp2p::kad::{PutRecordPhase, QueryInfo};
    let mut sender = TestNode::new()?;
    let mut receiver = TestNode::new()?;
    let (_, address) = receiver.listen().await?;
    sender.interface.swarm.dial(address)?;
    sender.identify_with(&mut receiver).await?;
    let value = b"a document whose upload is cancelled";
    let (command, _) = put_command(value);
    sender.command(command).await?;
    let uploading = |node: &TestNode| {
        node.interface
            .swarm
            .behaviour()
            .kademlia
            .iter_queries()
            .find_map(|query| {
                matches!(
                    query.info(),
                    QueryInfo::PutRecord {
                        phase: PutRecordPhase::PutRecord { .. },
                        ..
                    }
                )
                .then(|| query.id())
            })
    };
    // Run both nodes until the put uploads; the receiver is not polled after that, so the upload
    // is not acknowledged.
    let upload = loop {
        if let Some(upload) = uploading(&sender) {
            break upload;
        }
        tokio::select! {
            event = sender.next_event() => sender.process(event?).await?,
            event = receiver.next_event() => receiver.process(event?).await?,
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    };

    sender
        .command(NetCommand::DhtCancelPut {
            key: super::ContentHash::from_content(value),
        })
        .await?;

    assert!(sender
        .interface
        .swarm
        .behaviour()
        .kademlia
        .query(&upload)
        .is_none());
    sender
        .dht_puts
        .expire(Instant::now() + Duration::from_secs(60 * 60));
    assert!(sender.dht_puts.owns(&upload));
    while sender.dht_puts.owns(&upload) {
        let event = sender.next_event().await?;
        sender.process(event).await?;
    }
    assert!(sender.dht_puts.is_empty());
    Ok(())
}

/// The event loop's deadline timer ends a put whose query outlives its caller's deadline. The
/// caller gets one `Expired` result before the deadline that it waits for, and nothing more when
/// the query ends later.
#[tokio::test]
async fn a_running_put_reports_expired_at_its_deadline_once() -> anyhow::Result<()> {
    use crate::events::{NetCommand, NetEvent};
    use crate::NetInterface;
    // A peer that the node admits and that then stops answering, so the put's lookup waits on it
    // until Kademlia gives up on the peer (10 s).
    let mut silent = TestNode::new()?;
    silent
        .interface
        .swarm
        .listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    // The node listens on every interface, so it keeps loopback addresses out of its routing
    // table; it gets the peer's other address when the host has one.
    let mut addresses = Vec::new();
    let listening = tokio::time::Instant::now() + Duration::from_secs(2);
    while let Ok(event) = tokio::time::timeout_at(listening, silent.next_event()).await {
        let event = event?;
        if let super::SwarmEvent::NewListenAddr { address, .. } = &event {
            addresses.push(address.clone());
        }
        silent.process(event).await?;
    }
    let address = addresses
        .iter()
        .find(|address| !super::is_loopback_addr(address))
        .or(addresses.first())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("the peer did not listen"))?;
    let mut node = super::Libp2pNetInterface::new(
        super::Libp2pKeypair::generate(),
        vec![format!("{address}/p2p/{}", silent.peer_id())],
        None,
        super::NetworkPolicy::local_unrestricted(),
    )?;
    let handle = node.handle();
    let mut events = handle.rx();
    let running = tokio::spawn(async move { node.start().await });
    let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
    let driver = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stopped => return silent,
                event = silent.next_event() => {
                    if let Ok(event) = event {
                        let _ = silent.process(event).await;
                    }
                }
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(30), async {
        while handle.status().snapshot().gossip_subscribed_peers == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    let _ = stop.send(());
    let silent = driver.await?;

    let value = b"a document whose put outlives its deadline";
    let correlation_id = e3_events::CorrelationId::new();
    let deadline = Instant::now() + Duration::from_millis(500);
    handle
        .tx()
        .send(NetCommand::DhtPutRecord {
            correlation_id,
            key: super::ContentHash::from_content(value),
            expires: Some(Instant::now() + Duration::from_secs(3600)),
            value: e3_utils::ArcBytes::from_bytes(value),
            deadline,
        })
        .await?;
    let mut results = Vec::new();
    // The caller waits until its deadline and one run of the deadline timer more (the publisher
    // waits 30 s more). After it, Kademlia gives up on the silent peer and the query ends.
    let waits_until = tokio::time::Instant::from_std(
        deadline + super::DHT_PUT_DEADLINE_INTERVAL + Duration::from_secs(1),
    );
    let quiet_until = waits_until + Duration::from_secs(15);
    while tokio::time::Instant::now() < quiet_until {
        let Ok(event) = tokio::time::timeout_at(quiet_until, events.recv()).await else {
            break;
        };
        let event = match event {
            Ok(event) => event,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(error) => return Err(error.into()),
        };
        match event {
            NetEvent::DhtPutRecordSucceeded {
                correlation_id: id, ..
            } if id == correlation_id => {
                results.push(("stored".to_string(), tokio::time::Instant::now()));
            }
            NetEvent::DhtPutRecordError {
                correlation_id: id,
                error,
            } if id == correlation_id => {
                results.push((format!("{error:?}"), tokio::time::Instant::now()));
            }
            _ => {}
        }
    }
    running.abort();
    drop(silent);

    assert_eq!(results.len(), 1, "{results:?}");
    let (result, at) = &results[0];
    assert_eq!(result, "Expired");
    assert!(
        *at <= waits_until,
        "the result came after the caller stopped waiting"
    );
    Ok(())
}

/// A put that fails reaches the summary as failed.
#[tokio::test]
async fn a_failed_dht_upload_is_counted_for_the_summary() -> anyhow::Result<()> {
    let mut node = TestNode::new()?;
    let (command, _) = put_command(b"value");
    node.command(command).await?;
    while !node.dht_puts.is_empty() {
        let event = node.next_event().await?;
        node.process(event).await?;
    }
    assert_eq!(node.dht_puts.take_summary(), Some((0, 1)));
    Ok(())
}

mod notification_ingress {
    use crate::{
        events::{DocumentPublishedNotification, GossipData, NetCommand, NetEvent},
        ContentHash, Libp2pKeypair, Libp2pNetInterface, NetInterface, NetInterfaceHandle,
        NetworkPolicy,
    };
    use anyhow::{Context, Result};
    use chrono::{Timelike, Utc};
    use e3_events::{CorrelationId, DocumentKind, DocumentMeta, E3id, Filter};
    use libp2p::{gossipsub::MessageId, PeerId};
    use std::collections::HashSet;
    use std::time::Duration;
    use tokio::{
        sync::mpsc,
        time::{sleep, timeout},
    };

    async fn listen_address(handle: &NetInterfaceHandle) -> Result<String> {
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(address) = handle
                    .status()
                    .snapshot()
                    .listen_addresses
                    .into_iter()
                    .find(|address| address.starts_with("/ip4/127.0.0.1/"))
                {
                    return address;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("listener did not start")
    }

    struct GossipPath {
        handles: Vec<NetInterfaceHandle>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
        source: NetInterfaceHandle,
        source_events: tokio::sync::broadcast::Receiver<NetEvent>,
        receivers: Vec<mpsc::UnboundedReceiver<(PeerId, MessageId, Vec<u8>)>>,
    }

    impl Drop for GossipPath {
        fn drop(&mut self) {
            for task in &self.tasks {
                task.abort();
            }
        }
    }

    impl GossipPath {
        async fn new(relays: usize, receivers: usize) -> Result<Self> {
            let policy = NetworkPolicy::local_unrestricted();
            let mut handles = Vec::new();
            let mut tasks = Vec::new();
            let mut addresses = Vec::new();
            for _ in 0..relays {
                let key = Libp2pKeypair::generate();
                let peer = key.peer_id();
                let mut relay = Libp2pNetInterface::new(key, vec![], None, policy.clone())?;
                let handle = relay.handle();
                tasks.push(tokio::spawn(async move {
                    relay.start().await.unwrap();
                }));
                addresses.push(format!("{}/p2p/{peer}", listen_address(&handle).await?));
                handles.push(handle);
            }
            let mut source = Libp2pNetInterface::new(
                Libp2pKeypair::generate(),
                addresses.clone(),
                None,
                policy,
            )?;
            source.swarm.behaviour_mut().connection_limits =
                libp2p::connection_limits::Behaviour::new(
                    libp2p::connection_limits::ConnectionLimits::default()
                        .with_max_established(Some(relays as u32)),
                );
            let source_handle = source.handle();
            let source_events = source_handle.rx();
            handles.push(source.handle());
            tasks.push(tokio::spawn(async move {
                source.start().await.unwrap();
            }));
            let mut outputs = Vec::new();
            for _ in 0..receivers {
                let mut node = super::TestNode::new()?;
                node.interface.swarm.behaviour_mut().connection_limits =
                    libp2p::connection_limits::Behaviour::new(
                        libp2p::connection_limits::ConnectionLimits::default()
                            .with_max_established(Some(relays as u32)),
                    );
                for address in &addresses {
                    node.interface
                        .swarm
                        .dial(address.parse::<libp2p::Multiaddr>()?)?;
                }
                handles.push(node.interface.handle());
                let (raw, output) = mpsc::unbounded_channel();
                outputs.push(output);
                tasks.push(tokio::spawn(async move {
                    loop {
                        let event = node.next_event().await.unwrap();
                        if let super::super::SwarmEvent::Behaviour(
                            super::super::NodeBehaviourEvent::Gossipsub(
                                libp2p::gossipsub::Event::Message {
                                    propagation_source,
                                    message_id,
                                    message,
                                },
                            ),
                        ) = &event
                        {
                            // Observe bytes before the receiving interface can reject them.
                            raw.send((
                                *propagation_source,
                                message_id.clone(),
                                message.data.clone(),
                            ))
                            .unwrap();
                        }
                        node.process(event).await.unwrap();
                        super::super::reconcile_gossip_subscriptions(
                            &mut node.interface.swarm,
                            &node.admission,
                            &node.interface.topic,
                            &node.interface.status,
                        );
                    }
                }));
            }
            let path = Self {
                handles,
                tasks,
                source: source_handle,
                source_events,
                receivers: outputs,
            };
            timeout(Duration::from_secs(20), async {
                loop {
                    if path.handles.iter().enumerate().all(|(index, handle)| {
                        handle.status().snapshot().gossip_subscribed_peers
                            >= if index < relays {
                                receivers + 1
                            } else {
                                relays
                            }
                    }) {
                        break;
                    }
                    sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .context("gossip topology did not form")?;
            // Let the first heartbeat form the mesh before publishing the workload.
            sleep(Duration::from_secs(2)).await;
            Ok(path)
        }

        async fn publish(&mut self, data: GossipData) -> Result<MessageId> {
            let correlation_id = CorrelationId::new();
            self.source
                .tx()
                .send(NetCommand::GossipPublish {
                    topic: NetworkPolicy::local_unrestricted()
                        .protocols()
                        .gossip_topic()
                        .to_owned(),
                    data,
                    correlation_id,
                    delivery_id: None,
                })
                .await?;
            timeout(Duration::from_secs(5), async {
                loop {
                    match self.source_events.recv().await? {
                        NetEvent::GossipPublished {
                            correlation_id: id,
                            message_id,
                        } if id == correlation_id => return anyhow::Ok(message_id),
                        NetEvent::GossipPublishError {
                            correlation_id: id,
                            error,
                        } if id == correlation_id => anyhow::bail!("publication failed: {error}"),
                        _ => {}
                    }
                }
            })
            .await?
        }
    }

    fn notification(e3: u64, dealer: u64, recipient: u64) -> DocumentPublishedNotification {
        DocumentPublishedNotification {
            key: ContentHash::from_content(format!("{e3}:{dealer}:{recipient}").as_bytes()),
            ts: 1,
            meta: DocumentMeta::new(
                E3id::new(e3.to_string(), 1),
                DocumentKind::TrBFV,
                vec![Filter::Item(recipient)],
                Some(
                    (Utc::now() + chrono::Duration::hours(1))
                        .with_nanosecond(0)
                        .unwrap(),
                ),
            ),
        }
    }

    #[tokio::test]
    async fn invalid_notifications_stop_at_the_relay_but_other_party_documents_pass() -> Result<()>
    {
        let mut path = GossipPath::new(1, 1).await?;
        let valid = notification(1, 1, 7);
        let malformed = DocumentPublishedNotification {
            key: ContentHash(vec![1; 33]),
            ..valid.clone()
        };
        let mut expired = valid.clone();
        expired.meta.expires_at = Utc::now() - chrono::Duration::seconds(1);
        let warmup = path
            .publish(GossipData::DocumentPublishedNotification(notification(
                1, 2, 7,
            )))
            .await?;
        let bad_shape = path
            .publish(GossipData::DocumentPublishedNotification(malformed))
            .await?;
        let bad_expiry = path
            .publish(GossipData::DocumentPublishedNotification(expired))
            .await?;
        let valid_id = path
            .publish(GossipData::DocumentPublishedNotification(valid))
            .await?;
        let expected = HashSet::from([warmup, valid_id]);
        let mut delivered = HashSet::new();
        timeout(Duration::from_secs(10), async {
            while delivered.len() < expected.len() {
                let (_, id, _) = path.receivers[0].recv().await.context("receiver stopped")?;
                assert!(
                    expected.contains(&id),
                    "invalid notification reached the third peer before its validation: {id}"
                );
                delivered.insert(id);
            }
            anyhow::Ok(())
        })
        .await??;
        assert_eq!(delivered, expected);
        let extra = timeout(Duration::from_secs(2), path.receivers[0].recv()).await;
        assert!(extra.is_err(), "unexpected raw gossip after the controls: {extra:?}; rejected IDs: {bad_shape}, {bad_expiry}");
        Ok(())
    }

    #[tokio::test]
    async fn expiry_between_hops_preserves_relay_score_and_valid_delivery() -> Result<()> {
        let mut path = GossipPath::new(1, 0).await?;
        let relay: PeerId = path.source.status().snapshot().connected_peers[0]
            .peer_id
            .parse()?;
        let mut receiver = super::TestNode::new()?;
        let mut delivered = receiver.interface.handle().rx();
        receiver.interface.swarm.behaviour_mut().connection_limits =
            libp2p::connection_limits::Behaviour::new(
                libp2p::connection_limits::ConnectionLimits::default()
                    .with_max_established(Some(1)),
            );
        receiver.interface.swarm.dial(
            listen_address(&path.handles[0])
                .await?
                .parse::<libp2p::Multiaddr>()?,
        )?;
        timeout(Duration::from_secs(20), async {
            while !receiver.admission.is_admitted(&relay)
                || !receiver
                    .interface
                    .swarm
                    .behaviour()
                    .gossipsub
                    .all_peers()
                    .any(|(peer, topics)| *peer == relay && !topics.is_empty())
            {
                let event = receiver.next_event().await?;
                receiver.process(event).await?;
            }
            anyhow::Ok(())
        })
        .await??;

        let expiry = Utc::now() + chrono::Duration::seconds(3);
        let mut expected = HashSet::new();
        for dealer in 0..8 {
            let mut note = notification(1, dealer, 7);
            note.meta.expires_at = expiry;
            expected.insert(
                path.publish(GossipData::DocumentPublishedNotification(note))
                    .await?,
            );
        }
        let mut pending = Vec::new();
        timeout(Duration::from_secs(2), async {
            while pending.len() < expected.len() {
                let event = receiver.next_event().await?;
                if let super::super::SwarmEvent::Behaviour(
                    super::super::NodeBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message {
                            propagation_source,
                            message_id,
                            ..
                        },
                    ),
                ) = &event
                {
                    assert_eq!(*propagation_source, relay);
                    assert!(expected.contains(message_id));
                    assert!(Utc::now() < expiry, "the relay forwarded before expiry");
                    pending.push(event);
                } else {
                    receiver.process(event).await?;
                }
            }
            anyhow::Ok(())
        })
        .await??;
        // Hold application validation across expiry after the relay has forwarded the bytes.
        sleep((expiry - Utc::now()).to_std()? + Duration::from_millis(10)).await;
        let score = receiver
            .interface
            .swarm
            .behaviour()
            .gossipsub
            .peer_score(&relay)
            .context("relay score is enabled")?;
        for event in pending {
            receiver.process(event).await?;
        }
        assert_eq!(
            receiver
                .interface
                .swarm
                .behaviour()
                .gossipsub
                .peer_score(&relay),
            Some(score),
            "expiry must not penalize the relay",
        );
        while let Ok(event) = delivered.try_recv() {
            assert!(
                !matches!(event, NetEvent::DocumentIngress(_)),
                "expired notification was accepted"
            );
        }

        let valid = notification(2, 1, 9);
        let valid_id = path
            .publish(GossipData::DocumentPublishedNotification(valid.clone()))
            .await?;
        timeout(Duration::from_secs(10), async {
            loop {
                let event = receiver.next_event().await?;
                let is_valid = matches!(&event,
                    super::super::SwarmEvent::Behaviour(super::super::NodeBehaviourEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { propagation_source, message_id, .. }
                    )) if *propagation_source == relay && *message_id == valid_id);
                receiver.process(event).await?;
                if is_valid {
                    break;
                }
            }
            anyhow::Ok(())
        })
        .await??;
        assert!(std::iter::from_fn(|| delivered.try_recv().ok()).any(|event|
            matches!(event, NetEvent::DocumentIngress(ingress) if ingress.notification == valid)
        ), "valid traffic still reaches the document actor");
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_committee_bursts_reach_both_receivers_through_relays() -> Result<()> {
        use e3_events::{
            DKGRecursiveAggregationComplete, EventConstructorWithTimestamp, EventSource,
            InterfoldEvent, KeyshareCreated, Unsequenced,
        };
        use e3_utils::ArcBytes;
        // A concentrating relay, then two relay paths in a mesh. Both destinations need the
        // one-shot inputs used by active and standby aggregators.
        for relays in [1, 2] {
            let mut path = GossipPath::new(relays, 2).await?;
            let mut expected = HashSet::new();
            for e3 in 1..=2 {
                for dealer in 0..19 {
                    for recipient in 0..19 {
                        if recipient == dealer {
                            continue;
                        }
                        expected.insert(
                            path.publish(GossipData::DocumentPublishedNotification(notification(
                                e3, dealer, recipient,
                            )))
                            .await?,
                        );
                    }
                    for payload in [
                        KeyshareCreated {
                            e3_id: E3id::new(e3.to_string(), 1),
                            party_id: dealer,
                            node: "dealer".into(),
                            pubkey: ArcBytes::from_bytes(b"key"),
                            signed_pk_generation_proof: None,
                        }
                        .into(),
                        DKGRecursiveAggregationComplete::with_attestation(
                            E3id::new(e3.to_string(), 1),
                            dealer,
                            None,
                            None,
                        )
                        .into(),
                    ] {
                        let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
                            payload,
                            None,
                            1,
                            None,
                            EventSource::Local,
                        );
                        expected.insert(
                            path.publish(GossipData::GossipBytes(event.to_bytes()?))
                                .await?,
                        );
                    }
                }
            }
            assert_eq!(expected.len(), 2 * (342 + 19 + 19));
            for receiver in &mut path.receivers {
                let mut received = HashSet::new();
                timeout(Duration::from_secs(15), async {
                    while received.len() < expected.len() {
                        let (_, id, _) = receiver.recv().await.context("receiver stopped")?;
                        assert!(expected.contains(&id));
                        received.insert(id);
                    }
                    anyhow::Ok(())
                })
                .await
                .context("every committee contribution must reach each receiver")??;
                assert_eq!(received, expected);
            }
        }
        Ok(())
    }
}
