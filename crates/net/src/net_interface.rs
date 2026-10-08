// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    dial_guard::{DialGuard, RecentDials},
    dialer::dial_peers,
    events::{
        GossipData, GossipPublishFailure, IncomingRequest, NetCommand, NetEvent,
        OutgoingRequestFailed, OutgoingRequestSucceeded, PeerRejectionKind, PeerTarget,
        PutOrStoreError,
    },
    ContentHash,
};
use crate::{
    direct_responder::{ChannelType, DirectResponder},
    domain::{
        correlator::Correlator,
        dht_puts::{DhtPutResult, DhtPutStep, DhtPuts, EndedQuery, MAX_DHT_PUTS},
        peer_failure_tracker::PeerFailureTracker,
        replica_ledger::{ReplicaLedger, ReplicaLimits},
        wire::{encode_gossip, MAX_DHT_DOCUMENT_BYTES, MAX_GOSSIP_BYTES},
    },
    events::{IncomingResponse, OutgoingRequest, ProtocolResponse},
    gossip_ingress::GossipIngress,
    gossip_subscription_health::{GossipSubscriptionHealth, GOSSIP_SUBSCRIPTION_GRACE},
    keypair::Libp2pKeypair,
    net_interface_handle::{NetEventSender, NetInterfaceHandle},
    peer_admission::PeerAdmission,
    NetworkPolicy, NetworkStatus,
};
use anyhow::{bail, Context, Result};
use e3_events::CorrelationId;
use e3_utils::ArcBytes;
use libp2p::{
    connection_limits::{self, ConnectionLimits},
    futures::StreamExt,
    gossipsub,
    identify::{Behaviour as IdentifyBehaviour, Config as IdentifyConfig},
    identity::Keypair,
    kad::{
        self,
        store::{MemoryStore, MemoryStoreConfig, RecordStore},
        Behaviour as KademliaBehaviour, Config as KademliaConfig, GetRecordOk, InboundRequest,
        QueryResult, Quorum, Record, RecordKey, StoreInserts,
    },
    multiaddr::Protocol,
    request_response::{
        self, cbor, Event as RequestResponseEvent, Message as RequestResponseMessage,
        ProtocolSupport,
    },
    swarm::{
        dial_opts::DialOpts, ConnectionId, DialError, ListenError, NetworkBehaviour, SwarmEvent,
    },
    Multiaddr, Swarm,
};
use rand::prelude::IteratorRandom;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::Error,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{select, sync::mpsc, time::MissedTickBehavior};
use tracing::{debug, error, info, trace, warn};

const MAX_KADEMLIA_PAYLOAD_BYTES: usize = 26 * 1024 * 1024;
/// Kademlia timeout for each query phase (closest-peer lookup, then the put or get).
const DHT_QUERY_TIMEOUT: Duration = Duration::from_secs(60);
/// Time allowed for one Kademlia request on one stream. A put sends the whole document, up to
/// 20 at once, so the library default of 10 s fails every put on a slow uplink.
const DHT_SUBSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
/// gossipsub heartbeat. The library's tick-based defaults (message history, gossip windows,
/// graft timing) assume one second.
const GOSSIP_HEARTBEAT: Duration = Duration::from_secs(1);
/// Records that this node publishes or restored, beyond the inbound replicas. A local write that
/// finds no room evicts a replica.
const DHT_LOCAL_RECORDS: usize = 1024;
const DHT_MAX_RECORDS: usize = crate::ingress_limits::REPLICAS + DHT_LOCAL_RECORDS;
const DHT_REPLICA_LIMITS: ReplicaLimits = ReplicaLimits {
    per_owner: crate::ingress_limits::REPLICAS_PER_PEER,
    records: crate::ingress_limits::REPLICAS,
    bytes: crate::ingress_limits::REPLICA_BYTES,
};
const DHT_MAX_TTL: Duration = Duration::from_secs(31 * 24 * 60 * 60);
const DHT_MAX_PROVIDERS_PER_KEY: usize = 20;
const MAX_CONSECUTIVE_DIAL_FAILURES: u32 = 3;
const STALE_PEER_COOLDOWN: Duration = Duration::from_secs(30 * 60);
const CONFIGURED_PEER_REDIAL_INTERVAL: Duration = Duration::from_secs(15);
const GOSSIP_HEALTH_INTERVAL: Duration = Duration::from_secs(5);
/// How often expired DHT records are removed. Kademlia's own record jobs, which also removed them,
/// are disabled, and `MemoryStore` counts an expired record against its limits until it is removed.
const DHT_EXPIRY_INTERVAL: Duration = Duration::from_secs(60);
/// How often the interface reports finished DHT uploads at INFO.
const DHT_PUT_SUMMARY_INTERVAL: Duration = Duration::from_secs(60);
/// How often the interface ends the DHT puts that passed their deadline.
const DHT_PUT_DEADLINE_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const EVENT_CHANNEL_SIZE: usize = 1000;
const CMD_CHANNEL_SIZE: usize = 1000;
const MAX_IDENTIFY_ADDRESSES: usize = 8;
const MAX_IDENTIFY_ADDRESS_BYTES: usize = 2 * 1024;
const LIBP2P_ESTABLISHED_PER_PEER_LIMIT_TEXT: &str = "established connections per peer";

type GossipBehaviour =
    gossipsub::Behaviour<gossipsub::IdentityTransform, gossipsub::WhitelistSubscriptionFilter>;

/// Independent failure counters used to recover peer connectivity.
///
/// Identity mismatches are tracked separately because ordinary dial failures
/// must not consume the one-time recovery action for a peer whose key changed.
struct PeerConnectionFailures {
    dial: PeerFailureTracker,
    identity_mismatch: PeerFailureTracker,
    quarantined_until: HashMap<libp2p::PeerId, Instant>,
    identity_quarantined: HashSet<libp2p::PeerId>,
}

impl PeerConnectionFailures {
    fn new() -> Self {
        Self {
            dial: PeerFailureTracker::new(),
            identity_mismatch: PeerFailureTracker::new(),
            quarantined_until: HashMap::new(),
            identity_quarantined: HashSet::new(),
        }
    }

    fn connection_succeeded(&mut self, peer_id: &libp2p::PeerId) {
        self.dial.reset(peer_id);
        self.identity_mismatch.reset(peer_id);
        self.quarantined_until.remove(peer_id);
        self.identity_quarantined.remove(peer_id);
    }

    fn record_dial_failure(&mut self, peer_id: &libp2p::PeerId) -> Option<u32> {
        if self.is_quarantined(peer_id) {
            None
        } else {
            Some(self.dial.record_failure(peer_id))
        }
    }

    fn quarantine(&mut self, peer_id: &libp2p::PeerId) {
        self.dial.reset(peer_id);
        self.quarantined_until
            .insert(*peer_id, Instant::now() + STALE_PEER_COOLDOWN);
    }

    fn quarantine_identity(&mut self, peer_id: &libp2p::PeerId) {
        self.quarantine(peer_id);
        self.identity_quarantined.insert(*peer_id);
    }

    fn is_identity_quarantined(&mut self, peer_id: &libp2p::PeerId) -> bool {
        if !self.is_quarantined(peer_id) {
            self.identity_quarantined.remove(peer_id);
            return false;
        }
        self.identity_quarantined.contains(peer_id)
    }

    fn is_quarantined(&mut self, peer_id: &libp2p::PeerId) -> bool {
        let now = Instant::now();
        match self.quarantined_until.get(peer_id) {
            Some(until) if *until > now => true,
            Some(_) => {
                self.quarantined_until.remove(peer_id);
                false
            }
            None => false,
        }
    }

    fn quarantined_peers(&mut self) -> Vec<libp2p::PeerId> {
        let now = Instant::now();
        self.quarantined_until.retain(|_, until| *until > now);
        self.quarantined_until.keys().copied().collect()
    }
}

/// Returns true if the multiaddr contains a loopback IP (127.0.0.0/8 or ::1).
/// Loopback addresses are only meaningful on the local machine and must not be
/// added to the Kademlia routing table, otherwise they get propagated to remote
/// peers via FIND_NODE responses, causing those peers to dial themselves.
fn is_loopback_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_loopback(),
        // Also the IPv4-mapped form, ::ffff:127.0.0.1.
        Protocol::Ip6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        _ => false,
    })
}

/// Returns true only when we should filter loopback addresses from Kademlia.
/// This is the case on a public network, and when the node has at least one non-loopback
/// listener, meaning it's in a production-like environment where propagating loopback
/// addresses to remote peers would cause them to dial themselves. A public network does not
/// wait for the listeners: right after a start the swarm has not reported them yet.
/// In localhost test environments (all listeners on 127.0.0.1) we allow
/// loopback so that peers can discover each other.
fn should_filter_loopback(swarm: &Swarm<NodeBehaviour>, network: &NetworkPolicy) -> bool {
    network.profile().is_public()
        || swarm
            .listeners()
            .any(|addr| !is_loopback_addr(addr) && !is_unspecified_addr(addr))
}

/// Strip a trailing `/p2p/<peer-id>` component from a multiaddr.
/// Needed when re-keying a routing entry after a peer ID mismatch: the dialed
/// address still pins the stale peer ID, and re-adding it verbatim under the
/// new peer ID would make every subsequent dial fail with `WrongPeerId` again.
pub(crate) fn strip_peer_id(mut addr: Multiaddr) -> Multiaddr {
    if matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
        addr.pop();
    }
    addr
}

#[derive(Default)]
struct PeerAddresses {
    identify: Vec<Multiaddr>,
    connections: HashMap<ConnectionId, Multiaddr>,
}

impl PeerAddresses {
    fn refresh(
        &mut self,
        peer: libp2p::PeerId,
        advertised: Vec<Multiaddr>,
        filter_loopback: bool,
        kademlia: &mut KademliaBehaviour<MemoryStore>,
    ) {
        let mut advertised: Vec<_> = advertised
            .into_iter()
            .map(|address| strip_peer_id(address).with(Protocol::P2p(peer)))
            .collect();
        // Keep advertised live endpoints first so they remain available after disconnect.
        advertised.sort_by_key(|address| !self.connections.values().any(|live| live == address));
        let mut next = Vec::new();
        let mut bytes = 0;
        for address in advertised {
            if filter_loopback && is_loopback_addr(&address) {
                continue;
            }
            if next.contains(&address) || bytes + address.len() > MAX_IDENTIFY_ADDRESS_BYTES {
                continue;
            }
            bytes += address.len();
            next.push(address);
            if next.len() == MAX_IDENTIFY_ADDRESSES {
                break;
            }
        }

        // Remove old advertisements before inserting the bounded replacement. Live endpoints
        // stay until their connection closes, even when Identify no longer advertises them.
        let retired: Vec<_> = self
            .identify
            .iter()
            .filter(|address| {
                !next.contains(address) && !self.connections.values().any(|live| live == *address)
            })
            .cloned()
            .collect();
        remove_kademlia_addresses(kademlia, peer, &retired);
        for address in &next {
            kademlia.add_address(&peer, address.clone());
        }
        self.identify = next;
    }
}

fn remove_kademlia_addresses(
    kademlia: &mut KademliaBehaviour<MemoryStore>,
    peer: libp2p::PeerId,
    removed: &[Multiaddr],
) {
    if removed.is_empty() {
        return;
    }
    // Kademlia can insert a dial endpoint without its peer ID, but remove_address only matches
    // qualified addresses. Rebuild this entry to remove both forms and normalize the survivors.
    if let Some(entry) = kademlia.remove_peer(&peer) {
        for address in entry.node.value.into_vec() {
            let address = strip_peer_id(address).with(Protocol::P2p(peer));
            if !removed.contains(&address) {
                kademlia.add_address(&peer, address);
            }
        }
    }
}

fn prune_peer_addresses(
    peers: &mut HashMap<libp2p::PeerId, PeerAddresses>,
    kademlia: &mut KademliaBehaviour<MemoryStore>,
) {
    peers.retain(|peer, addresses| {
        if !addresses.connections.is_empty()
            || kademlia
                .kbucket(*peer)
                .is_some_and(|bucket| bucket.iter().any(|entry| entry.node.key.preimage() == peer))
        {
            return true;
        }
        // A disconnected peer without a routing entry needs no tracking. Remove any pending
        // insertion as well, so it cannot later retain addresses whose ownership we forgot.
        kademlia.remove_peer(peer);
        false
    });
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfiguredPeer {
    peer_id: Option<libp2p::PeerId>,
    address: Multiaddr,
    identity_pinned: bool,
    /// Whether `peer_id` comes from the configuration or from an admitted connection of the
    /// configured address, not from a rebind after a mismatch at another address.
    identity_trusted: bool,
    /// The concrete address of the last outbound connection to the trusted identity, such as the
    /// address that a `/dnsaddr` resolved to.
    fallback: Option<Multiaddr>,
}

impl ConfiguredPeer {
    fn from_address(address: Multiaddr) -> Self {
        let peer_id = match address.iter().last() {
            Some(Protocol::P2p(peer_id)) => Some(peer_id),
            _ => None,
        };
        Self {
            peer_id,
            address: strip_peer_id(address),
            identity_pinned: peer_id.is_some(),
            identity_trusted: peer_id.is_some(),
            fallback: None,
        }
    }

    fn matches_endpoint(&self, peer_id: &libp2p::PeerId, address: &Multiaddr) -> bool {
        self.peer_id == Some(*peer_id)
            && (self.address == *address
                || matches!(self.address.iter().next(), Some(Protocol::Dnsaddr(_))))
    }
}

/// Update an unpinned bootstrap identity after a key rotation.
///
/// Return `false` when the configuration explicitly pins the old identity. The
/// caller must then reject the replacement instead of trusting the endpoint.
fn rebind_configured_peer(
    configured: &mut [ConfiguredPeer],
    expected: &libp2p::PeerId,
    obtained: libp2p::PeerId,
    address: &Multiaddr,
) -> bool {
    let matching = configured
        .iter()
        .filter(|peer| peer.matches_endpoint(expected, address));
    if matching.clone().any(|peer| peer.identity_pinned) {
        return false;
    }
    for configured_peer in configured
        .iter_mut()
        .filter(|peer| peer.matches_endpoint(expected, address))
    {
        configured_peer.peer_id = Some(obtained);
        configured_peer.identity_trusted = false;
        configured_peer.fallback = None;
    }
    true
}

fn is_unspecified_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_unspecified(),
        Protocol::Ip6(ip) => ip.is_unspecified(),
        _ => false,
    })
}

fn is_redundant_peer_connection_denial(error: &ListenError) -> bool {
    let ListenError::Denied { cause } = error else {
        return false;
    };
    let mut current: &(dyn std::error::Error + 'static) = cause;
    loop {
        if let Some(exceeded) = current.downcast_ref::<connection_limits::Exceeded>() {
            // libp2p-connection-limits 0.6.0 keeps the limit kind private. Cargo.lock pins this
            // dependency, and the regression test verifies its per-peer display text.
            return exceeded
                .to_string()
                .contains(LIBP2P_ESTABLISHED_PER_PEER_LIMIT_TEXT);
        }
        let Some(source) = current.source() else {
            return false;
        };
        current = source;
    }
}

#[derive(NetworkBehaviour)]
pub struct NodeBehaviour {
    /// First, so it holds back a dial before the other behaviours prepare it.
    gossip_health: GossipSubscriptionHealth,
    gossipsub: GossipBehaviour,
    kademlia: KademliaBehaviour<MemoryStore>,
    connection_limits: connection_limits::Behaviour,
    identify: IdentifyBehaviour,
    /// Send bytes reply with enumeration for errors
    request_response: cbor::Behaviour<Vec<u8>, ProtocolResponse>,
}

/// Manage the peer to peer connection. This struct wraps a libp2p Swarm and enables communication
/// with it using channels.
pub struct Libp2pNetInterface {
    /// The Libp2p Swarm instance
    swarm: Swarm<NodeBehaviour>,
    /// A list of peers to automatically dial
    peers: Vec<String>,
    /// The UDP port that the peer listens to over QUIC
    udp_port: Option<u16>,
    /// The gossipsub topic that the peer should listen on
    topic: gossipsub::IdentTopic,
    /// Routes NetEvents to the raw and application channels.
    event_tx: NetEventSender,
    /// Transmission channel to send NetCommands to the Libp2pNetInterface
    cmd_tx: mpsc::Sender<NetCommand>,
    /// Local receiver to process NetCommands from
    cmd_rx: mpsc::Receiver<NetCommand>,
    /// Live operational connection state exposed to node operators.
    status: NetworkStatus,
    /// Immutable identity and deployment policy for this process.
    network: NetworkPolicy,
    /// The concrete addresses of recent successful dials, recorded below the DNS layer.
    recent_dials: RecentDials,
}

impl Libp2pNetInterface {
    pub fn new(
        id: Libp2pKeypair,
        peers: Vec<String>,
        udp_port: Option<u16>,
        network: NetworkPolicy,
    ) -> Result<Self> {
        Self::new_with_application_event_capacity(
            id,
            peers,
            udp_port,
            network,
            crate::DEFAULT_MAX_BUFFERED_NET_EVENTS,
        )
    }

    pub(crate) fn new_with_application_event_capacity(
        id: Libp2pKeypair,
        peers: Vec<String>,
        udp_port: Option<u16>,
        network: NetworkPolicy,
        application_event_capacity: usize,
    ) -> Result<Self> {
        if application_event_capacity == 0 {
            bail!("application event channel capacity must be greater than zero");
        }
        let event_tx = NetEventSender::new(EVENT_CHANNEL_SIZE, application_event_capacity);
        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_SIZE);
        let status = NetworkStatus::new(peers.len());

        let recent_dials = RecentDials::default();
        let swarm = libp2p::SwarmBuilder::with_existing_identity(id.into_keypair())
            .with_tokio()
            // QUIC under the dial guard, which sits below the DNS layer so it also sees the
            // addresses that a `/dnsaddr` resolves to.
            .with_other_transport(|key| {
                DialGuard::new(
                    libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(key)),
                    recent_dials.clone(),
                )
            })?
            .with_dns()
            .map_err(|e| anyhow::anyhow!("Failed to enable DNS: {e}"))?
            .with_behaviour(|key| create_behaviour(key, &network))?
            .build();

        let topic = gossipsub::IdentTopic::new(network.protocols().gossip_topic());

        Ok(Self {
            swarm,
            peers,
            udp_port,
            topic,
            event_tx,
            cmd_tx,
            cmd_rx,
            status,
            network,
            recent_dials,
        })
    }

    pub fn handle(&self) -> NetInterfaceHandle {
        NetInterfaceHandle::new(self.cmd_tx.clone(), &self.event_tx, self.status.clone())
    }

    pub async fn start(&mut self) -> Result<()> {
        let event_tx = self.event_tx.clone();
        let cmd_tx = self.cmd_tx.clone();
        let cmd_rx = &mut self.cmd_rx;
        let mut correlator = Correlator::new();
        let mut peer_failures = PeerConnectionFailures::new();
        let mut peer_admission = PeerAdmission::default();
        let mut peer_addresses = HashMap::<libp2p::PeerId, PeerAddresses>::new();
        let mut replicas = ReplicaLedger::new(DHT_REPLICA_LIMITS);
        let mut seen_gossip = GossipIngress::new();
        let mut admission_tick = tokio::time::interval(Duration::from_secs(5));
        admission_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut configured_peer_tick = tokio::time::interval(CONFIGURED_PEER_REDIAL_INTERVAL);
        configured_peer_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        configured_peer_tick.tick().await;
        let mut gossip_health_tick = tokio::time::interval(GOSSIP_HEALTH_INTERVAL);
        gossip_health_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        gossip_health_tick.tick().await;
        let mut dht_expiry_tick = tokio::time::interval(DHT_EXPIRY_INTERVAL);
        dht_expiry_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        dht_expiry_tick.tick().await;
        let mut dht_put_summary_tick = tokio::time::interval(DHT_PUT_SUMMARY_INTERVAL);
        dht_put_summary_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        dht_put_summary_tick.tick().await;
        let mut dht_put_deadline_tick = tokio::time::interval(DHT_PUT_DEADLINE_INTERVAL);
        dht_put_deadline_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        dht_put_deadline_tick.tick().await;
        let mut dht_puts = DhtPuts::default();
        let mut configured_peers: Vec<_> = self
            .peers
            .iter()
            .filter_map(|address| {
                let address: Multiaddr = address.parse().ok()?;
                Some(ConfiguredPeer::from_address(address))
            })
            .collect();
        // Limit repeated backpressure warnings.
        let mut last_backpressure_warn = Instant::now();

        info!(
            network = %self.network.profile().name(),
            network_id = %self.network.profile().id(),
            identify = %self.network.protocols().identify_protocol(),
            gossip = %self.network.protocols().gossip_topic(),
            kademlia = %self.network.protocols().kademlia_protocol(),
            sync = ?self.network.protocols().sync_protocols(),
            "Starting the scoped Interfold P2P network"
        );

        // Subscribe to topic
        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&self.topic)?;

        // Listen on the quic port
        let addr = match self.udp_port {
            Some(port) => format!("/ip4/0.0.0.0/udp/{}/quic-v1", port),
            None => "/ip4/0.0.0.0/udp/0/quic-v1".to_string(),
        };

        trace!("Requesting node.listen_on('{}')", addr);
        self.swarm.listen_on(addr.parse()?)?;

        trace!("Peers to dial: {:?}", self.peers);
        if self.peers.is_empty() {
            info!("Found 0 peers to dial");
        } else {
            info!("Found {} peer(s) to dial:", self.peers.len());
            for peer in &self.peers {
                info!("  -> {}", peer);
            }
        }
        tokio::spawn({
            let event_tx = event_tx.clone();
            let cmd_tx = cmd_tx.clone();
            let peers = self.peers.clone();
            async move {
                let total = peers.len();
                let connected = dial_peers(&cmd_tx, &event_tx, &peers).await?;
                event_tx.send(NetEvent::AllPeersDialed { connected, total })?;
                anyhow::Ok(())
            }
        });

        loop {
            select! {
                biased;

                _ = admission_tick.tick() => {
                    reconcile_replicas(&mut self.swarm, &mut replicas);
                    for peer_id in peer_failures.quarantined_peers() {
                        self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
                    }
                    for (peer_id, pending_connections) in peer_admission.expired_pending() {
                        debug!(%peer_id, "Peer did not complete Identify before the admission deadline");
                        self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        for pending in pending_connections {
                            let _ = event_tx.send(NetEvent::PeerRejected {
                                connection_id: pending.connection_id,
                                kind: PeerRejectionKind::Transient,
                                reason: "peer did not complete Identify before the admission deadline".to_string(),
                            });
                        }
                    }
                    prune_peer_addresses(&mut peer_addresses, &mut self.swarm.behaviour_mut().kademlia);
                }
                _ = dht_expiry_tick.tick() => {
                    prune_expired_dht_records(&mut self.swarm);
                    reconcile_replicas(&mut self.swarm, &mut replicas);
                }
                _ = configured_peer_tick.tick() => {
                    redial_disconnected_configured_peers(
                        &mut self.swarm,
                        &configured_peers,
                        &mut peer_failures,
                        &peer_admission,
                    );
                }
                _ = dht_put_deadline_tick.tick() => {
                    let (queries, steps) = dht_puts.expire(Instant::now());
                    end_dht_put_queries(&mut self.swarm.behaviour_mut().kademlia, queries);
                    for step in steps {
                        if let Err(e) = apply_dht_put_step(&mut self.swarm, &event_tx, &mut dht_puts, step) {
                            error!("Error ending an expired DHT put: {e}");
                        }
                    }
                }
                _ = dht_put_summary_tick.tick() => {
                    if let Some((stored, failed)) = dht_puts.take_summary() {
                        info!(
                            stored,
                            failed,
                            interval_seconds = DHT_PUT_SUMMARY_INTERVAL.as_secs(),
                            "DHT document uploads finished"
                        );
                    }
                }
                _ = gossip_health_tick.tick() => {
                    reconcile_gossip_subscriptions(
                        &mut self.swarm,
                        &peer_admission,
                        &self.topic,
                        &self.status,
                    );
                }
                // Process commands
                Some(command) = cmd_rx.recv() => {
                    if let NetCommand::Shutdown = command {
                        if let Err(e) = handle_shutdown(&mut self.swarm).await {
                            error!("Error processing NetCommand: {e}");
                        }
                        break;
                    }

                    if let NetCommand::ConfiguredPeerAdmitted { address, peer_id } = command {
                        admit_configured_peer(
                            &mut configured_peers,
                            address,
                            peer_id,
                            &self.recent_dials,
                        );
                        continue;
                    }

                    if let Err(e) = process_swarm_command(
                        &mut self.swarm,
                        &event_tx,
                        &mut correlator,
                        &mut dht_puts,
                        &mut replicas,
                        &peer_admission,
                        &self.network,
                        command,
                    ).await {
                        error!("Error processing NetCommand: {e}")
                    }
                }
                // Process events
                event = self.swarm.select_next_some() =>  {
                    match process_swarm_event(
                        &mut self.swarm,
                        &event_tx,
                        &cmd_tx,
                        &mut correlator,
                        &mut peer_failures,
                        &mut peer_admission,
                        &mut peer_addresses,
                        &mut configured_peers,
                        &mut replicas,
                        &mut seen_gossip,
                        &mut dht_puts,
                        &self.network,
                        &self.recent_dials,
                        &self.status,
                        event,
                    ).await {
                        Ok(_) => (),
                        Err(e) => error!("Error processing NetEvent: {e}")
                    }
                    let queued = event_tx.len();
                    if queued > EVENT_CHANNEL_SIZE * 3 / 4
                        && last_backpressure_warn.elapsed() > Duration::from_secs(10)
                    {
                        warn!("Event broadcast channel backpressure: {queued}/{EVENT_CHANNEL_SIZE} queued");
                        last_backpressure_warn = Instant::now();
                    }
                }

            }
        }

        info!("Event loop exited");
        Ok(())
    }
}

fn reconcile_gossip_subscriptions(
    swarm: &mut Swarm<NodeBehaviour>,
    admission: &PeerAdmission,
    topic: &gossipsub::IdentTopic,
    status: &NetworkStatus,
) {
    let topic_hash = topic.hash();
    let subscribed: HashSet<_> = swarm
        .behaviour()
        .gossipsub
        .all_peers()
        .filter(|(peer, topics)| admission.is_admitted(peer) && topics.contains(&&topic_hash))
        .map(|(peer, _)| *peer)
        .collect();
    status.gossip_peers(subscribed.len());

    let connected: HashSet<_> = swarm
        .connected_peers()
        .filter(|peer| admission.is_admitted(peer))
        .copied()
        .collect();
    let now = Instant::now();
    let stale = swarm
        .behaviour_mut()
        .gossip_health
        .stale_peers(&connected, &subscribed, now);
    for peer in stale {
        if swarm.disconnect_peer_id(peer).is_err() {
            continue;
        }
        // As for a quarantined peer, so it is not an initial candidate of new DHT queries. A query
        // can still choose it from another peer's answer; the backoff refuses that dial.
        let behaviour = swarm.behaviour_mut();
        behaviour.kademlia.remove_peer(&peer);
        let redial_delay = behaviour.gossip_health.disconnected_unsubscribed(peer, now);
        warn!(
            %peer,
            grace_seconds = GOSSIP_SUBSCRIPTION_GRACE.as_secs(),
            redial_after_seconds = redial_delay.as_secs(),
            "Disconnected a peer that did not establish the gossip subscription"
        );
    }
}

/// The addresses of one configured-peer redial: the configured address, and its fallback. A
/// configured `/dnsaddr` goes through the resolver that libp2p built from the system configuration
/// when the node started. The fallback reaches the peer without DNS. libp2p dials both at once.
fn redial_addresses(configured_peer: &ConfiguredPeer) -> Vec<Multiaddr> {
    let mut addresses = vec![configured_peer.address.clone()];
    addresses.extend(configured_peer.fallback.clone());
    addresses
}

/// Record that a configured address produced an admitted connection to `peer_id`. That identity
/// is trusted, and the concrete address of the dial becomes the peer's fallback.
fn admit_configured_peer(
    configured: &mut [ConfiguredPeer],
    address: Multiaddr,
    peer_id: libp2p::PeerId,
    recent_dials: &RecentDials,
) {
    let address = strip_peer_id(address);
    for configured_peer in configured.iter_mut() {
        if configured_peer.address == address
            && (!configured_peer.identity_pinned || configured_peer.peer_id == Some(peer_id))
        {
            configured_peer.peer_id = Some(peer_id);
            configured_peer.identity_trusted = true;
        }
    }
    refresh_configured_fallbacks(configured, &peer_id, recent_dials);
}

/// After an outbound connection to `peer_id`, make the concrete address of its dial the fallback of
/// each configured peer that trusts that identity. An identity that a rebind set is not trusted, so
/// an identity that another peer's routing data supplied never gets a fallback.
fn refresh_configured_fallbacks(
    configured: &mut [ConfiguredPeer],
    peer_id: &libp2p::PeerId,
    recent_dials: &RecentDials,
) {
    let Some(concrete) = recent_dials.get(peer_id) else {
        return;
    };
    for configured_peer in configured.iter_mut().filter(|configured_peer| {
        configured_peer.identity_trusted && configured_peer.peer_id == Some(*peer_id)
    }) {
        if concrete != configured_peer.address {
            configured_peer.fallback = Some(concrete.clone());
        }
    }
}

fn redial_disconnected_configured_peers(
    swarm: &mut Swarm<NodeBehaviour>,
    configured: &[ConfiguredPeer],
    failures: &mut PeerConnectionFailures,
    admission: &PeerAdmission,
) {
    let now = Instant::now();
    for configured_peer in configured {
        let Some(peer_id) = configured_peer.peer_id else {
            continue;
        };
        if peer_id == *swarm.local_peer_id()
            || swarm.is_connected(&peer_id)
            || failures.is_identity_quarantined(&peer_id)
            || admission.is_rejected(&peer_id)
            // The dial gate refuses a dial during the backoff, so do not try it every tick.
            || !swarm.behaviour().gossip_health.may_redial(&peer_id, now)
        {
            continue;
        }
        let options = DialOpts::peer_id(peer_id)
            .addresses(redial_addresses(configured_peer))
            .build();
        match swarm.dial(options) {
            Ok(()) => debug!(
                %peer_id,
                address = %configured_peer.address,
                "Redialing a disconnected configured peer"
            ),
            Err(DialError::DialPeerConditionFalse(_)) => {}
            Err(error) => debug!(
                %peer_id,
                address = %configured_peer.address,
                %error,
                "Configured peer redial skipped"
            ),
        }
    }
}

/// Create the libp2p behaviour
fn create_behaviour(
    key: &Keypair,
    network: &NetworkPolicy,
) -> std::result::Result<NodeBehaviour, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let peer_id = key.public().to_peer_id();
    let connection_limits = connection_limits::Behaviour::new(
        ConnectionLimits::default()
            .with_max_pending_incoming(Some(64))
            .with_max_pending_outgoing(Some(64))
            .with_max_established_incoming(Some(80))
            .with_max_established_outgoing(Some(64))
            .with_max_established_per_peer(Some(2))
            .with_max_established(Some(128)),
    );
    let identify = IdentifyBehaviour::new(
        IdentifyConfig::new(network.protocols().identify_protocol().into(), key.public())
            .with_agent_version(format!(
                "interfold-ciphernode/{}",
                env!("CARGO_PKG_VERSION")
            ))
            .with_interval(Duration::from_secs(60))
            .with_cache_size(0),
    );

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(GOSSIP_HEARTBEAT)
        .max_transmit_size(MAX_GOSSIP_BYTES)
        .validation_mode(gossipsub::ValidationMode::Strict)
        .validate_messages()
        .message_id_fn(|message| gossipsub::MessageId::from(Sha256::digest(&message.data).to_vec()))
        .build()
        .map_err(Error::other)?;

    let topic = gossipsub::IdentTopic::new(network.protocols().gossip_topic());
    let filter = gossipsub::WhitelistSubscriptionFilter(HashSet::from([topic.hash()]));
    let mut gossipsub = GossipBehaviour::new_with_subscription_filter(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub_config,
        filter,
    )?;
    let mut score_params = gossipsub::PeerScoreParams::default();
    let topic_score = gossipsub::TopicScoreParams {
        time_in_mesh_quantum: Duration::from_secs(1),
        time_in_mesh_cap: 10.0,
        first_message_deliveries_cap: 100.0,
        mesh_message_deliveries_weight: 0.0,
        mesh_failure_penalty_weight: 0.0,
        invalid_message_deliveries_weight: -10.0,
        ..Default::default()
    };
    score_params.topics.insert(topic.hash(), topic_score);
    gossipsub
        .with_peer_score(score_params, gossipsub::PeerScoreThresholds::default())
        .map_err(Error::other)?;
    let request_response_config =
        request_response::Config::default().with_request_timeout(Duration::from_secs(30));

    let request_response = cbor::Behaviour::<Vec<u8>, ProtocolResponse>::new(
        network
            .protocols()
            .sync_protocols()
            .iter()
            .cloned()
            .map(|protocol| (protocol, ProtocolSupport::Full)),
        request_response_config,
    );
    let mut config = KademliaConfig::new(network.protocols().kademlia_protocol());
    // New routing-table entries come only from the filtered `add_address` calls for admitted
    // peers. Automatic inserts would store the dialed address of every connection, including
    // loopback addresses between nodes on one host, and FIND_NODE responses would pass those to
    // remote peers, which then dial themselves. Kademlia still adds a dialed address to an existing
    // entry; `RoutingUpdated` removes loopback addresses again.
    //
    // The library's record jobs are off. Each hour the replication job would put every stored record
    // that no peer put again since its last run to up to 20 peers; after a DKG ends, that includes
    // the other peers' DKG documents. The publication job would republish this node's records. The
    // document publisher refreshes its own documents instead.
    config
        .set_max_packet_size(MAX_KADEMLIA_PAYLOAD_BYTES)
        .set_query_timeout(DHT_QUERY_TIMEOUT)
        .set_substreams_timeout(DHT_SUBSTREAM_TIMEOUT)
        .set_record_filtering(StoreInserts::FilterBoth)
        .set_kbucket_inserts(kad::BucketInserts::Manual)
        .set_replication_interval(None)
        .set_publication_interval(None);
    let store = dht_store(peer_id);
    let mut kademlia = KademliaBehaviour::with_config(peer_id, store, config);
    kademlia.set_mode(Some(kad::Mode::Server));

    Ok(NodeBehaviour {
        gossip_health: GossipSubscriptionHealth::default(),
        gossipsub,
        kademlia,
        connection_limits,
        identify,
        request_response,
    })
}

/// Process all swarm events
#[allow(clippy::too_many_arguments)]
async fn process_swarm_event(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &NetEventSender,
    cmd_tx: &mpsc::Sender<NetCommand>,
    correlator: &mut Correlator,
    peer_failures: &mut PeerConnectionFailures,
    peer_admission: &mut PeerAdmission,
    peer_addresses: &mut HashMap<libp2p::PeerId, PeerAddresses>,
    configured_peers: &mut [ConfiguredPeer],
    replicas: &mut ReplicaLedger,
    seen_gossip: &mut GossipIngress,
    dht_puts: &mut DhtPuts,
    network: &NetworkPolicy,
    recent_dials: &RecentDials,
    status: &NetworkStatus,
    event: SwarmEvent<NodeBehaviourEvent>,
) -> Result<()> {
    match event {
        SwarmEvent::ConnectionEstablished {
            peer_id,
            endpoint,
            connection_id,
            num_established,
            ..
        } => {
            // The authenticated transport identity is necessary but not sufficient. Keep the
            // connection staged until Identify confirms the Interfold network and capabilities.
            let remote_addr = endpoint.get_remote_address().clone();
            if endpoint.is_dialer() {
                refresh_configured_fallbacks(configured_peers, &peer_id, recent_dials);
            }
            peer_addresses
                .entry(peer_id)
                .or_default()
                .connections
                .insert(
                    connection_id,
                    strip_peer_id(remote_addr.clone()).with(Protocol::P2p(peer_id)),
                );
            let direction = if endpoint.is_dialer() {
                "outbound"
            } else {
                "inbound"
            };
            if peer_admission.is_admitted(&peer_id) {
                peer_failures.connection_succeeded(&peer_id);
                status.connected(
                    peer_id.to_string(),
                    remote_addr.to_string(),
                    direction,
                    num_established.get(),
                );
                if !(should_filter_loopback(swarm, network) && is_loopback_addr(&remote_addr)) {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, remote_addr);
                }
                event_tx.send(NetEvent::ConnectionEstablished { connection_id })?;
                event_tx.send(NetEvent::ConfiguredDialAdmitted {
                    connection_id,
                    peer_id,
                })?;
            } else if let Err(kind) = peer_admission.stage(
                peer_id,
                PeerAdmission::pending(
                    connection_id,
                    remote_addr,
                    direction,
                    num_established.get(),
                ),
            ) {
                debug!(%peer_id, "Disconnecting a peer rejected during the admission TTL");
                let _ = swarm.disconnect_peer_id(peer_id);
                event_tx.send(NetEvent::PeerRejected {
                    connection_id,
                    kind,
                    reason: "peer is temporarily blocked by the network admission policy"
                        .to_string(),
                })?;
            }
        }

        SwarmEvent::OutgoingConnectionError {
            peer_id,
            error,
            connection_id,
        } => {
            status.record_error(format!("connection {connection_id}: {error}"));
            if let Some(ref failed_peer) = peer_id {
                if let DialError::WrongPeerId {
                    obtained,
                    ref address,
                } = error
                {
                    let remote_addr = address.clone();
                    if obtained == *swarm.local_peer_id() {
                        // Another peer advertised an address of ours (usually loopback) for
                        // `failed_peer`. Drop that address only; the peer itself is not at fault.
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .remove_address(failed_peer, &strip_peer_id(remote_addr.clone()));
                        debug!(
                            %failed_peer,
                            %remote_addr,
                            "Dialed this node through an address advertised for another peer; removed the address"
                        );
                        event_tx.send(NetEvent::OutgoingConnectionError {
                            connection_id,
                            error: Arc::new(error),
                        })?;
                        return Ok(());
                    }
                    let stale = strip_peer_id(remote_addr.clone());
                    let mut was_fallback = false;
                    for configured_peer in configured_peers.iter_mut() {
                        if configured_peer.peer_id == Some(*failed_peer)
                            && configured_peer.fallback.as_ref() == Some(&stale)
                        {
                            configured_peer.fallback = None;
                            was_fallback = true;
                        }
                    }
                    if was_fallback {
                        // Another node now answers at a configured peer's fallback, an address
                        // that this node kept. Drop the address only: the configured address still
                        // names the peer, so neither quarantine nor rebind it.
                        // remove_address adds /p2p/<peer> before it compares.
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .remove_address(failed_peer, &stale);
                        debug!(
                            %failed_peer,
                            %remote_addr,
                            %obtained,
                            "Another node answers at the fallback of a configured peer; dropped it"
                        );
                        event_tx.send(NetEvent::OutgoingConnectionError {
                            connection_id,
                            error: Arc::new(error),
                        })?;
                        return Ok(());
                    }
                    let mismatch_count =
                        peer_failures.identity_mismatch.record_failure(failed_peer);
                    peer_failures.quarantine_identity(failed_peer);
                    if mismatch_count == 1 {
                        info!(
                            "Peer ID mismatch at {remote_addr}: expected {failed_peer}, got {obtained} — \
                             removing the stale routing entry"
                        );
                    } else {
                        debug!(
                            "Peer ID mismatch at {remote_addr}: expected {failed_peer}, got {obtained} \
                             (seen {mismatch_count} times) — stale entry re-learned from the network"
                        );
                    }
                    let local_peer = *swarm.local_peer_id();
                    swarm.behaviour_mut().kademlia.remove_peer(failed_peer);
                    if obtained != local_peer {
                        let corrected_addr = strip_peer_id(remote_addr.clone());
                        let can_rebind = rebind_configured_peer(
                            configured_peers,
                            failed_peer,
                            obtained,
                            &corrected_addr,
                        );

                        if can_rebind {
                            let opts = DialOpts::peer_id(obtained)
                                .addresses(vec![corrected_addr])
                                .build();
                            if let Err(e) = swarm.dial(opts) {
                                debug!(
                                    "Redial of {obtained} after peer ID replacement skipped: {e}"
                                );
                            }
                        } else {
                            warn!(
                                %remote_addr,
                                expected = %failed_peer,
                                %obtained,
                                "Rejected a configured peer whose pinned identity changed"
                            );
                        }
                    }
                } else {
                    match peer_failures.record_dial_failure(failed_peer) {
                        None => {
                            debug!(%failed_peer, %error, "Dial failed while the peer is quarantined");
                        }
                        Some(count) if count >= MAX_CONSECUTIVE_DIAL_FAILURES => {
                            info!(
                                cooldown_secs = STALE_PEER_COOLDOWN.as_secs(),
                                "Evicting unreachable peer {failed_peer} after {count} consecutive failures"
                            );
                            swarm.behaviour_mut().kademlia.remove_peer(failed_peer);
                            peer_failures.quarantine(failed_peer);
                        }
                        Some(count) => {
                            debug!(
                                "Dial failure for {failed_peer} (attempt {count}/{MAX_CONSECUTIVE_DIAL_FAILURES}): {error}"
                            );
                        }
                    }
                }
            } else {
                debug!("Failed to dial a peer without a known identity: {error}");
            }

            event_tx.send(NetEvent::OutgoingConnectionError {
                connection_id,
                error: Arc::new(error),
            })?;
        }

        SwarmEvent::IncomingConnectionError { error, .. } => {
            let is_redundant_connection = is_redundant_peer_connection_denial(&error);
            let error_str = format!("{:#}", anyhow::Error::from(error));
            // Downgrade benign handshake failures to debug:
            // - "Local peer ID": self-dial attempt
            // - "aborted by peer": simultaneous connection dedup (both sides dialed,
            //   libp2p keeps one connection and the other side aborts the handshake)
            // - per-peer connection-limit denial: an existing peer opened a redundant connection
            if is_redundant_connection
                || error_str.contains("Local peer ID")
                || error_str.contains("aborted by peer")
            {
                debug!("{}", error_str);
            } else {
                status.record_error(format!("incoming connection: {error_str}"));
                warn!("Incoming connection error: {}", error_str);
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Kademlia(kad::Event::RoutingUpdated {
            peer,
            addresses,
            ..
        })) => {
            if peer_failures.is_quarantined(&peer) {
                swarm.behaviour_mut().kademlia.remove_peer(&peer);
                debug!(%peer, "Ignored a quarantined Kademlia routing update");
            } else if should_filter_loopback(swarm, network) {
                // Kademlia adds a dialed address to an existing entry without the filter that
                // `add_address` applies. Remote peers would receive a loopback address in
                // FIND_NODE responses and dial themselves.
                for address in addresses.iter().filter(|address| is_loopback_addr(address)) {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .remove_address(&peer, address);
                    debug!(%peer, %address, "Removed a loopback address from the routing table");
                }
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Kademlia(kad::Event::InboundRequest {
            request:
                InboundRequest::PutRecord {
                    source,
                    record: Some(record),
                    ..
                },
        })) => {
            if !peer_admission.is_admitted(&source) {
                debug!(%source, "Rejected an inbound DHT record from an unadmitted peer");
                return Ok(());
            }
            let local_peer_id = *swarm.local_peer_id();
            let store = swarm.behaviour_mut().kademlia.store_mut();
            if let Err(reason) = admit_replica(
                store,
                replicas,
                DHT_MAX_RECORDS,
                local_peer_id,
                source,
                record,
                Instant::now(),
            ) {
                debug!(%source, reason, "Rejected an inbound DHT record");
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Kademlia(kad::Event::InboundRequest {
            request: InboundRequest::AddProvider { .. },
        })) => {
            // Interfold does not use provider records. FilterBoth prevents remote peers from
            // consuming the provider-record budget.
        }

        // The lookup that checks a put. Only another peer's copy of the record counts; this node's
        // own copy and a different record are ignored, and the query runs on.
        SwarmEvent::Behaviour(NodeBehaviourEvent::Kademlia(
            kad::Event::OutboundQueryProgressed {
                id,
                result: QueryResult::GetRecord(result),
                step,
                ..
            },
        )) if dht_puts.owns(&id) => {
            handle_put_check(swarm, event_tx, dht_puts, id, &result, step.last)?;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Kademlia(
            kad::Event::OutboundQueryProgressed {
                id,
                result: QueryResult::GetRecord(result),
                step,
                ..
            },
        )) => match result {
            Ok(GetRecordOk::FoundRecord(record)) => {
                // Kademlia passes on whatever record a peer returns. A peer can answer with a
                // different, self-consistent document, so only the requested key is accepted, and
                // the query keeps running for the other peers' answers.
                let requested = swarm.behaviour().kademlia.query(&id).is_some_and(|query| {
                    matches!(
                        query.info(),
                        kad::QueryInfo::GetRecord { key, .. } if *key == record.record.key
                    )
                });
                if !requested {
                    debug!(peer = ?record.peer, "Ignored a DHT record for a key that was not requested");
                    return Ok(());
                }
                let key = ContentHash(record.record.key.to_vec());
                let record_bytes = record.record.value;
                let check_key = ContentHash::from_content(&record_bytes);
                if check_key != key {
                    // Perhaps we do something else here too? maybe this logic should be handled upstream? Not sure...
                    return Err(anyhow::anyhow!(format!(
                        "Received record from peer {:?} but record was invalid ignoring.",
                        record.peer
                    )));
                }
                // As soon as we have a valid record we cancel the query because the record will be large and we can validate the value by hashing the content.
                if let Some(mut query) = swarm.behaviour_mut().kademlia.query_mut(&id) {
                    query.finish();
                }
                let cid = correlator.expire(id)?;
                debug!("Received valid DHT record for key={:?} cid={}", key, cid);
                event_tx.send(NetEvent::DhtGetRecordSucceeded {
                    key,
                    correlation_id: cid,
                    value: ArcBytes::from_bytes(&record_bytes),
                })?;
            }
            Ok(GetRecordOk::FinishedWithNoAdditionalRecord {
                cache_candidates: c,
            }) => {
                trace!("Finished cache={:?} step={:?}", c, step);
            }
            Err(e) => {
                error!("DHT get record failed: step={:?} error={}", step, e);
                event_tx.send(NetEvent::DhtGetRecordError {
                    correlation_id: correlator.expire(id)?,
                    error: e,
                })?;
            }
        },

        SwarmEvent::Behaviour(NodeBehaviourEvent::Kademlia(
            kad::Event::OutboundQueryProgressed {
                id,
                result: QueryResult::PutRecord(result),
                ..
            },
        )) => match dht_puts.upload_ended(id, result.map(|_| ())) {
            Some(next) => apply_dht_put_step(swarm, event_tx, dht_puts, next)?,
            // A put that this node cancelled, or that ended at its deadline.
            None => debug!(?id, "A DHT upload ended that no caller waits for"),
        },

        SwarmEvent::Behaviour(NodeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source: peer_id,
            message_id: id,
            message,
        })) => {
            trace!("Got message with id: {id} from peer: {peer_id}");
            if !peer_admission.is_admitted(&peer_id) {
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(
                        &id,
                        &peer_id,
                        gossipsub::MessageAcceptance::Ignore,
                    );
                debug!(%peer_id, %id, "Ignored gossip from a peer that has not passed Identify");
            } else {
                match seen_gossip.validate(
                    peer_id,
                    &id,
                    &message.data,
                    network,
                    Instant::now(),
                    chrono::Utc::now(),
                ) {
                    Ok(Some(gossip_data)) => {
                        swarm
                            .behaviour_mut()
                            .gossipsub
                            .report_message_validation_result(
                                &id,
                                &peer_id,
                                gossipsub::MessageAcceptance::Accept,
                            );
                        let event = match gossip_data {
                            GossipData::DocumentPublishedNotification(notification) => {
                                NetEvent::DocumentIngress(Box::new(
                                    crate::events::DocumentIngress {
                                        propagation_source: Some(peer_id),
                                        notification,
                                    },
                                ))
                            }
                            data => NetEvent::GossipIngress {
                                propagation_source: peer_id,
                                data,
                            },
                        };
                        event_tx.send(event)?;
                    }
                    Ok(None) => {
                        swarm
                            .behaviour_mut()
                            .gossipsub
                            .report_message_validation_result(
                                &id,
                                &peer_id,
                                gossipsub::MessageAcceptance::Ignore,
                            );
                        trace!(%peer_id, %id, "Ignored duplicate or expired gossip");
                    }
                    Err(error) => {
                        swarm
                            .behaviour_mut()
                            .gossipsub
                            .report_message_validation_result(
                                &id,
                                &peer_id,
                                gossipsub::MessageAcceptance::Reject,
                            );
                        debug!(%peer_id, %id, %error, "Rejected invalid gossip message");
                    }
                }
            }
        }

        SwarmEvent::NewListenAddr { address, .. } => {
            status.listening_on(address.to_string());
            trace!("Local node is listening on {address}");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed {
            peer_id,
            topic,
        })) => {
            if !peer_admission.is_admitted(&peer_id) {
                debug!(%peer_id, %topic, "Ignoring a subscription before peer admission");
                return Ok(());
            }
            debug!("Peer {} subscribed to {}", peer_id, topic);
            if topic == gossipsub::IdentTopic::new(network.protocols().gossip_topic()).hash() {
                swarm.behaviour_mut().gossip_health.subscribed(&peer_id);
            }
            let count = swarm
                .behaviour()
                .gossipsub
                .mesh_peers(&topic)
                .filter(|peer| peer_admission.is_admitted(peer))
                .count();
            event_tx.send(NetEvent::GossipSubscribed { count, topic })?;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::RequestResponse(
            RequestResponseEvent::Message {
                peer,
                connection_id,
                message:
                    RequestResponseMessage::Request {
                        request,
                        channel,
                        request_id,
                    },
            },
        )) => {
            if !peer_admission.is_admitted(&peer) {
                debug!(%peer, "Ignoring a historical-sync request from a peer that has not passed Identify");
                return Ok(());
            }
            debug!(
                "Incoming request received (peer={}, connection={}, id={})",
                peer, connection_id, request_id
            );
            let responder = DirectResponder::new(request_id, ChannelType::Channel(channel), cmd_tx)
                .with_request(request);

            // received a request for events
            event_tx.send(NetEvent::IncomingRequest(IncomingRequest {
                peer,
                responder,
            }))?;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::RequestResponse(
            RequestResponseEvent::Message {
                message:
                    RequestResponseMessage::Response {
                        request_id,
                        response,
                        ..
                    },
                ..
            },
        )) => {
            debug!("Response received (id={request_id})");
            let correlation_id = correlator.expire(request_id)?;
            debug!("Correlated response: {correlation_id}");
            event_tx.send(NetEvent::OutgoingRequestSucceeded(
                OutgoingRequestSucceeded {
                    payload: response,
                    correlation_id,
                },
            ))?;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::RequestResponse(
            RequestResponseEvent::OutboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            },
        )) => {
            warn!(
                "Outbound request failed: peer={}, connection={}, id={}, error={:?}",
                peer, connection_id, request_id, error
            );
            let correlation_id = correlator.expire(request_id)?;
            event_tx.send(NetEvent::OutgoingRequestFailed(OutgoingRequestFailed {
                correlation_id,
                error: format!("Outbound request failed: {:?}", error),
            }))?;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::RequestResponse(
            RequestResponseEvent::InboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            },
        )) => {
            // ConnectionClosed is routine during peer churn (the connection closes while
            // a request is in flight; the remote side retries against another peer). The
            // other variants point at local faults: a dropped ResponseChannel, a protocol
            // mismatch, an I/O error, or a handler too slow to respond.
            if matches!(error, request_response::InboundFailure::ConnectionClosed) {
                debug!(
                    "Inbound request failed: peer={}, connection={}, id={}, error={:?}",
                    peer, connection_id, request_id, error
                );
            } else {
                warn!(
                    "Inbound request failed: peer={}, connection={}, id={}, error={:?}",
                    peer, connection_id, request_id, error
                );
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::RequestResponse(
            RequestResponseEvent::ResponseSent {
                peer,
                connection_id,
                request_id,
            },
        )) => {
            debug!(
                "Response sent to peer={}, connection={}, id={}",
                peer, connection_id, request_id
            );
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Identify(
            libp2p::identify::Event::Received {
                connection_id,
                peer_id,
                info,
            },
        )) => {
            if let Err(reason) = network.protocols().supports_peer(&info) {
                let rejected_connections = peer_admission.pending_connections(&peer_id);
                let first_rejection = peer_admission.reject(peer_id, PeerRejectionKind::Permanent);
                swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
                status.disconnected(&peer_id.to_string(), 0);
                let _ = swarm.disconnect_peer_id(peer_id);
                if first_rejection {
                    info!(
                        %peer_id,
                        peer_protocol = %info.protocol_version,
                        peer_agent = %info.agent_version,
                        %reason,
                        "Rejected an incompatible Interfold peer"
                    );
                } else {
                    debug!(%peer_id, %reason, "Rejected an incompatible peer again");
                }
                if rejected_connections.is_empty() {
                    event_tx.send(NetEvent::PeerRejected {
                        connection_id,
                        kind: PeerRejectionKind::Permanent,
                        reason: reason.to_string(),
                    })?;
                } else {
                    for pending in rejected_connections {
                        event_tx.send(NetEvent::PeerRejected {
                            connection_id: pending.connection_id,
                            kind: PeerRejectionKind::Permanent,
                            reason: reason.to_string(),
                        })?;
                    }
                }
                return Ok(());
            }

            let pending_connections = peer_admission.admit(peer_id);
            if !peer_admission.is_admitted(&peer_id) {
                debug!(%peer_id, "Received Identify for an unstaged peer");
                return Ok(());
            }
            let filter = should_filter_loopback(swarm, network);
            peer_addresses.entry(peer_id).or_default().refresh(
                peer_id,
                info.listen_addrs,
                filter,
                &mut swarm.behaviour_mut().kademlia,
            );
            trace!(observed_address = %info.observed_addr, "Peer reported our observed address");
            let Some(pending_connections) = pending_connections else {
                return Ok(());
            };
            peer_failures.connection_succeeded(&peer_id);
            info!(
                %peer_id,
                peer_agent = %info.agent_version,
                network = %network.profile().name(),
                "Peer admitted"
            );
            let status_pending = pending_connections
                .iter()
                .max_by_key(|pending| pending.connections)
                .expect("admitted peers have at least one staged connection");
            status.connected(
                peer_id.to_string(),
                status_pending.remote_address.to_string(),
                status_pending.direction,
                status_pending.connections,
            );
            for pending in &pending_connections {
                if !(filter && is_loopback_addr(&pending.remote_address)) {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, strip_peer_id(pending.remote_address.clone()));
                }
            }
            let topic = gossipsub::IdentTopic::new(network.protocols().gossip_topic()).hash();
            // The subscribe event of a peer that subscribed before its admission was ignored.
            let subscribed_before_admission = swarm
                .behaviour()
                .gossipsub
                .all_peers()
                .any(|(peer, topics)| *peer == peer_id && topics.contains(&&topic));
            if subscribed_before_admission {
                swarm.behaviour_mut().gossip_health.subscribed(&peer_id);
            }
            let count = swarm
                .behaviour()
                .gossipsub
                .mesh_peers(&topic)
                .filter(|peer| peer_admission.is_admitted(peer))
                .count();
            event_tx.send(NetEvent::GossipSubscribed { count, topic })?;
            for pending in pending_connections {
                event_tx.send(NetEvent::ConnectionEstablished {
                    connection_id: pending.connection_id,
                })?;
                event_tx.send(NetEvent::ConfiguredDialAdmitted {
                    connection_id: pending.connection_id,
                    peer_id,
                })?;
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Identify(libp2p::identify::Event::Error {
            connection_id,
            peer_id,
            error,
        })) => {
            // A transient connection close can race with Identify, especially during peer-ID
            // replacement or simultaneous dialing. It is not compatibility evidence. Keep the
            // peer staged until another Identify response succeeds or the admission timer expires.
            debug!(%peer_id, %connection_id, %error, "Peer Identify exchange failed");
        }

        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            num_established,
            cause,
            ..
        } => {
            peer_admission.closed(&peer_id, connection_id, num_established);
            if let Some(addresses) = peer_addresses.get_mut(&peer_id) {
                if let Some(address) = addresses.connections.remove(&connection_id) {
                    if !addresses.identify.contains(&address)
                        && !addresses.connections.values().any(|live| live == &address)
                    {
                        remove_kademlia_addresses(
                            &mut swarm.behaviour_mut().kademlia,
                            peer_id,
                            &[address],
                        );
                    }
                }
            }
            prune_peer_addresses(peer_addresses, &mut swarm.behaviour_mut().kademlia);
            status.disconnected(&peer_id.to_string(), num_established);
            if num_established == 0 {
                let total = swarm.connected_peers().count();
                debug!("Peer disconnected: {peer_id} (total: {total}, cause: {cause:?})");
            }
        }

        SwarmEvent::ListenerClosed {
            addresses, reason, ..
        } => {
            status.stopped_listening(addresses.iter().map(ToString::to_string));
            status.record_error(format!("listener closed: {reason:?}"));
            warn!("Listener closed on {addresses:?}: {reason:?}");
        }

        SwarmEvent::ListenerError { error, .. } => {
            status.record_error(format!("listener error: {error}"));
            error!("Listener error: {error}");
        }

        unknown => {
            debug!("Unhandled swarm event: {:?}", unknown);
        }
    };
    Ok(())
}

/// Process all swarm commands except shutdown.
#[allow(clippy::too_many_arguments)]
async fn process_swarm_command(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &NetEventSender,
    correlator: &mut Correlator,
    dht_puts: &mut DhtPuts,
    replicas: &mut ReplicaLedger,
    peer_admission: &PeerAdmission,
    network: &NetworkPolicy,
    command: NetCommand,
) -> Result<()> {
    match command {
        NetCommand::GossipPublish {
            data,
            topic,
            correlation_id,
            delivery_id,
        } => {
            handle_gossip_publish(
                swarm,
                event_tx,
                network,
                data,
                topic,
                correlation_id,
                delivery_id,
            )?;
            Ok(())
        }
        NetCommand::Dial(env) => {
            let multi = env.take().context("Dial received without payload")?;
            handle_dial(swarm, event_tx, multi)?;
            Ok(())
        }
        NetCommand::DhtStoreLocal {
            correlation_id,
            key,
            expires,
            value,
        } => {
            handle_store_local(
                swarm,
                replicas,
                event_tx,
                correlation_id,
                key,
                expires,
                value,
            )?;
            Ok(())
        }
        NetCommand::DhtPutRecord {
            correlation_id,
            key,
            expires,
            value,
            deadline,
        } => {
            handle_put_record(
                swarm,
                event_tx,
                dht_puts,
                replicas,
                correlation_id,
                key,
                expires,
                value,
                deadline,
            )?;
            Ok(())
        }
        NetCommand::DhtCancelPut { key } => {
            let (queries, steps) = dht_puts.cancel(&key);
            end_dht_put_queries(&mut swarm.behaviour_mut().kademlia, queries);
            for step in steps {
                apply_dht_put_step(swarm, event_tx, dht_puts, step)?;
            }
            Ok(())
        }
        NetCommand::DhtGetRecord {
            correlation_id,
            key,
        } => {
            handle_get_record(swarm, correlator, correlation_id, key)?;
            Ok(())
        }
        NetCommand::DhtRemoveRecords { keys } => {
            handle_remove_records(swarm, replicas, keys);
            Ok(())
        }
        NetCommand::OutgoingRequest(OutgoingRequest {
            correlation_id,
            payload,
            target,
        }) => {
            if let Err(e) = handle_outgoing_request(
                swarm,
                correlator,
                peer_admission,
                correlation_id,
                payload,
                target,
            ) {
                event_tx.send(NetEvent::OutgoingRequestFailed(OutgoingRequestFailed {
                    correlation_id,
                    error: e.to_string(),
                }))?;
            };
            Ok(())
        }
        NetCommand::IncomingResponse(IncomingResponse { responder }) => {
            handle_response(swarm, responder)?;
            Ok(())
        }
        NetCommand::AdmittedPeers { correlation_id } => {
            let peers = swarm
                .connected_peers()
                .filter(|peer| peer_admission.is_admitted(peer))
                .copied()
                .collect();
            event_tx.send(NetEvent::AdmittedPeers {
                correlation_id,
                peers,
            })?;
            Ok(())
        }
        NetCommand::Shutdown | NetCommand::ConfiguredPeerAdmitted { .. } => {
            unreachable!("control commands must be handled in Libp2pNetInterface::start")
        }
    }
}

fn handle_gossip_publish(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &NetEventSender,
    network: &NetworkPolicy,
    data: GossipData,
    topic: String,
    correlation_id: CorrelationId,
    delivery_id: Option<[u8; 16]>,
) -> Result<()> {
    let bytes = match (|| -> Result<Vec<u8>> {
        anyhow::ensure!(
            topic == network.protocols().gossip_topic(),
            "refusing to publish on an unconfigured gossip topic"
        );
        encode_gossip(&data, network, delivery_id)
    })() {
        Ok(bytes) => bytes,
        Err(error) => {
            event_tx.send(NetEvent::GossipPublishError {
                correlation_id,
                error: Arc::new(GossipPublishFailure::permanent(error.to_string())),
            })?;
            return Ok(());
        }
    };
    debug!("Publishing gossip message ({} bytes)", bytes.len());
    let gossipsub_behaviour = &mut swarm.behaviour_mut().gossipsub;
    match gossipsub_behaviour.publish(gossipsub::IdentTopic::new(topic), bytes) {
        Ok(message_id) => {
            event_tx.send(NetEvent::GossipPublished {
                correlation_id,
                message_id,
            })?;
        }
        Err(e) => {
            error!(error=?e, "Could not GossipPublish.");
            event_tx.send(NetEvent::GossipPublishError {
                correlation_id,
                error: Arc::new(GossipPublishFailure::from_libp2p(e)),
            })?;
        }
    }
    Ok(())
}

fn handle_dial(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &NetEventSender,
    dial_opts: DialOpts,
) -> Result<()> {
    trace!("DIAL: {:?}", dial_opts);
    match swarm.dial(dial_opts) {
        Ok(v) => trace!("Dial returned {:?}", v),
        Err(error) => {
            // Expected outcomes of concurrent dials (already connected or dialing,
            // aborted, over a connection limit) stay at debug; the dialer logs one
            // warn-level summary for retryable peers. Anything else is a permanent
            // local configuration error and must stay visible.
            match &error {
                DialError::DialPeerConditionFalse(_)
                | DialError::Aborted
                | DialError::Denied { .. } => {
                    debug!("Dialing error! {}", error);
                }
                _ => warn!("Dialing error! {}", error),
            }
            event_tx.send(NetEvent::DialError {
                error: error.into(),
            })?;
        }
    }
    Ok(())
}

/// Remove specific DHT records by key.
///
/// Called when an E3 completes to free up local DHT store space.
/// Records on remote peers are left to expire naturally.
fn handle_remove_records(
    swarm: &mut Swarm<NodeBehaviour>,
    replicas: &mut ReplicaLedger,
    keys: Vec<ContentHash>,
) {
    let store = swarm.behaviour_mut().kademlia.store_mut();
    let mut removed = 0usize;
    for key in &keys {
        store.remove(&RecordKey::new(key));
        replicas.remove(key.as_ref());
        removed += 1;
    }
    if removed > 0 {
        info!(
            "DHT removed {} records for completed E3 ({} remaining)",
            removed,
            store.records().count()
        );
    }
}

/// Evict expired records from the DHT store.
///
/// `MemoryStore` does not check expiration on `put()` — it simply counts
/// all records, expired or not.  This helper removes stale entries so that
/// the `max_records` budget reflects only live data.
///
/// It runs every [`DHT_EXPIRY_INTERVAL`]; a write to a full store also prunes
/// ([`store_local_record`]). Records of a completed E3 are also removed by `handle_remove_records`.
fn prune_expired_dht_records(swarm: &mut Swarm<NodeBehaviour>) {
    let store = swarm.behaviour_mut().kademlia.store_mut();
    let pruned = prune_expired_records(store, Instant::now());
    if pruned > 0 {
        info!(
            "DHT pruned {} expired records ({} remaining)",
            pruned,
            store.records().count()
        );
    }
}

/// Remove the records that expired at `now` from a DHT store, and return how many were removed.
fn prune_expired_records(store: &mut MemoryStore, now: Instant) -> usize {
    let before = store.records().count();
    store.retain(|_, record| record.expires.is_none_or(|expires| expires > now));
    before - store.records().count()
}

/// Store a record in this node's own DHT store. A replica of the same key becomes this node's
/// record, and the ledger releases it. When the store is full, remove the expired records, and
/// then the oldest replica of the sender with the most, so this node's records always fit. Local
/// stores and puts both write through here.
fn store_local_record(
    store: &mut MemoryStore,
    replicas: &mut ReplicaLedger,
    record: Record,
    now: Instant,
) -> Result<(), kad::store::Error> {
    replicas.remove(record.key.as_ref());
    match store.put(record.clone()) {
        Err(kad::store::Error::MaxRecords) => {
            let pruned = prune_expired_records(store, now);
            reconcile_store_replicas(store, replicas, None);
            if let Err(kad::store::Error::MaxRecords) = store.put(record.clone()) {
                let Some(victim) = replicas.room_for_local() else {
                    return Err(kad::store::Error::MaxRecords);
                };
                store.remove(&RecordKey::from(victim.clone()));
                replicas.remove(&victim);
                warn!("DHT store full: removed {pruned} expired records and a replica");
                return store.put(record);
            }
            warn!("DHT store full: removed {pruned} expired records");
            Ok(())
        }
        result => result,
    }
}

/// This node's DHT store.
fn dht_store(peer_id: libp2p::PeerId) -> MemoryStore {
    MemoryStore::with_config(
        peer_id,
        MemoryStoreConfig {
            max_records: DHT_MAX_RECORDS,
            // The store refuses a value of this size or more, so the largest document fits.
            max_value_bytes: MAX_DHT_DOCUMENT_BYTES + 1,
            max_providers_per_key: DHT_MAX_PROVIDERS_PER_KEY,
            max_provided_keys: DHT_MAX_RECORDS,
        },
    )
}

/// Store an inbound replica from `source`, making room by evicting other replicas when a limit
/// is reached. A refresh of a held replica only extends its expiry; this node's own records are
/// never replaced. `max_records` is the store's record limit. Returns why the record was refused.
fn admit_replica(
    store: &mut MemoryStore,
    replicas: &mut ReplicaLedger,
    max_records: usize,
    local_peer_id: libp2p::PeerId,
    source: libp2p::PeerId,
    record: Record,
    now: Instant,
) -> Result<(), &'static str> {
    let valid_expiry = record
        .expires
        .is_some_and(|expires| expires > now && expires <= now + DHT_MAX_TTL);
    if !valid_expiry {
        return Err("invalid expiry");
    }
    if record.key.as_ref().len() != 32
        || ContentHash::from_content(&record.value).as_ref() != record.key.as_ref()
    {
        return Err("key does not match the content");
    }
    if record.value.len() > MAX_DHT_DOCUMENT_BYTES {
        return Err("record too large");
    }
    // A record that names this node as its publisher is not a replica: reconciliation would drop
    // it from the ledger and leave it in the store outside every replica limit.
    if record.publisher == Some(local_peer_id) {
        return Err("record claims this node as its publisher");
    }
    if let Some(existing) = store.get(&record.key) {
        // Remote puts cannot replace our records or shorten a replica's lifetime.
        if existing.publisher == Some(local_peer_id)
            || existing.expires.is_none()
            || existing.expires >= record.expires
        {
            return Ok(());
        }
        let refreshed = Record {
            expires: record.expires,
            ..existing.into_owned()
        };
        return store
            .put(refreshed)
            .map_err(|_| "store refused the refresh");
    }
    // The store does not hold the key, so a ledger entry for it is stale: Kademlia removed the
    // expired record during a lookup. The new replica gets its own owner and place.
    replicas.remove(record.key.as_ref());
    let bytes = record.value.len();
    let free = |store: &MemoryStore| max_records.saturating_sub(store.records().count());
    let mut victims = replicas.room_for(source, bytes, free(store));
    if victims.as_ref().is_none_or(|victims| !victims.is_empty()) {
        // Expired records give their room back before a live replica is evicted.
        prune_expired_records(store, now);
        reconcile_store_replicas(store, replicas, Some(local_peer_id));
        victims = replicas.room_for(source, bytes, free(store));
    }
    let victims = victims.ok_or("no room among the replicas")?;
    for victim in victims {
        store.remove(&RecordKey::from(victim.clone()));
        replicas.remove(&victim);
    }
    let key = record.key.to_vec();
    store.put(record).map_err(|_| "store refused the record")?;
    replicas.insert(key, source, bytes);
    Ok(())
}

/// Forget the replicas that the store no longer holds as replicas: removed, expired and removed by
/// Kademlia, or now this node's own record.
fn reconcile_replicas(swarm: &mut Swarm<NodeBehaviour>, replicas: &mut ReplicaLedger) {
    let local_peer_id = *swarm.local_peer_id();
    let store = swarm.behaviour_mut().kademlia.store_mut();
    reconcile_store_replicas(store, replicas, Some(local_peer_id));
}

fn reconcile_store_replicas(
    store: &MemoryStore,
    replicas: &mut ReplicaLedger,
    local_peer_id: Option<libp2p::PeerId>,
) {
    replicas.retain(|key| {
        store
            .get(&RecordKey::from(key.to_vec()))
            .is_some_and(|record| local_peer_id.is_none() || record.publisher != local_peer_id)
    });
}

/// Store a document in this node's own DHT store, as the publisher, without uploading it to other
/// peers. Peers that look its key up can then fetch it from this node, even when no upload has
/// succeeded yet.
fn handle_store_local(
    swarm: &mut Swarm<NodeBehaviour>,
    replicas: &mut ReplicaLedger,
    event_tx: &NetEventSender,
    correlation_id: CorrelationId,
    key: ContentHash,
    expires: Option<Instant>,
    value: ArcBytes,
) -> Result<()> {
    let record = Record {
        key: RecordKey::new(&key),
        value: value.extract_bytes(),
        publisher: Some(*swarm.local_peer_id()),
        expires,
    };
    let store = swarm.behaviour_mut().kademlia.store_mut();
    match store_local_record(store, replicas, record, Instant::now()) {
        Ok(()) => {
            debug!("DHT STORE LOCAL OK cid={}", correlation_id);
            event_tx.send(NetEvent::DhtStoreLocalSucceeded {
                key,
                correlation_id,
            })?;
        }
        Err(error) => {
            warn!("DHT local store failed: {error:?}");
            event_tx.send(NetEvent::DhtStoreLocalError {
                correlation_id,
                error,
            })?;
        }
    }
    Ok(())
}

/// A progress step of the lookup that checks a put. Only another peer's copy of the requested
/// record counts: this node's own copy, a record under another key, and a record whose content
/// does not hash to the key are ignored, and the query runs on. At the last step a put that no
/// peer served fails as not replicated.
fn handle_put_check(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &NetEventSender,
    dht_puts: &mut DhtPuts,
    id: kad::QueryId,
    result: &Result<GetRecordOk, kad::GetRecordError>,
    last: bool,
) -> Result<()> {
    if let Ok(GetRecordOk::FoundRecord(found)) = result {
        let served = found.peer.is_some()
            && dht_puts.checked_key(&id).is_some_and(|key| {
                found.record.key == RecordKey::new(key)
                    && ContentHash::from_content(&found.record.value) == *key
            });
        if served {
            if let Some(stored) = dht_puts.served_by_peer(&id) {
                if let Some(mut query) = swarm.behaviour_mut().kademlia.query_mut(&id) {
                    query.finish();
                }
                apply_dht_put_step(swarm, event_tx, dht_puts, stored)?;
            }
        }
    }
    if let Some(ended) = dht_puts.check_progressed(&id, last) {
        apply_dht_put_step(swarm, event_tx, dht_puts, ended)?;
    }
    Ok(())
}

/// Store a record and upload it to the peers closest to its key. The put is owned in `dht_puts`
/// until another peer serves the record back or it fails, and reports one result by `deadline`.
#[allow(clippy::too_many_arguments)]
fn handle_put_record(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &NetEventSender,
    dht_puts: &mut DhtPuts,
    replicas: &mut ReplicaLedger,
    correlation_id: CorrelationId,
    key: ContentHash,
    expires: Option<Instant>,
    value: ArcBytes,
    deadline: Instant,
) -> Result<()> {
    debug!("DHT PUT RECORD");
    if Instant::now() >= deadline {
        // The caller stops waiting before an upload could finish.
        let step = dht_puts.expired_before_start(correlation_id, key);
        return apply_dht_put_step(swarm, event_tx, dht_puts, step);
    }
    if !dht_puts.has_room() {
        warn!("DHT put refused: {MAX_DHT_PUTS} puts already run");
        event_tx.send(NetEvent::DhtPutRecordError {
            correlation_id,
            error: PutOrStoreError::Busy,
        })?;
        return Ok(());
    }
    let record = Record {
        key: RecordKey::new(&key),
        value: value.extract_bytes(),
        publisher: None, // Will be set automatically to local peer ID
        expires,
    };
    // put_record writes this node's store before its query. Writing the record first, through
    // the helper that makes room in a full store, lets put_record replace it instead of failing
    // on the record limit.
    let store = swarm.behaviour_mut().kademlia.store_mut();
    let result =
        store_local_record(store, replicas, record.clone(), Instant::now()).and_then(|()| {
            swarm
                .behaviour_mut()
                .kademlia
                // Quorum::Majority calculates quorum from the Kademlia routing table size,
                // not the actual cluster size. With a routing table of ~21 entries,
                // it required 11 peers to acknowledge the record, which is impossible
                // in a 4-node cluster.
                .put_record(record, Quorum::One)
        });
    match result {
        Ok(qid) => {
            dht_puts.start(correlation_id, key, qid, deadline);
            debug!("PUT RECORD OK qid={:?} cid={}", qid, correlation_id);
        }
        Err(error) => {
            warn!("DHT put failed: {error:?}");
            event_tx.send(NetEvent::DhtPutRecordError {
                correlation_id,
                error: PutOrStoreError::StoreError(error),
            })?;
        }
    }
    Ok(())
}

/// End the queries of puts that nobody waits for any more, so they release the record. A check
/// lookup ends at once. An upload ends only in its upload phase: ending its closest-peer lookup
/// would make Kademlia upload the record to the peers found so far, so such a put runs on to its
/// normal end and is ignored then. This is not a full cancel: requests that a query already gave to
/// the connection handlers still go out. Returns the queries that ended.
fn end_dht_put_queries(
    kademlia: &mut KademliaBehaviour<MemoryStore>,
    queries: Vec<EndedQuery>,
) -> Vec<kad::QueryId> {
    let mut finished = Vec::new();
    for EndedQuery { query, checking } in queries {
        let Some(mut running) = kademlia.query_mut(&query) else {
            continue;
        };
        let uploading = matches!(
            running.info(),
            kad::QueryInfo::PutRecord {
                phase: kad::PutRecordPhase::PutRecord { .. },
                ..
            }
        );
        if checking || uploading {
            running.finish();
            finished.push(query);
        }
    }
    finished
}

/// Carry out the next step of a put: start its check, or send its result to the caller. A
/// cancelled put is only logged at DEBUG.
fn apply_dht_put_step(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &NetEventSender,
    dht_puts: &mut DhtPuts,
    step: DhtPutStep,
) -> Result<()> {
    let (correlation_id, key, result) = match step {
        DhtPutStep::Check {
            correlation_id,
            key,
        } => {
            let query = swarm
                .behaviour_mut()
                .kademlia
                .get_record(RecordKey::new(&key));
            dht_puts.checking(correlation_id, query);
            return Ok(());
        }
        DhtPutStep::Report {
            correlation_id,
            key,
            result,
        } => (correlation_id, key, result),
    };
    let error = match result {
        DhtPutResult::Stored => {
            debug!("DHT put record stored by another peer: {:?}", key);
            event_tx.send(NetEvent::DhtPutRecordSucceeded {
                key,
                correlation_id,
            })?;
            return Ok(());
        }
        DhtPutResult::UploadFailed(error) => {
            error!("DHT put record failed: {}", error);
            PutOrStoreError::PutRecordError(error)
        }
        DhtPutResult::NotReplicated => {
            error!("DHT put record failed: no other peer serves {:?}", key);
            PutOrStoreError::NotReplicated
        }
        DhtPutResult::Expired => {
            warn!("DHT put record did not end by its deadline: {:?}", key);
            PutOrStoreError::Expired
        }
        DhtPutResult::Cancelled => {
            debug!("DHT put record cancelled: {:?}", key);
            PutOrStoreError::Cancelled
        }
    };
    event_tx.send(NetEvent::DhtPutRecordError {
        correlation_id,
        error,
    })?;
    Ok(())
}

fn handle_get_record(
    swarm: &mut Swarm<NodeBehaviour>,
    correlator: &mut Correlator,
    correlation_id: CorrelationId,
    key: ContentHash,
) -> Result<()> {
    let query_id = swarm
        .behaviour_mut()
        .kademlia
        .get_record(RecordKey::new(&key));

    // QueryId is returned synchronously and we immediately add it to the correlator so race conditions should not be an issue.
    correlator.track(query_id, correlation_id);
    debug!(
        "GET RECORD CORRELATED! query_id={:?} correlation_id={}",
        query_id, correlation_id
    );
    Ok(())
}

async fn handle_shutdown(swarm: &mut Swarm<NodeBehaviour>) -> Result<()> {
    info!("Starting graceful shutdown");
    let peers: Vec<_> = swarm.connected_peers().copied().collect();
    for peer in peers {
        let _ = swarm.disconnect_peer_id(peer);
    }
    // Drive the swarm briefly to flush QUIC CONNECTION_CLOSE frames
    let drain_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < drain_deadline {
        match tokio::time::timeout(Duration::from_millis(100), swarm.select_next_some()).await {
            Ok(_event) => continue,
            Err(_timeout) => break, // No more events, frames flushed
        }
    }
    info!("Graceful shutdown complete");
    Ok(())
}

fn handle_outgoing_request(
    swarm: &mut Swarm<NodeBehaviour>,
    correlator: &mut Correlator,
    peer_admission: &PeerAdmission,
    correlation_id: CorrelationId,
    payload: Vec<u8>,
    target: PeerTarget,
) -> Result<()> {
    let peer = match target {
        PeerTarget::Random => swarm
            .connected_peers()
            .filter(|peer| peer_admission.is_admitted(peer))
            .choose(&mut rand::rng())
            .copied()
            .context("No connected peers available")?,
        PeerTarget::Specific(peer_id) => {
            anyhow::ensure!(
                peer_admission.is_admitted(&peer_id),
                "requested peer has not passed network admission"
            );
            peer_id
        }
    };

    debug!("Outgoing request payload size: {:?}", payload.len());

    // Request events
    let query_id = swarm
        .behaviour_mut()
        .request_response
        .send_request(&peer, payload);
    debug!(
        "Outgoing request sent: query_id={}, correlation_id={}",
        query_id, correlation_id
    );
    correlator.track(query_id, correlation_id);
    Ok(())
}

fn handle_response(swarm: &mut Swarm<NodeBehaviour>, responder: DirectResponder) -> Result<()> {
    debug!("Sending response to {}", responder.id());
    let (channel, response) = responder.to_response()?;
    let ChannelType::Channel(channel) = channel else {
        bail!("responder did not return the correct type of channel");
    };
    swarm
        .behaviour_mut()
        .request_response
        .send_response(channel, response)
        .map_err(|payload| anyhow::anyhow!("Failed to send response: {:?}", payload))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use libp2p::connection_limits::{Behaviour, ConnectionLimits};
    use libp2p::kad::store::{MemoryStore, MemoryStoreConfig, RecordStore};
    use libp2p::kad::{Record, RecordKey};
    use libp2p::swarm::{ConnectionDenied, ConnectionId, ListenError, NetworkBehaviour};
    use libp2p::{Multiaddr, PeerId};
    use std::time::{Duration, Instant};

    #[test]
    fn quarantined_peer_is_restored_after_a_successful_admission() {
        let peer = PeerId::random();
        let mut failures = super::PeerConnectionFailures::new();

        failures.quarantine(&peer);
        assert!(failures.is_quarantined(&peer));

        failures.connection_succeeded(&peer);
        assert!(!failures.is_quarantined(&peer));
    }

    #[test]
    fn three_consecutive_failures_reach_the_eviction_threshold() {
        let peer = PeerId::random();
        let mut failures = super::PeerConnectionFailures::new();

        assert_eq!(failures.record_dial_failure(&peer), Some(1));
        assert_eq!(failures.record_dial_failure(&peer), Some(2));
        assert_eq!(
            failures.record_dial_failure(&peer),
            Some(super::MAX_CONSECUTIVE_DIAL_FAILURES)
        );

        failures.quarantine(&peer);
        assert_eq!(failures.record_dial_failure(&peer), None);
    }

    #[test]
    fn configured_peer_redial_distinguishes_unavailable_from_wrong_identity() {
        let unavailable = PeerId::random();
        let wrong_identity = PeerId::random();
        let mut failures = super::PeerConnectionFailures::new();

        failures.quarantine(&unavailable);
        failures.quarantine_identity(&wrong_identity);

        assert!(failures.is_quarantined(&unavailable));
        assert!(!failures.is_identity_quarantined(&unavailable));
        assert!(failures.is_identity_quarantined(&wrong_identity));

        failures.connection_succeeded(&wrong_identity);
        assert!(!failures.is_identity_quarantined(&wrong_identity));
    }

    #[test]
    fn ipv4_mapped_loopback_is_loopback() {
        assert!(super::is_loopback_addr(
            &"/ip6/::ffff:127.0.0.1/udp/9091/quic-v1".parse().unwrap()
        ));
        assert!(!super::is_loopback_addr(
            &"/ip6/::ffff:192.0.2.1/udp/9091/quic-v1".parse().unwrap()
        ));
    }

    #[test]
    fn strip_peer_id_removes_trailing_p2p_component() {
        let peer = PeerId::random();
        let addr: libp2p::Multiaddr = format!("/ip4/172.20.0.1/udp/9091/quic-v1/p2p/{peer}")
            .parse()
            .unwrap();
        let stripped = super::strip_peer_id(addr);
        assert_eq!(
            stripped,
            "/ip4/172.20.0.1/udp/9091/quic-v1"
                .parse::<libp2p::Multiaddr>()
                .unwrap()
        );
        // Idempotent on addresses without a /p2p/ suffix
        assert_eq!(super::strip_peer_id(stripped.clone()), stripped);
    }

    #[test]
    fn explicit_configured_peer_identity_cannot_rebind() {
        let expected = PeerId::random();
        let obtained = PeerId::random();
        let address: Multiaddr = format!("/ip4/172.20.0.1/udp/9091/quic-v1/p2p/{expected}")
            .parse()
            .unwrap();
        let corrected = super::strip_peer_id(address.clone());
        let mut configured = vec![super::ConfiguredPeer::from_address(address)];

        assert!(!super::rebind_configured_peer(
            &mut configured,
            &expected,
            obtained,
            &corrected,
        ));
        assert_eq!(configured[0].peer_id, Some(expected));
    }

    #[test]
    fn discovered_configured_peer_identity_can_rebind() {
        let expected = PeerId::random();
        let obtained = PeerId::random();
        let address: Multiaddr = "/ip4/172.20.0.1/udp/9091/quic-v1".parse().unwrap();
        let mut configured = vec![super::ConfiguredPeer::from_address(address.clone())];
        configured[0].peer_id = Some(expected);

        assert!(super::rebind_configured_peer(
            &mut configured,
            &expected,
            obtained,
            &address,
        ));
        assert_eq!(configured[0].peer_id, Some(obtained));
    }

    #[test]
    fn a_configured_peer_redial_adds_its_fallback() {
        let mut configured = super::ConfiguredPeer::from_address(
            "/dnsaddr/bootstrap.interfold.network".parse().unwrap(),
        );
        assert_eq!(
            super::redial_addresses(&configured),
            vec![configured.address.clone()]
        );

        let concrete: Multiaddr = "/ip4/34.192.113.100/udp/9501/quic-v1".parse().unwrap();
        configured.fallback = Some(concrete.clone());
        assert_eq!(
            super::redial_addresses(&configured),
            vec![configured.address.clone(), concrete]
        );
    }

    #[test]
    fn admission_through_the_configured_address_sets_the_fallback() {
        let peer = PeerId::random();
        let dnsaddr: Multiaddr = "/dnsaddr/bootstrap.interfold.network".parse().unwrap();
        let concrete: Multiaddr = "/ip4/34.192.113.100/udp/9501/quic-v1".parse().unwrap();
        let recent = super::RecentDials::default();
        recent.record(peer, concrete.clone());
        let mut configured = vec![super::ConfiguredPeer::from_address(dnsaddr.clone())];

        super::admit_configured_peer(&mut configured, dnsaddr, peer, &recent);

        assert_eq!(configured[0].peer_id, Some(peer));
        assert!(configured[0].identity_trusted);
        assert_eq!(configured[0].fallback, Some(concrete));
    }

    #[test]
    fn a_connection_refreshes_only_a_trusted_fallback() {
        let peer = PeerId::random();
        let moved: Multiaddr = "/ip4/34.192.113.101/udp/9501/quic-v1".parse().unwrap();
        let recent = super::RecentDials::default();
        recent.record(peer, moved.clone());
        let dnsaddr: Multiaddr = "/dnsaddr/bootstrap.interfold.network".parse().unwrap();
        let mut trusted = super::ConfiguredPeer::from_address(dnsaddr.clone());
        trusted.peer_id = Some(peer);
        trusted.identity_trusted = true;
        trusted.fallback = Some("/ip4/34.192.113.100/udp/9501/quic-v1".parse().unwrap());
        let mut rebound = super::ConfiguredPeer::from_address(dnsaddr);
        rebound.peer_id = Some(peer);
        let mut configured = vec![trusted, rebound];

        super::refresh_configured_fallbacks(&mut configured, &peer, &recent);

        assert_eq!(configured[0].fallback, Some(moved));
        assert_eq!(configured[1].fallback, None);
    }

    #[test]
    fn a_rebind_drops_the_fallback() {
        let expected = PeerId::random();
        let obtained = PeerId::random();
        let dnsaddr: Multiaddr = "/dnsaddr/bootstrap.interfold.network".parse().unwrap();
        let mut configured = vec![super::ConfiguredPeer::from_address(dnsaddr)];
        configured[0].peer_id = Some(expected);
        configured[0].fallback = Some("/ip4/34.192.113.100/udp/9501/quic-v1".parse().unwrap());

        // Any address matches a `/dnsaddr` entry, also one that another peer supplied.
        assert!(super::rebind_configured_peer(
            &mut configured,
            &expected,
            obtained,
            &"/ip4/192.0.2.9/udp/9091/quic-v1".parse().unwrap(),
        ));

        assert_eq!(configured[0].peer_id, Some(obtained));
        assert!(!configured[0].identity_trusted);
        assert_eq!(configured[0].fallback, None);
    }

    #[test]
    fn pinned_identity_blocks_rebinding_every_matching_entry() {
        let expected = PeerId::random();
        let obtained = PeerId::random();
        let pinned: Multiaddr = format!("/ip4/172.20.0.1/udp/9091/quic-v1/p2p/{expected}")
            .parse()
            .unwrap();
        let endpoint = super::strip_peer_id(pinned.clone());
        let mut configured = vec![
            super::ConfiguredPeer::from_address(endpoint.clone()),
            super::ConfiguredPeer::from_address(pinned),
        ];
        configured[0].peer_id = Some(expected);

        assert!(!super::rebind_configured_peer(
            &mut configured,
            &expected,
            obtained,
            &endpoint,
        ));
        assert!(configured
            .iter()
            .all(|configured_peer| configured_peer.peer_id == Some(expected)));
    }

    #[test]
    fn nested_per_peer_connection_limit_denial_is_expected() {
        let mut behaviour =
            Behaviour::new(ConnectionLimits::default().with_max_established_per_peer(Some(0)));
        let address: Multiaddr = "/memory/1".parse().unwrap();
        let limit_error = match behaviour.handle_established_inbound_connection(
            ConnectionId::new_unchecked(1),
            PeerId::random(),
            &address,
            &address,
        ) {
            Err(error) => error,
            Ok(_) => panic!("a zero per-peer connection limit must reject the connection"),
        };
        let exceeded = limit_error
            .downcast_ref::<libp2p::connection_limits::Exceeded>()
            .expect("the connection-limits behaviour must return Exceeded");
        assert_eq!(
            exceeded.to_string(),
            "connection limit exceeded: at most 0 established connections per peer are allowed"
        );
        let error = ListenError::Denied {
            cause: ConnectionDenied::new(limit_error),
        };

        assert!(super::is_redundant_peer_connection_denial(&error));
    }

    #[test]
    fn other_connection_limit_denial_is_not_redundant() {
        let mut behaviour =
            Behaviour::new(ConnectionLimits::default().with_max_pending_incoming(Some(0)));
        let address: Multiaddr = "/memory/1".parse().unwrap();
        let limit_error = behaviour
            .handle_pending_inbound_connection(ConnectionId::new_unchecked(1), &address, &address)
            .expect_err("a zero pending-incoming limit must reject the connection");
        let error = ListenError::Denied {
            cause: ConnectionDenied::new(limit_error),
        };

        assert!(!super::is_redundant_peer_connection_denial(&error));
    }

    #[test]
    fn expired_records_are_pruned_on_full_store() {
        let peer_id = PeerId::random();
        let config = MemoryStoreConfig {
            max_records: 5,
            max_value_bytes: 1024,
            max_providers_per_key: 1,
            max_provided_keys: 5,
        };
        let mut store = MemoryStore::with_config(peer_id, config);

        let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        for i in 0..5 {
            let record = Record {
                key: RecordKey::new(&format!("expired-{i}").into_bytes()),
                value: vec![i as u8],
                publisher: None,
                expires: Some(past),
            };
            store.put(record).expect("should succeed while under limit");
        }

        // Store is full — new put must fail
        let new_record = Record {
            key: RecordKey::new(&b"new-record".to_vec()),
            value: vec![42],
            publisher: None,
            expires: Some(Instant::now() + Duration::from_secs(3600)),
        };
        assert!(
            store.put(new_record.clone()).is_err(),
            "put should fail when store is at max_records"
        );

        super::prune_expired_records(&mut store, Instant::now());

        assert_eq!(
            store.records().count(),
            0,
            "all expired records should be pruned"
        );

        store
            .put(new_record)
            .expect("put should succeed after pruning expired records");
        assert_eq!(store.records().count(), 1);
    }

    #[test]
    fn non_expired_records_survive_pruning() {
        let peer_id = PeerId::random();
        let config = MemoryStoreConfig {
            max_records: 5,
            max_value_bytes: 1024,
            max_providers_per_key: 1,
            max_provided_keys: 5,
        };
        let mut store = MemoryStore::with_config(peer_id, config);

        let future = Instant::now() + Duration::from_secs(3600);
        let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();

        // 3 live records, 2 expired
        for i in 0..3 {
            store
                .put(Record {
                    key: RecordKey::new(&format!("live-{i}").into_bytes()),
                    value: vec![i as u8],
                    publisher: None,
                    expires: Some(future),
                })
                .unwrap();
        }
        for i in 0..2 {
            store
                .put(Record {
                    key: RecordKey::new(&format!("dead-{i}").into_bytes()),
                    value: vec![i as u8],
                    publisher: None,
                    expires: Some(past),
                })
                .unwrap();
        }

        assert_eq!(store.records().count(), 5);

        super::prune_expired_records(&mut store, Instant::now());

        assert_eq!(
            store.records().count(),
            3,
            "only live records should remain"
        );
    }

    fn small_store(max_records: usize) -> MemoryStore {
        let config = MemoryStoreConfig {
            max_records,
            max_value_bytes: 1024,
            max_providers_per_key: 1,
            max_provided_keys: 5,
        };
        MemoryStore::with_config(PeerId::random(), config)
    }

    fn record(key: &str, expires: Instant) -> Record {
        Record {
            key: RecordKey::new(&key.as_bytes().to_vec()),
            value: key.as_bytes().to_vec(),
            publisher: None,
            expires: Some(expires),
        }
    }

    fn ledger(per_owner: usize, records: usize, bytes: usize) -> super::ReplicaLedger {
        super::ReplicaLedger::new(super::ReplicaLimits {
            per_owner,
            records,
            bytes,
        })
    }

    /// A record whose key is the hash of its value, as peers store documents.
    fn document(value: &[u8], expires: Instant) -> Record {
        Record {
            key: RecordKey::new(&super::ContentHash::from_content(value)),
            value: value.to_vec(),
            publisher: None,
            expires: Some(expires),
        }
    }

    #[test]
    fn a_local_record_can_be_read_back_from_the_store() {
        let mut store = small_store(5);
        let now = Instant::now();
        let document = record("document", now + Duration::from_secs(3600));

        super::store_local_record(&mut store, &mut ledger(5, 5, 1024), document.clone(), now)
            .unwrap();

        assert_eq!(
            store.get(&document.key).map(|stored| stored.value.clone()),
            Some(document.value)
        );
    }

    #[test]
    fn a_full_store_drops_expired_records_to_hold_a_local_record() {
        let mut store = small_store(2);
        let now = Instant::now();
        let past = now.checked_sub(Duration::from_secs(1)).unwrap();
        store.put(record("expired", past)).unwrap();
        store
            .put(record("live", now + Duration::from_secs(3600)))
            .unwrap();
        let document = record("document", now + Duration::from_secs(3600));

        super::store_local_record(&mut store, &mut ledger(5, 5, 1024), document.clone(), now)
            .unwrap();

        assert!(store.get(&document.key).is_some());
        assert!(store.get(&RecordKey::new(&b"live".to_vec())).is_some());
        assert!(store.get(&RecordKey::new(&b"expired".to_vec())).is_none());
    }

    #[test]
    fn a_full_store_of_this_nodes_records_refuses_a_local_record() {
        let mut store = small_store(1);
        let now = Instant::now();
        store
            .put(record("live", now + Duration::from_secs(3600)))
            .unwrap();
        let document = record("document", now + Duration::from_secs(3600));

        assert!(matches!(
            super::store_local_record(&mut store, &mut ledger(5, 5, 1024), document, now),
            Err(libp2p::kad::store::Error::MaxRecords)
        ));
    }

    /// A local write in a store full of live records evicts a replica, the oldest of the sender
    /// with the most, so this node's records always fit. A replica of the same key becomes this
    /// node's record, and the ledger releases it.
    #[test]
    fn a_local_write_evicts_a_replica_and_takes_over_its_own_key() {
        let mut store = small_store(2);
        let mut replicas = ledger(5, 5, 1024);
        let (local, sender) = (PeerId::random(), PeerId::random());
        let now = Instant::now();
        let expires = now + Duration::from_secs(3600);
        for value in [b"first".as_slice(), b"second".as_slice()] {
            super::admit_replica(
                &mut store,
                &mut replicas,
                2,
                local,
                sender,
                document(value, expires),
                now,
            )
            .unwrap();
        }
        let own = document(b"own", expires);

        super::store_local_record(&mut store, &mut replicas, own.clone(), now).unwrap();
        assert!(store.get(&own.key).is_some());
        assert!(store.get(&document(b"first", expires).key).is_none());
        assert!(replicas.contains(document(b"second", expires).key.as_ref()));

        let promoted = document(b"second", expires);
        super::store_local_record(&mut store, &mut replicas, promoted.clone(), now).unwrap();
        assert!(!replicas.contains(promoted.key.as_ref()));
    }

    /// A sender cannot name this node as the publisher of a replica: the record would leave the
    /// ledger at the next reconciliation and stay in the store outside every replica limit.
    #[test]
    fn an_inbound_replica_that_names_this_node_as_its_publisher_is_refused() {
        let mut store = small_store(10);
        let mut replicas = ledger(5, 5, 1024);
        let (local, sender) = (PeerId::random(), PeerId::random());
        let now = Instant::now();
        let mut claimed = document(b"claimed", now + Duration::from_secs(3600));
        claimed.publisher = Some(local);

        assert!(super::admit_replica(
            &mut store,
            &mut replicas,
            10,
            local,
            sender,
            claimed.clone(),
            now,
        )
        .is_err());
        assert!(store.get(&claimed.key).is_none());
        assert!(!replicas.contains(claimed.key.as_ref()));
    }

    /// An inbound replica makes room: expired records go first, then the sender at its own limit
    /// gives up its oldest replica. This node's records are never replaced or evicted.
    #[test]
    fn an_inbound_replica_reclaims_expired_records_then_its_senders_oldest() {
        let mut store = small_store(10);
        let mut replicas = ledger(2, 10, 1024);
        let (local, sender) = (PeerId::random(), PeerId::random());
        let now = Instant::now();
        let expires = now + Duration::from_secs(3600);
        let past = now.checked_sub(Duration::from_secs(1)).unwrap();
        let mut own = document(b"own", expires);
        own.publisher = Some(local);
        store.put(own.clone()).unwrap();
        let admit = |store: &mut MemoryStore, replicas: &mut super::ReplicaLedger, value: &[u8]| {
            super::admit_replica(
                store,
                replicas,
                10,
                local,
                sender,
                document(value, expires),
                now,
            )
        };
        admit(&mut store, &mut replicas, b"one").unwrap();
        // A replica that expired still counts until the store removes it.
        let mut stale = document(b"stale", expires);
        super::admit_replica(
            &mut store,
            &mut replicas,
            10,
            local,
            sender,
            stale.clone(),
            now,
        )
        .unwrap();
        stale.expires = Some(past);
        store.put(stale.clone()).unwrap();

        admit(&mut store, &mut replicas, b"two").unwrap();
        assert!(
            store.get(&stale.key).is_none(),
            "the expired replica goes first"
        );
        assert!(store.get(&document(b"one", expires).key).is_some());

        admit(&mut store, &mut replicas, b"three").unwrap();
        assert!(
            store.get(&document(b"one", expires).key).is_none(),
            "the oldest goes next"
        );
        assert_eq!(replicas.owned_by(&sender), 2);

        // A remote put never replaces this node's record.
        let mut replacement = own.clone();
        replacement.publisher = Some(sender);
        replacement.expires = Some(expires + Duration::from_secs(60));
        super::admit_replica(
            &mut store,
            &mut replicas,
            10,
            local,
            sender,
            replacement,
            now,
        )
        .unwrap();
        assert_eq!(store.get(&own.key).unwrap().publisher, Some(local));
        assert!(!replicas.contains(own.key.as_ref()));
    }

    /// Kademlia removes an expired record during a lookup without telling the ledger. A peer that
    /// then stores the key again owns the new replica.
    #[test]
    fn a_replica_stored_again_after_kademlia_removed_it_gets_a_new_owner_and_place() {
        let mut store = small_store(10);
        let mut replicas = ledger(5, 10, 1024);
        let (local, first, second) = (PeerId::random(), PeerId::random(), PeerId::random());
        let now = Instant::now();
        let expires = now + Duration::from_secs(3600);
        let again = document(b"stored again", expires);
        super::admit_replica(
            &mut store,
            &mut replicas,
            10,
            local,
            first,
            again.clone(),
            now,
        )
        .unwrap();
        super::admit_replica(
            &mut store,
            &mut replicas,
            10,
            local,
            first,
            document(b"other", expires),
            now,
        )
        .unwrap();
        // As Kademlia does with an expired record during a lookup.
        store.remove(&again.key);

        super::admit_replica(
            &mut store,
            &mut replicas,
            10,
            local,
            second,
            again.clone(),
            now,
        )
        .unwrap();
        assert_eq!(replicas.owned_by(&first), 1);
        assert_eq!(replicas.owned_by(&second), 1);
    }

    /// One dealer's documents for four concurrent E3s fit its share of the replicas.
    #[test]
    fn a_dealers_documents_for_four_e3s_are_all_admitted() {
        let mut store = super::dht_store(PeerId::random());
        let mut replicas = super::ReplicaLedger::new(super::DHT_REPLICA_LIMITS);
        let (local, dealer) = (PeerId::random(), PeerId::random());
        let now = Instant::now();
        let expires = now + Duration::from_secs(3600);
        for index in 0..crate::ingress_limits::REPLICAS_PER_PEER {
            let value = format!("document {index}");
            super::admit_replica(
                &mut store,
                &mut replicas,
                super::DHT_MAX_RECORDS,
                local,
                dealer,
                document(value.as_bytes(), expires),
                now,
            )
            .unwrap();
        }
        assert_eq!(replicas.owned_by(&dealer), 160);
        assert_eq!(store.records().count(), 160);
    }

    /// The store holds a document of exactly the largest size, and refuses one byte more.
    #[test]
    fn a_document_of_the_largest_size_is_stored_and_one_byte_more_is_not() {
        let mut store = super::dht_store(PeerId::random());
        let mut replicas = super::ReplicaLedger::new(super::DHT_REPLICA_LIMITS);
        let (local, sender) = (PeerId::random(), PeerId::random());
        let now = Instant::now();
        let expires = now + Duration::from_secs(3600);
        let largest = vec![7u8; super::MAX_DHT_DOCUMENT_BYTES];
        let mut too_large = largest.clone();
        too_large.push(7);

        super::admit_replica(
            &mut store,
            &mut replicas,
            super::DHT_MAX_RECORDS,
            local,
            sender,
            document(&largest, expires),
            now,
        )
        .unwrap();
        assert!(super::admit_replica(
            &mut store,
            &mut replicas,
            super::DHT_MAX_RECORDS,
            local,
            sender,
            document(&too_large, expires),
            now
        )
        .is_err());
        let mut own = document(&too_large, expires);
        own.publisher = Some(local);
        assert!(super::store_local_record(&mut store, &mut replicas, own, now).is_err());
        assert_eq!(store.records().count(), 1);
    }

    /// A cancelled put reports at DEBUG and stays out of the upload summary, while a real failure
    /// stays an ERROR and counts as failed. Both reach their caller under their own correlation ID.
    #[test]
    fn cancelled_put_logs_debug_and_real_failure_logs_error() {
        use super::{DhtPutStep, DhtPuts};
        use libp2p::kad::{self, Quorum};
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Captured(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut node = super::Libp2pNetInterface::new(
            super::Libp2pKeypair::generate(),
            vec![],
            None,
            super::NetworkPolicy::local_unrestricted(),
        )
        .unwrap();
        let swarm = &mut node.swarm;
        let peer = PeerId::random();
        swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer, "/ip4/192.0.2.1/udp/1/quic-v1".parse().unwrap());
        let document = super::ContentHash::from_content(b"document");
        let other = super::ContentHash::from_content(b"other document");
        let record_of = |key: &super::ContentHash| Record::new(RecordKey::new(key), vec![1]);
        let kademlia = &mut swarm.behaviour_mut().kademlia;
        let cancelled =
            kademlia.put_record_to(record_of(&document), [peer].into_iter(), Quorum::One);
        let failed = kademlia.put_record_to(record_of(&other), [peer].into_iter(), Quorum::One);
        let mut dht_puts = DhtPuts::default();
        let (cancelled_id, failed_id) = (
            e3_events::CorrelationId::new(),
            e3_events::CorrelationId::new(),
        );
        let now = std::time::Instant::now();
        let deadline = now + Duration::from_secs(240);
        dht_puts.start(cancelled_id, document.clone(), cancelled, deadline);
        dht_puts.start(failed_id, other.clone(), failed, deadline);
        let event_tx = super::NetEventSender::new(8, 8);
        let mut events = event_tx.subscribe();
        let quorum_failed = |key: &super::ContentHash| {
            Err(kad::PutRecordError::QuorumFailed {
                key: RecordKey::new(key),
                success: Vec::new(),
                quorum: std::num::NonZeroUsize::new(1).unwrap(),
            })
        };

        let logs = Arc::new(Mutex::new(Vec::new()));
        let writer = Captured(logs.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let (queries, steps) = dht_puts.cancel(&document);
            super::end_dht_put_queries(&mut swarm.behaviour_mut().kademlia, queries);
            for step in steps {
                super::apply_dht_put_step(swarm, &event_tx, &mut dht_puts, step).unwrap();
            }
            // The cancelled upload's own end reports nothing more.
            assert!(dht_puts
                .upload_ended(cancelled, quorum_failed(&document))
                .is_none());
            let step: DhtPutStep = dht_puts
                .upload_ended(failed, quorum_failed(&other))
                .expect("the failure is reported");
            super::apply_dht_put_step(swarm, &event_tx, &mut dht_puts, step).unwrap();
        });

        let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        let line = |text: &str| {
            logs.lines()
                .find(|line| line.contains(text))
                .unwrap_or_default()
        };
        assert!(line("DHT put record cancelled").contains("DEBUG"), "{logs}");
        assert!(line("DHT put record failed").contains("ERROR"), "{logs}");
        assert_eq!(logs.matches("DHT put record failed").count(), 1, "{logs}");
        let correlation = |event| match event {
            super::NetEvent::DhtPutRecordError { correlation_id, .. } => correlation_id,
            other => panic!("expected a put error, got {other:?}"),
        };
        assert_eq!(correlation(events.try_recv().unwrap()), cancelled_id);
        assert_eq!(correlation(events.try_recv().unwrap()), failed_id);
        // The upload summary counts the real failure only.
        assert_eq!(dht_puts.take_summary(), Some((0, 1)));
    }

    /// Ending the queries of cancelled puts finishes an upload and a check. A put that still looks
    /// up its closest peers runs on: ending that lookup would upload the record to the peers found
    /// so far.
    #[test]
    fn ending_a_put_finishes_only_uploads_and_checks() {
        use super::EndedQuery;
        use libp2p::kad::{self, QueryInfo, Quorum};
        use std::task::{Context, Poll};

        let local = PeerId::random();
        let mut kademlia = kad::Behaviour::new(local, MemoryStore::new(local));
        let peer = PeerId::random();
        kademlia.add_address(&peer, "/ip4/192.0.2.1/udp/1/quic-v1".parse().unwrap());
        let document = super::ContentHash::from_content(b"document");
        let record_of = |key: &super::ContentHash| Record::new(RecordKey::new(key), vec![1]);

        let lookup = kademlia
            .put_record(record_of(&document), Quorum::One)
            .unwrap();
        let upload = kademlia.put_record_to(record_of(&document), [peer].into_iter(), Quorum::One);
        let check = kademlia.get_record(RecordKey::new(&document));
        let untouched =
            kademlia.put_record_to(record_of(&document), [peer].into_iter(), Quorum::One);

        let ended = super::end_dht_put_queries(
            &mut kademlia,
            vec![
                EndedQuery {
                    query: lookup,
                    checking: false,
                },
                EndedQuery {
                    query: upload,
                    checking: false,
                },
                EndedQuery {
                    query: check,
                    checking: true,
                },
            ],
        );
        assert_eq!(ended, vec![upload, check]);

        let mut context = Context::from_waker(futures::task::noop_waker_ref());
        let mut reported = Vec::new();
        for _ in 0..100 {
            match NetworkBehaviour::poll(&mut kademlia, &mut context) {
                Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent(
                    kad::Event::OutboundQueryProgressed { id, step, .. },
                )) if step.last => reported.push(id),
                Poll::Ready(_) => {}
                Poll::Pending => break,
            }
        }
        assert_eq!(reported.len(), 2);
        assert!(reported.contains(&upload) && reported.contains(&check));
        assert!(kademlia.query(&untouched).is_some());
        assert!(matches!(
            kademlia.query(&lookup).map(|query| query.info().clone()),
            Some(QueryInfo::PutRecord {
                phase: kad::PutRecordPhase::GetClosestPeers,
                ..
            })
        ));
    }
}

#[cfg(test)]
#[path = "net_interface_swarm_tests.rs"]
mod swarm_tests;
