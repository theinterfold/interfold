// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
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
        dht_put_summary::DhtPutSummary,
        peer_failure_tracker::PeerFailureTracker,
        wire::{decode_gossip, encode_gossip, MAX_DHT_DOCUMENT_BYTES, MAX_GOSSIP_BYTES},
    },
    events::{IncomingResponse, OutgoingRequest, ProtocolResponse},
    gossip_subscription_health::{GossipSubscriptionHealth, GOSSIP_SUBSCRIPTION_GRACE},
    keypair::Libp2pKeypair,
    net_interface_handle::{NetEventSender, NetInterfaceHandle},
    peer_admission::PeerAdmission,
    seen_messages::SeenIds,
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
    swarm::{dial_opts::DialOpts, DialError, ListenError, NetworkBehaviour, SwarmEvent},
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
/// How long, and for how many IDs, the node ignores a gossip message from an admitted peer that it
/// has already handled. This covers copies that return after the gossipsub duplicate cache (60 s)
/// has expired. The duplicate cache keeps its default: it also holds messages that arrived before
/// the sender was admitted, and a longer cache would delay a later copy of such a message.
const SEEN_GOSSIP_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const SEEN_GOSSIP_CAPACITY: usize = 100_000;
const DHT_MAX_RECORDS: usize = 1024;
const DHT_MAX_RECORDS_PER_PEER: usize = 64;
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
pub(crate) const EVENT_CHANNEL_SIZE: usize = 1000;
const CMD_CHANNEL_SIZE: usize = 1000;
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
        Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

/// Returns true only when we should filter loopback addresses from Kademlia.
/// This is the case when the node has at least one non-loopback listener,
/// meaning it's in a production-like environment where propagating loopback
/// addresses to remote peers would cause them to dial themselves.
/// In localhost test environments (all listeners on 127.0.0.1) we allow
/// loopback so that peers can discover each other.
fn should_filter_loopback(swarm: &Swarm<NodeBehaviour>) -> bool {
    swarm
        .listeners()
        .any(|addr| !is_loopback_addr(addr) && !is_unspecified_addr(addr))
}

/// Strip a trailing `/p2p/<peer-id>` component from a multiaddr.
/// Needed when re-keying a routing entry after a peer ID mismatch: the dialed
/// address still pins the stale peer ID, and re-adding it verbatim under the
/// new peer ID would make every subsequent dial fail with `WrongPeerId` again.
fn strip_peer_id(mut addr: Multiaddr) -> Multiaddr {
    if matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
        addr.pop();
    }
    addr
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfiguredPeer {
    peer_id: Option<libp2p::PeerId>,
    address: Multiaddr,
    identity_pinned: bool,
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

        let swarm = libp2p::SwarmBuilder::with_existing_identity(id.into_keypair())
            .with_tokio()
            .with_quic()
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
        let mut dht_records_by_peer: HashMap<libp2p::PeerId, HashSet<Vec<u8>>> = HashMap::new();
        let mut seen_gossip = SeenIds::new(SEEN_GOSSIP_TTL, SEEN_GOSSIP_CAPACITY);
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
        let mut dht_puts = DhtPutSummary::default();
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
                    prune_dht_peer_quotas(&mut self.swarm, &mut dht_records_by_peer);
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
                }
                _ = dht_expiry_tick.tick() => {
                    prune_expired_dht_records(&mut self.swarm);
                    prune_dht_peer_quotas(&mut self.swarm, &mut dht_records_by_peer);
                }
                _ = configured_peer_tick.tick() => {
                    redial_disconnected_configured_peers(
                        &mut self.swarm,
                        &configured_peers,
                        &mut peer_failures,
                        &peer_admission,
                    );
                }
                _ = dht_put_summary_tick.tick() => {
                    if let Some((stored, failed)) = dht_puts.take() {
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
                        let address = strip_peer_id(address);
                        for configured_peer in &mut configured_peers {
                            if configured_peer.address == address
                                && (!configured_peer.identity_pinned
                                    || configured_peer.peer_id == Some(peer_id))
                            {
                                configured_peer.peer_id = Some(peer_id);
                            }
                        }
                        continue;
                    }

                    if let Err(e) = process_swarm_command(
                        &mut self.swarm,
                        &event_tx,
                        &mut correlator,
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
                        &mut configured_peers,
                        &mut dht_records_by_peer,
                        &mut seen_gossip,
                        &mut dht_puts,
                        &self.network,
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
            .addresses(vec![configured_peer.address.clone()])
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
            .with_interval(Duration::from_secs(60)),
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
    let mut topic_score = gossipsub::TopicScoreParams::default();
    topic_score.time_in_mesh_quantum = Duration::from_secs(1);
    topic_score.time_in_mesh_cap = 10.0;
    topic_score.first_message_deliveries_cap = 100.0;
    topic_score.mesh_message_deliveries_weight = 0.0;
    topic_score.mesh_failure_penalty_weight = 0.0;
    topic_score.invalid_message_deliveries_weight = -10.0;
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
    let store_config = MemoryStoreConfig {
        max_records: DHT_MAX_RECORDS,
        max_value_bytes: MAX_DHT_DOCUMENT_BYTES,
        max_providers_per_key: DHT_MAX_PROVIDERS_PER_KEY,
        max_provided_keys: DHT_MAX_RECORDS,
    };
    let store = MemoryStore::with_config(peer_id, store_config);
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
async fn process_swarm_event(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &NetEventSender,
    cmd_tx: &mpsc::Sender<NetCommand>,
    correlator: &mut Correlator,
    peer_failures: &mut PeerConnectionFailures,
    peer_admission: &mut PeerAdmission,
    configured_peers: &mut [ConfiguredPeer],
    dht_records_by_peer: &mut HashMap<libp2p::PeerId, HashSet<Vec<u8>>>,
    seen_gossip: &mut SeenIds<gossipsub::MessageId>,
    dht_puts: &mut DhtPutSummary,
    network: &NetworkPolicy,
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
                if !(should_filter_loopback(swarm) && is_loopback_addr(&remote_addr)) {
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
            } else if should_filter_loopback(swarm) {
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
            let key_bytes = record.key.to_vec();
            let now = Instant::now();
            let valid_expiry = record
                .expires
                .is_some_and(|expires| expires > now && expires <= now + DHT_MAX_TTL);
            let key_matches = key_bytes.len() == 32
                && ContentHash::from_content(&record.value).as_ref() == key_bytes.as_slice();
            if !peer_admission.is_admitted(&source) {
                debug!(%source, "Rejected an inbound DHT record from an unadmitted peer");
                return Ok(());
            }
            let peer_keys = dht_records_by_peer.entry(source).or_default();
            let within_quota =
                peer_keys.contains(&key_bytes) || peer_keys.len() < DHT_MAX_RECORDS_PER_PEER;
            if record.value.len() <= MAX_DHT_DOCUMENT_BYTES
                && valid_expiry
                && key_matches
                && within_quota
            {
                let key_exists = swarm
                    .behaviour_mut()
                    .kademlia
                    .store_mut()
                    .get(&record.key)
                    .is_some();
                match swarm.behaviour_mut().kademlia.store_mut().put(record) {
                    Ok(()) if !key_exists => {
                        peer_keys.insert(key_bytes);
                    }
                    Ok(()) => {}
                    Err(error) => debug!(%source, %error, "Rejected DHT record at the local store"),
                }
            } else {
                debug!(
                    %source,
                    valid_expiry,
                    key_matches,
                    within_quota,
                    value_bytes = record.value.len(),
                    "Rejected an inbound DHT record"
                );
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Kademlia(kad::Event::InboundRequest {
            request: InboundRequest::AddProvider { .. },
        })) => {
            // Interfold does not use provider records. FilterBoth prevents remote peers from
            // consuming the provider-record budget.
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
                result: QueryResult::PutRecord(record),
                ..
            },
        )) => {
            report_put_record_result(event_tx, correlator, dht_puts, id, record)?;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source: peer_id,
            message_id: id,
            message,
        })) => {
            trace!("Got message with id: {id} from peer: {peer_id}");
            if peer_admission.is_admitted(&peer_id)
                && seen_gossip.check_and_record(&id, Instant::now())
            {
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(
                        &id,
                        &peer_id,
                        gossipsub::MessageAcceptance::Ignore,
                    );
                trace!(%peer_id, %id, "Ignored a gossip message this node already handled");
            } else if !peer_admission.is_admitted(&peer_id) {
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
                match decode_gossip(&message.data, network) {
                    Ok(gossip_data) => {
                        swarm
                            .behaviour_mut()
                            .gossipsub
                            .report_message_validation_result(
                                &id,
                                &peer_id,
                                gossipsub::MessageAcceptance::Accept,
                            );
                        event_tx.send(NetEvent::GossipData(gossip_data))?;
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

            let Some(pending_connections) = peer_admission.admit(peer_id) else {
                debug!(%peer_id, "Received Identify for an admitted or unstaged peer");
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
            let filter = should_filter_loopback(swarm);
            for pending in &pending_connections {
                if !(filter && is_loopback_addr(&pending.remote_address)) {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, strip_peer_id(pending.remote_address.clone()));
                }
            }
            for addr in &info.listen_addrs {
                if !(filter && is_loopback_addr(addr)) {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, strip_peer_id(addr.clone()));
                }
            }
            trace!(observed_address = %info.observed_addr, "Peer reported our observed address");
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
async fn process_swarm_command(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &NetEventSender,
    correlator: &mut Correlator,
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
            handle_store_local(swarm, event_tx, correlation_id, key, expires, value)?;
            Ok(())
        }
        NetCommand::DhtPutRecord {
            correlation_id,
            key,
            expires,
            value,
        } => {
            handle_put_record(
                swarm,
                event_tx,
                correlator,
                correlation_id,
                key,
                expires,
                value,
            )?;
            Ok(())
        }
        NetCommand::DhtCancelPut { key } => {
            cancel_record_uploads(&mut swarm.behaviour_mut().kademlia, correlator, &key);
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
            handle_remove_records(swarm, keys);
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
fn handle_remove_records(swarm: &mut Swarm<NodeBehaviour>, keys: Vec<ContentHash>) {
    let store = swarm.behaviour_mut().kademlia.store_mut();
    let mut removed = 0usize;
    for key in &keys {
        store.remove(&RecordKey::new(key));
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

/// Store a record in this node's own DHT store. When the store is full, remove the expired
/// records and try once more. Local stores and puts both write through here.
fn store_local_record(
    store: &mut MemoryStore,
    record: Record,
    now: Instant,
) -> Result<(), kad::store::Error> {
    match store.put(record.clone()) {
        Err(kad::store::Error::MaxRecords) => {
            let pruned = prune_expired_records(store, now);
            warn!("DHT store full: removed {pruned} expired records, storing once more");
            store.put(record)
        }
        result => result,
    }
}

/// Store a document in this node's own DHT store, as the publisher, without uploading it to other
/// peers. Peers that look its key up can then fetch it from this node, even when no upload has
/// succeeded yet.
fn handle_store_local(
    swarm: &mut Swarm<NodeBehaviour>,
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
    match store_local_record(store, record, Instant::now()) {
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

/// Release per-peer quota entries after the corresponding local record is removed.
fn prune_dht_peer_quotas(
    swarm: &mut Swarm<NodeBehaviour>,
    records_by_peer: &mut HashMap<libp2p::PeerId, HashSet<Vec<u8>>>,
) {
    let store = swarm.behaviour_mut().kademlia.store_mut();
    for keys in records_by_peer.values_mut() {
        keys.retain(|key| store.get(&RecordKey::new(key)).is_some());
    }
    records_by_peer.retain(|_, keys| !keys.is_empty());
}

fn handle_put_record(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &NetEventSender,
    correlator: &mut Correlator,
    correlation_id: CorrelationId,
    key: ContentHash,
    expires: Option<Instant>,
    value: ArcBytes,
) -> Result<()> {
    debug!("DHT PUT RECORD");
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
    let result = store_local_record(store, record.clone(), Instant::now()).and_then(|()| {
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
            correlator.track(qid, correlation_id);
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

/// End the puts of `key` that are in their upload phase, so that their queries stop waiting for
/// answers and release the record. An ended put still reports its result, which nobody waits for.
/// This is not a full cancel. Requests that a query already gave to the connection handlers,
/// queued or in progress, still go out: Kademlia has no call that takes them back.
///
/// A put first looks up the peers closest to the key. Ending that lookup makes Kademlia upload the
/// record to the peers found so far, so a put in its lookup runs on to its normal end and uploads.
/// End the puts of `key` that upload their record, and mark them cancelled, so that their quorum
/// failure is not reported as a failed upload. A put that still looks up its closest peers runs on.
fn cancel_record_uploads(
    kademlia: &mut KademliaBehaviour<MemoryStore>,
    correlator: &mut Correlator,
    key: &ContentHash,
) {
    for query_id in finish_record_uploads(kademlia, key) {
        correlator.mark_cancelled(query_id);
    }
}

/// Send the result of a put to its caller and count it in the upload summary. A put that this node
/// cancelled ends with a quorum failure too; it is logged at DEBUG and not counted, because it was
/// neither stored nor a failed upload.
fn report_put_record_result(
    event_tx: &NetEventSender,
    correlator: &mut Correlator,
    dht_puts: &mut DhtPutSummary,
    id: kad::QueryId,
    result: kad::PutRecordResult,
) -> Result<()> {
    let (correlation_id, cancelled) = correlator.expire_cancellable(id)?;
    if !cancelled {
        dht_puts.record(result.is_ok());
    }
    match result {
        Ok(record) => {
            let key = ContentHash(record.key.to_vec());
            debug!("DHT put record succeeded: {:?}", key);
            event_tx.send(NetEvent::DhtPutRecordSucceeded {
                key,
                correlation_id,
            })?;
        }
        Err(error) => {
            if cancelled {
                debug!("DHT put record cancelled: {}", error);
            } else {
                error!("DHT put record failed: {}", error);
            }
            event_tx.send(NetEvent::DhtPutRecordError {
                correlation_id,
                error: PutOrStoreError::PutRecordError(error),
            })?;
        }
    }
    Ok(())
}

/// End the puts of `key` that upload their record, and return their query IDs.
fn finish_record_uploads(
    kademlia: &mut KademliaBehaviour<MemoryStore>,
    key: &ContentHash,
) -> Vec<kad::QueryId> {
    let key = RecordKey::new(key);
    let mut finished = Vec::new();
    for mut query in kademlia.iter_queries_mut() {
        let uploading = matches!(
            query.info(),
            kad::QueryInfo::PutRecord {
                record,
                phase: kad::PutRecordPhase::PutRecord { .. },
                ..
            } if record.key == key
        );
        if uploading {
            query.finish();
            finished.push(query.id());
        }
    }
    finished
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

    #[test]
    fn a_local_record_can_be_read_back_from_the_store() {
        let mut store = small_store(5);
        let now = Instant::now();
        let document = record("document", now + Duration::from_secs(3600));

        super::store_local_record(&mut store, document.clone(), now).unwrap();

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

        super::store_local_record(&mut store, document.clone(), now).unwrap();

        assert!(store.get(&document.key).is_some());
        assert!(store.get(&RecordKey::new(&b"live".to_vec())).is_some());
        assert!(store.get(&RecordKey::new(&b"expired".to_vec())).is_none());
    }

    #[test]
    fn a_full_store_of_live_records_refuses_a_local_record() {
        let mut store = small_store(1);
        let now = Instant::now();
        store
            .put(record("live", now + Duration::from_secs(3600)))
            .unwrap();
        let document = record("document", now + Duration::from_secs(3600));

        assert!(matches!(
            super::store_local_record(&mut store, document, now),
            Err(libp2p::kad::store::Error::MaxRecords)
        ));
    }

    /// A cancelled upload ends with a quorum failure that is logged at DEBUG and left out of the
    /// upload summary, while a real failure stays an ERROR and counts as failed. Both reach their
    /// caller under their own correlation ID.
    #[test]
    fn cancelled_put_logs_debug_and_real_failure_logs_error() {
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

        let local = PeerId::random();
        let mut kademlia = kad::Behaviour::new(local, MemoryStore::new(local));
        let peer = PeerId::random();
        kademlia.add_address(&peer, "/ip4/192.0.2.1/udp/1/quic-v1".parse().unwrap());
        let document = super::ContentHash::from_content(b"document");
        let other = super::ContentHash::from_content(b"other document");
        let record_of = |key: &super::ContentHash| Record::new(RecordKey::new(key), vec![1]);
        let cancelled =
            kademlia.put_record_to(record_of(&document), [peer].into_iter(), Quorum::One);
        let failed = kademlia.put_record_to(record_of(&other), [peer].into_iter(), Quorum::One);
        let mut correlator = super::Correlator::new();
        let (cancelled_id, failed_id) = (
            e3_events::CorrelationId::new(),
            e3_events::CorrelationId::new(),
        );
        correlator.track(cancelled, cancelled_id);
        correlator.track(failed, failed_id);
        let event_tx = super::NetEventSender::new(8, 8);
        let mut events = event_tx.subscribe();
        let mut dht_puts = super::DhtPutSummary::default();
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
            super::cancel_record_uploads(&mut kademlia, &mut correlator, &document);
            super::report_put_record_result(
                &event_tx,
                &mut correlator,
                &mut dht_puts,
                cancelled,
                quorum_failed(&document),
            )
            .unwrap();
            super::report_put_record_result(
                &event_tx,
                &mut correlator,
                &mut dht_puts,
                failed,
                quorum_failed(&other),
            )
            .unwrap();
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
        assert_eq!(dht_puts.take(), Some((0, 1)));
    }

    /// A cancel ends the upload of its key only. A put that still looks up its closest peers runs
    /// on: ending that lookup would upload the record to the peers found so far.
    #[test]
    fn a_cancel_ends_only_the_uploads_of_its_key() {
        use libp2p::kad::{self, QueryInfo, Quorum};
        use std::task::{Context, Poll};

        let local = PeerId::random();
        let mut kademlia = kad::Behaviour::new(local, MemoryStore::new(local));
        let peer = PeerId::random();
        kademlia.add_address(&peer, "/ip4/192.0.2.1/udp/1/quic-v1".parse().unwrap());
        let document = super::ContentHash::from_content(b"document");
        let other = super::ContentHash::from_content(b"other document");
        let record_of = |key: &super::ContentHash| Record::new(RecordKey::new(key), vec![1]);

        let lookup = kademlia
            .put_record(record_of(&document), Quorum::One)
            .unwrap();
        let upload = kademlia.put_record_to(record_of(&document), [peer].into_iter(), Quorum::One);
        let other_upload =
            kademlia.put_record_to(record_of(&other), [peer].into_iter(), Quorum::One);

        assert_eq!(
            super::finish_record_uploads(&mut kademlia, &document),
            vec![upload]
        );

        let mut context = Context::from_waker(futures::task::noop_waker_ref());
        let mut reported = Vec::new();
        for _ in 0..100 {
            match NetworkBehaviour::poll(&mut kademlia, &mut context) {
                Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent(
                    kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::PutRecord(_),
                        ..
                    },
                )) => reported.push(id),
                Poll::Ready(_) => {}
                Poll::Pending => break,
            }
        }
        assert_eq!(reported, vec![upload]);
        assert!(kademlia.query(&other_upload).is_some());
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
