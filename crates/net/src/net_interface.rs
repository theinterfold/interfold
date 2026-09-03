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
        peer_failure_tracker::PeerFailureTracker,
        wire::{decode_gossip, encode_gossip, MAX_DHT_DOCUMENT_BYTES, MAX_GOSSIP_BYTES},
    },
    events::{IncomingResponse, OutgoingRequest, ProtocolResponse},
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
const DHT_MAX_RECORDS: usize = 1024;
/// Per-peer inbound record quota. Must absorb a full CKKS relin ceremony:
/// every committee member broadcasts one document per (round, level,
/// chunk) — 48+ documents each at the 24-level sign-extraction ladder —
/// and Kademlia replication makes peers re-serve OTHERS' records under
/// their own source id, so a peer can legitimately deliver most of the
/// record set. 64 starved the ceremony live (puts failed QuorumFailed
/// once the quota tripped); the global DHT_MAX_RECORDS cap still bounds
/// total memory.
const DHT_MAX_RECORDS_PER_PEER: usize = 512;
const DHT_MAX_TTL: Duration = Duration::from_secs(31 * 24 * 60 * 60);
const DHT_MAX_PROVIDERS_PER_KEY: usize = 20;
const MAX_CONSECUTIVE_DIAL_FAILURES: u32 = 3;
const STALE_PEER_COOLDOWN: Duration = Duration::from_secs(30 * 60);
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
}

impl PeerConnectionFailures {
    fn new() -> Self {
        Self {
            dial: PeerFailureTracker::new(),
            identity_mismatch: PeerFailureTracker::new(),
            quarantined_until: HashMap::new(),
        }
    }

    fn connection_succeeded(&mut self, peer_id: &libp2p::PeerId) {
        self.dial.reset(peer_id);
        self.identity_mismatch.reset(peer_id);
        self.quarantined_until.remove(peer_id);
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
        let mut admission_tick = tokio::time::interval(Duration::from_secs(5));
        admission_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
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
                // Process commands
                Some(command) = cmd_rx.recv() => {
                    if let NetCommand::Shutdown = command {
                        if let Err(e) = handle_shutdown(&mut self.swarm).await {
                            error!("Error processing NetCommand: {e}");
                        }
                        break;
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
                        &mut dht_records_by_peer,
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
        .heartbeat_interval(Duration::from_secs(10))
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
    config
        .set_max_packet_size(MAX_KADEMLIA_PAYLOAD_BYTES)
        .set_query_timeout(Duration::from_secs(30))
        .set_record_filtering(StoreInserts::FilterBoth);
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
    dht_records_by_peer: &mut HashMap<libp2p::PeerId, HashSet<Vec<u8>>>,
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
                    // The node at this address has a new PeerId (e.g. restarted with new keys).
                    // Remove the stale entry and add the new one so we don't loop.
                    // Other routing tables can advertise the stale identity again. Quarantine
                    // prevents reinsertion, and concurrent failures remain debug events.
                    let remote_addr = address.clone();
                    let mismatch_count =
                        peer_failures.identity_mismatch.record_failure(failed_peer);
                    peer_failures.quarantine(failed_peer);
                    if mismatch_count == 1 {
                        info!(
                            "Peer ID mismatch at {remote_addr}: expected {failed_peer}, got {obtained} — \
                             replacing stale routing entry"
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
                        // Strip the stale /p2p/<old-id> suffix, otherwise dials to the
                        // new peer via this address fail with WrongPeerId forever.
                        let corrected_addr = strip_peer_id(remote_addr.clone());

                        // Redial the node under its actual identity — a direct dial
                        // doesn't propagate the address, so no loopback filtering is
                        // needed. The default dial condition (DisconnectedAndNotDialing)
                        // makes this a no-op while we are already connected or
                        // connecting to the real peer, so repeated mismatches cause no
                        // churn — while a dropped connection is re-attempted on any
                        // later mismatch (recovery is not one-shot).
                        let opts = DialOpts::peer_id(obtained)
                            .addresses(vec![corrected_addr])
                            .build();
                        if let Err(e) = swarm.dial(opts) {
                            debug!("Redial of {obtained} after peer ID replacement skipped: {e}");
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
            ..
        })) => {
            if peer_failures.is_quarantined(&peer) {
                swarm.behaviour_mut().kademlia.remove_peer(&peer);
                debug!(%peer, "Ignored a quarantined Kademlia routing update");
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
            let correlation_id = correlator.expire(id)?;
            match record {
                Ok(record) => {
                    let key = ContentHash(record.key.to_vec());
                    debug!("DHT put record succeeded: {:?}", key);
                    event_tx.send(NetEvent::DhtPutRecordSucceeded {
                        key,
                        correlation_id,
                    })?;
                }
                Err(error) => {
                    error!("DHT put record failed: {}", error);
                    event_tx.send(NetEvent::DhtPutRecordError {
                        correlation_id,
                        error: PutOrStoreError::PutRecordError(error),
                    })?;
                }
            }
        }

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
        } => {
            handle_gossip_publish(swarm, event_tx, network, data, topic, correlation_id)?;
            Ok(())
        }
        NetCommand::Dial(env) => {
            let multi = env.take().context("Dial received without payload")?;
            handle_dial(swarm, event_tx, multi)?;
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
        NetCommand::Shutdown => {
            unreachable!("shutdown command must be handled in Libp2pNetInterface::start")
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
) -> Result<()> {
    let bytes = match (|| -> Result<Vec<u8>> {
        anyhow::ensure!(
            topic == network.protocols().gossip_topic(),
            "refusing to publish on an unconfigured gossip topic"
        );
        encode_gossip(&data, network)
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
/// This is a fallback safety net — primary cleanup happens per-E3 via
/// `handle_remove_records` when an E3 completes.
fn prune_expired_dht_records(swarm: &mut Swarm<NodeBehaviour>) {
    let now = Instant::now();
    let store = swarm.behaviour_mut().kademlia.store_mut();
    let before = store.records().count();
    store.retain(|_, r| r.expires.is_none_or(|e| e > now));
    let after = store.records().count();
    if before != after {
        info!(
            "DHT pruned {} expired records ({} remaining)",
            before - after,
            after
        );
    }
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
    match swarm
        .behaviour_mut()
        .kademlia
        // Quorum::Majority calculates quorum from the Kademlia routing table size,
        // not the actual cluster size. With a routing table of ~21 entries,
        // it required 11 peers to acknowledge the record, which is impossible
        // in a 4-node cluster.
        .put_record(record.clone(), Quorum::One)
    {
        Ok(qid) => {
            correlator.track(qid, correlation_id);
            debug!("PUT RECORD OK qid={:?} cid={}", qid, correlation_id);
        }
        Err(kad::store::Error::MaxRecords) => {
            warn!("DHT store full (MaxRecords) — attempting fallback expired-record prune");
            prune_expired_dht_records(swarm);
            match swarm
                .behaviour_mut()
                .kademlia
                .put_record(record, Quorum::One)
            {
                Ok(qid) => {
                    correlator.track(qid, correlation_id);
                    debug!(
                        "PUT RECORD OK (after prune) qid={:?} cid={}",
                        qid, correlation_id
                    );
                }
                Err(error) => {
                    error!("DHT put failed even after pruning expired records: {error:?}");
                    event_tx.send(NetEvent::DhtPutRecordError {
                        correlation_id,
                        error: PutOrStoreError::StoreError(error),
                    })?;
                }
            }
        }
        Err(error) => {
            event_tx.send(NetEvent::DhtPutRecordError {
                correlation_id,
                error: PutOrStoreError::StoreError(error),
            })?;
        }
    }
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

        let now = Instant::now();
        store.retain(|_, r| r.expires.is_none_or(|e| e > now));

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

        let now = Instant::now();
        store.retain(|_, r| r.expires.is_none_or(|e| e > now));

        assert_eq!(
            store.records().count(),
            3,
            "only live records should remain"
        );
    }
}
