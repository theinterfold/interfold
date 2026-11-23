// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The node's place on the network: one task owns the swarm, and everything else talks to it
//! through commands that never wait. Disk reads and writes run off that task.

use crate::{
    behaviour::{Behaviour, BehaviourEvent, IDLE_CONNECTION, MAX_BLOB_BYTES},
    blob_codec::{BlobBatchRequest, BlobBatchResponse, DirectAck, DirectMessage},
    fetcher::{Done, Fetcher, Wanted},
    inbox::{inbox, Inbox, InboxWriter},
    peers::{advertised, strip_peer_id, PeerBook},
    protocols::{Protocols, Standing},
    serving::Serving,
    transport::{DialGuard, RecentDials},
    Network, NetworkError, NetworkStats,
};
use alloy_primitives::{Address, B256};
use e3_blobs::{BlobStore, MemoryBlobs};
use e3_protocol::{
    node::{Admission, PeerMessage},
    wire::{Envelope, PeerProof},
    BlobRef, E3Id,
};
use e3_utils::limited::Limited;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, MessageAcceptance, MessageId, PublishError},
    identify,
    identity::Keypair,
    kad,
    request_response::{self, InboundRequestId, OutboundRequestId, ResponseChannel},
    swarm::{dial_opts::DialOpts, DialError, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info, warn};

/// Commands waiting for the swarm's task. Past this, a command is told the node is busy.
const MAX_COMMANDS: usize = 1_024;
/// Messages whose senders a node remembers, to fetch their blobs from.
const MAX_SOURCES: usize = 4_096;
/// Maximum distinct source peers tracked per message ID.
const MAX_SOURCES_PER_MESSAGE: usize = 8;
/// The peers whose addresses the node remembers putting into Kademlia.
const MAX_ADVERTISING_PEERS: usize = 1_024;
/// A publish waits this long for a peer on the topic, as a node that just started has none.
const PUBLISH_ATTEMPTS: u32 = 6;
const PUBLISH_RETRY: Duration = Duration::from_secs(5);
/// How often the node looks at which configured peers to dial.
const DIAL_CHECK: Duration = Duration::from_secs(1);
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the node checks its peers: identified in time, subscribed, and fetches not stuck.
const PEER_CHECK: Duration = Duration::from_secs(5);
/// A copy counts from `MAX_COPY_AGE` seconds before this node's clock to `MAX_CLOCK_AHEAD` after
/// it. Every send and re-send signs a new copy, so an older one is a replay, which gossip's
/// duplicate cache stops for only a minute.
const MAX_COPY_AGE: u64 = 10 * 60;
const MAX_CLOCK_AHEAD: u64 = 2 * 60;
/// How long a stop waits for connections to say goodbye.
const DRAIN: Duration = Duration::from_secs(2);
/// A log line that can repeat with every message comes at most this often.
const WARN_EVERY: Duration = Duration::from_secs(60);

#[derive(Default)]
struct AtomicStats {
    direct_sent: AtomicU64,
    gossip_sent: AtomicU64,
    blob_batches_fetched: AtomicU64,
    blob_batches_served: AtomicU64,
}

impl AtomicStats {
    fn snapshot(&self) -> NetworkStats {
        NetworkStats {
            direct_sent: self.direct_sent.load(Ordering::Relaxed),
            gossip_sent: self.gossip_sent.load(Ordering::Relaxed),
            blob_batches_fetched: self.blob_batches_fetched.load(Ordering::Relaxed),
            blob_batches_served: self.blob_batches_served.load(Ordering::Relaxed),
        }
    }
}

/// How a node joins its network.
#[derive(Clone, Debug)]
pub struct P2pConfig {
    /// The ed25519 secret of the node's network identity, which peers address it by.
    pub identity: [u8; 32],
    /// Nodes of different networks, or of releases with different protocol versions, never share
    /// a topic or a protocol.
    pub network: String,
    /// Keeps deployments on one network apart.
    pub deployment: String,
    pub protocol_version: u32,
    pub listen: Vec<Multiaddr>,
    /// Peers to dial, again whenever the connection drops. One without its `/p2p/` identity is
    /// dialed by address until a connection shows which peer it is.
    pub peers: Vec<Multiaddr>,
}

impl P2pConfig {
    /// The hash the node's operator key signs to say this network identity is theirs.
    pub fn proof_hash(&self) -> Result<B256, P2pError> {
        Ok(PeerProof::signing_hash(&self.peer()?.to_bytes()))
    }

    fn key(&self) -> Result<Keypair, P2pError> {
        Keypair::ed25519_from_bytes(self.identity)
            .map_err(|error| P2pError::Identity(error.to_string()))
    }

    fn peer(&self) -> Result<PeerId, P2pError> {
        Ok(self.key()?.public().to_peer_id())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    #[error("network identity: {0}")]
    Identity(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("listening on {0}: {1}")]
    Listen(Multiaddr, String),
}

/// The node's place on the peer-to-peer network.
pub struct P2p {
    commands: mpsc::Sender<Command>,
    admitted: watch::Sender<Admission>,
    peer: PeerId,
    listening: Vec<Multiaddr>,
    connected: Arc<AtomicUsize>,
    stats: Arc<AtomicStats>,
}

enum Command {
    Publish { envelope: Envelope, done: Done },
    Fetch { message: PeerMessage, done: Done },
    Close { done: oneshot::Sender<()> },
}

impl P2p {
    /// Joins the network as the operator that `proof` names. Peer messages for this node arrive
    /// in the returned inbox as their envelopes open; `fetch` brings their blobs into `blobs`. The
    /// inbox closes when the network stops.
    pub async fn start(
        config: P2pConfig,
        proof: PeerProof,
        blobs: impl BlobStore,
    ) -> Result<(Self, Inbox), P2pError> {
        if !proof.holds_for(&config.peer()?.to_bytes()) {
            let why = "the operator's proof does not name this network identity";
            return Err(P2pError::Identity(why.into()));
        }
        Self::join(config, true, proof, blobs).await
    }

    /// Joins the network only to help peers find each other: the node answers their lookups and
    /// takes no part in their messages. The inbox only says when the network stopped.
    pub async fn bootstrap(config: P2pConfig) -> Result<(Self, Inbox), P2pError> {
        Self::join(config, false, PeerProof::default(), MemoryBlobs::default()).await
    }

    async fn join(
        config: P2pConfig,
        messages: bool,
        proof: PeerProof,
        blobs: impl BlobStore,
    ) -> Result<(Self, Inbox), P2pError> {
        let key = config.key()?;
        let peer = key.public().to_peer_id();
        let protocols =
            Protocols::new(&config.network, &config.deployment, config.protocol_version);
        let recent_dials = RecentDials::default();
        let book = PeerBook::new(peer, config.peers, Instant::now());
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            // QUIC under the dial guard, below the DNS layer, so it also sees the addresses that
            // a `/dnsaddr` resolves to.
            .with_other_transport(|key| {
                DialGuard::new(
                    libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(key)),
                    recent_dials.clone(),
                )
            })
            .map_err(|error| P2pError::Transport(error.to_string()))?
            .with_dns()
            .map_err(|error| P2pError::Transport(error.to_string()))?
            .with_behaviour(|key| {
                Behaviour::new(key, &protocols, messages, book).map_err(Into::into)
            })
            .map_err(|error| P2pError::Transport(error.to_string()))?
            .with_swarm_config(|config| config.with_idle_connection_timeout(IDLE_CONNECTION))
            .build();
        for address in &config.listen {
            swarm
                .listen_on(address.clone())
                .map_err(|error| P2pError::Listen(address.clone(), error.to_string()))?;
        }
        let listening = listening(&mut swarm, peer, config.listen.len()).await?;
        let (writer, reader) = inbox();
        let (commands, command_receiver) = mpsc::channel(MAX_COMMANDS);
        let (admitted, admission) = watch::channel(Admission::default());
        let (served_writer, served) = mpsc::unbounded_channel();
        let (stored_writer, stored) = mpsc::unbounded_channel();
        let connected = Arc::new(AtomicUsize::new(0));
        let stats = Arc::new(AtomicStats::default());
        let mut driver = Driver {
            connected: connected.clone(),
            stats: stats.clone(),
            swarm,
            protocols,
            messages,
            proof,
            blobs,
            inbox: writer,
            admission,
            recent_dials,
            sources: Recent::default(),
            advertised: Recent::default(),
            verified_peers: HashMap::new(),
            operator_peers: HashMap::new(),
            fetcher: Fetcher::default(),
            requests: HashMap::new(),
            direct_pending: HashMap::new(),
            publishes: VecDeque::new(),
            serving: Serving::default(),
            served_writer,
            served,
            stored_writer,
            stored,
            refused: Limited::new(WARN_EVERY),
        };
        driver.dial_peers();
        tokio::spawn(driver.run(command_receiver));
        let p2p = Self {
            commands,
            admitted,
            peer,
            listening,
            connected,
            stats,
        };
        Ok((p2p, reader))
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer
    }

    /// The addresses peers can dial this node at.
    pub fn listening(&self) -> &[Multiaddr] {
        &self.listening
    }

    fn send(&self, command: Command) -> Result<(), NetworkError> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => NetworkError::Busy,
                mpsc::error::TrySendError::Closed(_) => NetworkError::Stopped,
            })
    }
}

async fn listening(
    swarm: &mut Swarm<Behaviour>,
    peer: PeerId,
    wanted: usize,
) -> Result<Vec<Multiaddr>, P2pError> {
    tokio::time::timeout(LISTEN_TIMEOUT, async {
        let mut listening = Vec::new();
        while listening.len() < wanted {
            match swarm.next().await {
                Some(SwarmEvent::NewListenAddr { address, .. }) => listening.push(
                    address
                        .with_p2p(peer)
                        .expect("a listen address names no peer"),
                ),
                Some(SwarmEvent::ListenerClosed {
                    addresses, reason, ..
                }) => {
                    let address = addresses.first().cloned().unwrap_or(Multiaddr::empty());
                    let reason = reason.err().map(|error| error.to_string());
                    return Err(P2pError::Listen(address, reason.unwrap_or_default()));
                }
                _ => {}
            }
        }
        Ok(listening)
    })
    .await
    .map_err(|_| P2pError::Listen(Multiaddr::empty(), "no address in time".into()))?
}

impl Network for P2p {
    async fn publish(&self, envelope: Envelope) -> Result<(), NetworkError> {
        let (done, result) = oneshot::channel();
        self.send(Command::Publish { envelope, done })?;
        result.await.map_err(|_| NetworkError::Stopped)?
    }

    async fn fetch(&self, message: PeerMessage) -> Result<(), NetworkError> {
        let (done, result) = oneshot::channel();
        self.send(Command::Fetch { message, done })?;
        result.await.map_err(|_| NetworkError::Stopped)?
    }

    fn admit(&self, admission: Admission) {
        self.admitted.send_replace(admission);
    }

    fn connected(&self) -> usize {
        self.connected.load(Ordering::Relaxed)
    }

    fn stats(&self) -> NetworkStats {
        self.stats.snapshot()
    }

    async fn close(&self) {
        let (done, closed) = oneshot::channel();
        if self.commands.send(Command::Close { done }).await.is_ok() {
            let _ = closed.await;
        }
    }
}

/// The latest `CAPACITY` entries, oldest dropped first.
struct Recent<K, V, const CAPACITY: usize> {
    entries: HashMap<K, V>,
    order: VecDeque<K>,
}

impl<K, V, const CAPACITY: usize> Default for Recent<K, V, CAPACITY> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl<K: Copy + Eq + std::hash::Hash, V, const CAPACITY: usize> Recent<K, V, CAPACITY> {
    fn insert(&mut self, key: K, value: V) {
        if self.entries.insert(key, value).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key)
    }
}

struct PendingPublish {
    bytes: Vec<u8>,
    attempts: u32,
    done: Done,
}

/// A member's batched request for blobs, on its way through the line.
struct Asked {
    e3: E3Id,
    hashes: Vec<B256>,
    member: Address,
    channel: ResponseChannel<BlobBatchResponse>,
}

/// A blob batch read for a member, ready to send.
struct Served {
    request: InboundRequestId,
    channel: ResponseChannel<BlobBatchResponse>,
    response: BlobBatchResponse,
}

/// What became of a blob batch that arrived.
enum BatchStored {
    Done { kept: usize, retry: Vec<BlobRef> },
    Failed(String),
}

struct Driver<S> {
    connected: Arc<AtomicUsize>,
    stats: Arc<AtomicStats>,
    swarm: Swarm<Behaviour>,
    protocols: Protocols,
    /// Whether the node takes part in the network's messages; a bootstrap node does not.
    messages: bool,
    /// The operator this node is, and its word for it, which every blob/direct request shows.
    proof: PeerProof,
    blobs: S,
    inbox: InboxWriter,
    /// Whose messages the node takes, and who may read each E3's blobs.
    admission: watch::Receiver<Admission>,
    recent_dials: RecentDials,
    /// The peers that sent each message, by its ID.
    sources: Recent<B256, Vec<PeerId>, MAX_SOURCES>,
    /// The addresses of each peer that the node put into Kademlia from its last Identify.
    advertised: Recent<PeerId, Vec<Multiaddr>, MAX_ADVERTISING_PEERS>,
    /// Verified `(PeerId -> Operator)` cache for active connections, avoiding repeated ECDSA
    /// verification on every blob/direct request and enabling direct pairwise routing.
    verified_peers: HashMap<PeerId, Address>,
    operator_peers: HashMap<Address, PeerId>,
    fetcher: Fetcher<PeerId>,
    /// The read ticket each outbound blob batch request belongs to.
    requests: HashMap<OutboundRequestId, u64>,
    /// Outbound direct pairwise sends awaiting ack before optional gossipsub fallback.
    direct_pending: HashMap<OutboundRequestId, PendingPublish>,
    /// Publishes that found no peer on the topic yet.
    publishes: VecDeque<PendingPublish>,
    serving: Serving<InboundRequestId, Asked>,
    served_writer: mpsc::UnboundedSender<Served>,
    served: mpsc::UnboundedReceiver<Served>,
    stored_writer: mpsc::UnboundedSender<(u64, BatchStored)>,
    stored: mpsc::UnboundedReceiver<(u64, BatchStored)>,
    refused: Limited,
}

impl<S: BlobStore> Driver<S> {
    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        let mut dials = tokio::time::interval(DIAL_CHECK);
        let mut retry = tokio::time::interval(PUBLISH_RETRY);
        let mut peers = tokio::time::interval(PEER_CHECK);
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(Command::Publish { envelope, done }) => self.publish(envelope, done),
                    Some(Command::Fetch { message, done }) => self.fetch(message, done),
                    Some(Command::Close { done }) => {
                        self.drain().await;
                        let _ = done.send(());
                        return;
                    }
                    None => {
                        self.drain().await;
                        return;
                    }
                },
                event = self.swarm.select_next_some() => self.on_event(event),
                Some(served) = self.served.recv() => self.on_served(served),
                Some((read, stored)) = self.stored.recv() => self.on_stored(read, stored),
                _ = dials.tick() => self.dial_peers(),
                _ = retry.tick() => self.retry_publishes(),
                _ = peers.tick() => self.check_peers(),
            }
        }
    }

    /// Says goodbye to every peer and gives their connections a moment to close, so they do not
    /// have to time out.
    async fn drain(&mut self) {
        let peers: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
        for peer in peers {
            let _ = self.swarm.disconnect_peer_id(peer);
        }
        let deadline = Instant::now() + DRAIN;
        while Instant::now() < deadline {
            let event = self.swarm.select_next_some();
            if tokio::time::timeout(Duration::from_millis(100), event)
                .await
                .is_err()
            {
                break;
            }
        }
    }

    /// Dials the configured peers whose turn it is. Kademlia finds the others: it looks up the
    /// network whenever its routing table gains a peer, and connects to the peers it finds.
    fn dial_peers(&mut self) {
        let due = self.swarm.behaviour_mut().peers.due_dials(Instant::now());
        for address in due {
            if let Err(error) = self.swarm.dial(address.clone()) {
                debug!(%address, %error, "dialing a configured peer failed");
            }
        }
    }

    /// Drops the peers that did not identify in time or stayed connected without the network's
    /// topic, and fetches that have waited too long.
    fn check_peers(&mut self) {
        let now = Instant::now();
        let connected = self.swarm.connected_peers().count();
        self.connected.store(connected, Ordering::Relaxed);
        self.fetcher.expire(now);
        for peer in self.swarm.behaviour_mut().peers.unidentified(now) {
            debug!(%peer, "a peer did not identify in time");
            let _ = self.swarm.disconnect_peer_id(peer);
        }
        if self.messages {
            self.check_subscriptions(now);
        }
    }

    fn check_subscriptions(&mut self, now: Instant) {
        let topic = self.protocols.topic.hash();
        let subscribed: HashSet<PeerId> = self
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .filter(|(_, topics)| topics.contains(&&topic))
            .map(|(peer, _)| *peer)
            .collect();
        let stale = self
            .swarm
            .behaviour_mut()
            .peers
            .unsubscribed(&subscribed, now);
        for peer in stale {
            if self.swarm.disconnect_peer_id(peer).is_err() {
                continue;
            }
            let behaviour = self.swarm.behaviour_mut();
            behaviour.kademlia.remove_peer(&peer);
            let wait = behaviour.peers.disconnected_unsubscribed(peer, now);
            warn!(%peer, ?wait, "disconnected a peer that did not subscribe to the network's messages");
        }
    }

    fn record_verified_peer(&mut self, peer: PeerId, operator: Address) {
        if let Some(prev) = self.verified_peers.insert(peer, operator) {
            if prev != operator && self.operator_peers.get(&prev) == Some(&peer) {
                self.operator_peers.remove(&prev);
            }
        }
        self.operator_peers.insert(operator, peer);
    }

    fn forget_verified_peer(&mut self, peer: &PeerId) {
        if let Some(operator) = self.verified_peers.remove(peer) {
            if self.operator_peers.get(&operator) == Some(peer) {
                self.operator_peers.remove(&operator);
            }
        }
    }

    fn verify_peer_proof(&mut self, peer: PeerId, proof: &PeerProof) -> bool {
        if self.verified_peers.get(&peer) == Some(&proof.operator) {
            return true;
        }
        if proof.holds_for(&peer.to_bytes()) {
            self.record_verified_peer(peer, proof.operator);
            return true;
        }
        false
    }

    fn add_sources(&mut self, id: B256, candidates: impl IntoIterator<Item = PeerId>) {
        let book = &self.swarm.behaviour().peers;
        let filtered: Vec<PeerId> = candidates
            .into_iter()
            .filter(|peer| !book.takes_no_messages(peer))
            .collect();
        if filtered.is_empty() {
            return;
        }
        if let Some(existing) = self.sources.get_mut(&id) {
            for peer in filtered {
                if !existing.contains(&peer) && existing.len() < MAX_SOURCES_PER_MESSAGE {
                    existing.push(peer);
                }
            }
        } else {
            let mut peers = Vec::with_capacity(filtered.len().min(MAX_SOURCES_PER_MESSAGE));
            for peer in filtered {
                if !peers.contains(&peer) && peers.len() < MAX_SOURCES_PER_MESSAGE {
                    peers.push(peer);
                }
            }
            self.sources.insert(id, peers);
        }
    }

    fn publish(&mut self, envelope: Envelope, done: Done) {
        let bytes = envelope.encode();
        // Recipient-targeted messages (e.g. DKG shares) go directly over a single QUIC stream when
        // the recipient's peer ID is already known and connected, falling back to gossipsub on any
        // error or rejection.
        if let Some(recipient) = envelope.message.recipient() {
            if let Some(&peer) = self.operator_peers.get(&recipient) {
                if self.swarm.is_connected(&peer)
                    && !self
                        .swarm
                        .behaviour()
                        .peers
                        .is_rejected(&peer, Instant::now())
                {
                    let req = DirectMessage {
                        envelope: bytes.clone(),
                        sender_proof: self.proof.clone(),
                    };
                    let request_id = self.swarm.behaviour_mut().direct.send_request(&peer, req);
                    self.direct_pending.insert(
                        request_id,
                        PendingPublish {
                            bytes,
                            attempts: 0,
                            done,
                        },
                    );
                    return;
                }
            }
        }
        let pending = PendingPublish {
            bytes,
            attempts: 0,
            done,
        };
        self.try_publish(pending);
    }

    fn try_publish(&mut self, mut pending: PendingPublish) {
        // A caller that stopped waiting no longer owes this message.
        if pending.done.is_closed() {
            return;
        }
        let topic = self.protocols.topic.clone();
        let result = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, pending.bytes.clone());
        match result {
            Ok(_) => {
                self.stats.gossip_sent.fetch_add(1, Ordering::Relaxed);
                let _ = pending.done.send(Ok(()));
            }
            Err(PublishError::NoPeersSubscribedToTopic | PublishError::AllQueuesFull(_))
                if pending.attempts + 1 < PUBLISH_ATTEMPTS =>
            {
                pending.attempts += 1;
                self.publishes.push_back(pending);
            }
            Err(error) => {
                let _ = pending
                    .done
                    .send(Err(NetworkError::Publish(error.to_string())));
            }
        }
    }

    fn retry_publishes(&mut self) {
        for pending in std::mem::take(&mut self.publishes) {
            self.try_publish(pending);
        }
    }

    fn on_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            })) => self.on_gossip(propagation_source, message_id, message),
            SwarmEvent::Behaviour(BehaviourEvent::Blobs(event)) => self.on_blobs(event),
            SwarmEvent::Behaviour(BehaviourEvent::Direct(event)) => self.on_direct_event(event),
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => self.on_identify(peer_id, info),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                let now = Instant::now();
                let concrete = self.recent_dials.get(&peer_id);
                let peers = &mut self.swarm.behaviour_mut().peers;
                let address = endpoint.get_remote_address().clone();
                peers.established(peer_id, connection_id, address, concrete, now);
                if peers.is_rejected(&peer_id, now) {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                num_established,
                ..
            } => {
                self.swarm
                    .behaviour_mut()
                    .peers
                    .closed(peer_id, connection_id);
                if num_established == 0 {
                    self.forget_verified_peer(&peer_id);
                }
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id,
                error: DialError::WrongPeerId { obtained, address },
                ..
            } => self.on_wrong_peer(peer_id, obtained, address),
            SwarmEvent::IncomingConnectionError { error, .. } => self.on_incoming_error(error),
            _ => {}
        }
    }

    /// An address answered as a peer other than the one it was dialed for, so the address goes
    /// from that peer's routes. A peer that changed its identity is dialed under the new one,
    /// unless the operator named the identity the address must have.
    fn on_wrong_peer(&mut self, expected: Option<PeerId>, obtained: PeerId, address: Multiaddr) {
        let stale = strip_peer_id(address);
        let me = *self.swarm.local_peer_id();
        let behaviour = self.swarm.behaviour_mut();
        if let Some(expected) = expected {
            remove_address(&mut behaviour.kademlia, expected, &stale);
        }
        if obtained == me {
            return;
        }
        if behaviour.peers.rebind(&stale, obtained) {
            behaviour.kademlia.add_address(&obtained, stale.clone());
            let dial = DialOpts::peer_id(obtained).addresses(vec![stale]).build();
            if let Err(error) = self.swarm.dial(dial) {
                debug!(%obtained, %error, "dialing a peer under its new identity failed");
            }
        }
    }

    /// A refused connection the operator can act on is worth a line; a redundant connection, a
    /// limit doing its job, or an aborted handshake is not.
    fn on_incoming_error(&mut self, error: libp2p::swarm::ListenError) {
        let text = format!("{error}");
        let expected = text.contains("established connections per peer")
            || text.contains("address group")
            || text.contains("Local peer ID")
            || text.contains("aborted by peer");
        if expected {
            debug!(%text, "an incoming connection failed");
        } else if let Some(held_back) = self.refused.pass() {
            warn!(%text, held_back, "an incoming connection failed");
        }
    }

    /// Passes on every fresh envelope that opens and comes from an admitted sender, whoever it is
    /// for; queues the ones for this node, and remembers who sent each, to fetch its blobs from.
    /// Another sender's envelope, or an old copy, is ignored without blaming the peer that passed
    /// it on: a node whose chain reader is ahead may know an operator this one does not yet, and
    /// a clock may be off.
    fn on_gossip(&mut self, propagation: PeerId, id: MessageId, message: gossipsub::Message) {
        let envelope = Envelope::decode(&message.data);
        let fresh = envelope
            .as_ref()
            .is_some_and(|envelope| fresh(envelope.sent_at, unix_now()));
        let opened = envelope.and_then(Envelope::open);
        let admitted = fresh
            && opened
                .as_ref()
                .is_some_and(|opened| self.admission.borrow().senders.contains(&opened.sender));
        let acceptance = match (&opened, admitted) {
            (Some(_), true) => MessageAcceptance::Accept,
            (Some(_), false) => MessageAcceptance::Ignore,
            (None, _) => MessageAcceptance::Reject,
        };
        self.swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&id, &propagation, acceptance);
        let me = self.proof.operator;
        let Some(peer_message) = opened.filter(|opened| admitted && opened.is_for(me)) else {
            return;
        };
        // A bootstrap peer offers no blobs. Who carried a message does not matter otherwise: its
        // signature says who wrote it, and refusing the first copy would make the network's own
        // duplicate filter drop the honest copies behind it.
        let mut peers: Vec<PeerId> = message.source.into_iter().collect();
        if !peers.contains(&propagation) {
            peers.push(propagation);
        }
        self.add_sources(peer_message.id(), peers);
        let sender = peer_message.sender;
        if !self.inbox.push(peer_message, message.data.len() as u64) {
            if let Some(held_back) = self.refused.pass() {
                warn!(%sender, held_back, "the node's inbox has no room for this sender");
            }
        }
    }

    fn on_direct_event(&mut self, event: request_response::Event<DirectMessage, DirectAck>) {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => self.on_direct_request(peer, request, channel),
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                let Some(pending) = self.direct_pending.remove(&request_id) else {
                    return;
                };
                if response.0 {
                    self.stats.direct_sent.fetch_add(1, Ordering::Relaxed);
                    let _ = pending.done.send(Ok(()));
                } else {
                    self.try_publish(pending);
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(pending) = self.direct_pending.remove(&request_id) {
                    debug!(%error, "direct message send failed; falling back to gossipsub");
                    self.try_publish(pending);
                }
            }
            request_response::Event::ResponseSent { .. }
            | request_response::Event::InboundFailure { .. } => {}
        }
    }

    fn on_direct_request(
        &mut self,
        peer: PeerId,
        request: DirectMessage,
        channel: ResponseChannel<DirectAck>,
    ) {
        let DirectMessage {
            envelope: bytes,
            sender_proof,
        } = request;
        if !self.verify_peer_proof(peer, &sender_proof) {
            if let Some(held_back) = self.refused.pass() {
                let operator = sender_proof.operator;
                warn!(%peer, %operator, held_back, "a peer sent a direct message with an invalid identity proof");
            }
            let _ = self
                .swarm
                .behaviour_mut()
                .direct
                .send_response(channel, DirectAck(false));
            self.refuse(peer);
            return;
        }
        let wire_len = bytes.len() as u64;
        let envelope = Envelope::decode(&bytes);
        let is_fresh = envelope
            .as_ref()
            .is_some_and(|env| fresh(env.sent_at, unix_now()));
        let opened = envelope.and_then(Envelope::open);
        let me = self.proof.operator;
        let admitted = is_fresh
            && opened.as_ref().is_some_and(|msg| {
                msg.sender == sender_proof.operator
                    && self.admission.borrow().senders.contains(&msg.sender)
                    && msg.is_for(me)
            });
        let accepted = if admitted {
            let peer_message = opened.expect("admitted implies opened");
            self.add_sources(peer_message.id(), [peer]);
            let sender = peer_message.sender;
            let queued = self.inbox.push(peer_message, wire_len);
            if !queued {
                if let Some(held_back) = self.refused.pass() {
                    warn!(%sender, held_back, "the node's inbox has no room for this sender");
                }
            }
            queued
        } else {
            false
        };
        let _ = self
            .swarm
            .behaviour_mut()
            .direct
            .send_response(channel, DirectAck(accepted));
    }

    /// Fetches the blobs `message` names that the store lacks. A fetch already on its way for the
    /// same message answers this caller too.
    fn fetch(&mut self, message: PeerMessage, done: Done) {
        let id = message.id();
        let Some(done) = self.fetcher.join(&id, done) else {
            return;
        };
        // A message can name one blob many times; one read brings it.
        let named: BTreeSet<BlobRef> = message.blobs().into_iter().collect();
        let missing: Vec<BlobRef> = named
            .into_iter()
            .filter(|blob| !self.blobs.has(message.e3, blob))
            .collect();
        if missing.is_empty() {
            let _ = done.send(Ok(()));
            return;
        }
        let Some(mut peers) = self.sources.get(&id).cloned() else {
            let _ = done.send(Err(NetworkError::Unavailable));
            return;
        };
        if !missing.iter().all(|blob| blob.len <= MAX_BLOB_BYTES) {
            let _ = done.send(Err(NetworkError::Unavailable));
            return;
        }
        // Prefer the original publisher if its peer ID is already verified and connected.
        if let Some(&publisher) = self.operator_peers.get(&message.sender) {
            if !self.swarm.behaviour().peers.takes_no_messages(&publisher)
                && !peers.contains(&publisher)
            {
                peers.insert(0, publisher);
            }
        }
        let wanted = Wanted {
            message,
            missing,
            peers,
        };
        self.fetcher.add(wanted, done, Instant::now());
        self.start_reads();
    }

    fn start_reads(&mut self) {
        for read in self.fetcher.next_reads() {
            let hashes = read.blobs.iter().map(|blob| blob.hash).collect();
            let request = self.swarm.behaviour_mut().blobs.send_request(
                &read.peer,
                BlobBatchRequest {
                    e3: read.e3,
                    hashes,
                    requester: self.proof.clone(),
                },
            );
            self.stats
                .blob_batches_fetched
                .fetch_add(1, Ordering::Relaxed);
            self.requests.insert(request, read.ticket);
        }
    }

    fn on_blobs(&mut self, event: request_response::Event<BlobBatchRequest, BlobBatchResponse>) {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request_id,
                        request,
                        channel,
                    },
                ..
            } => self.on_asked(peer, request_id, request, channel),
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                let Some(read) = self.requests.remove(&request_id) else {
                    return;
                };
                self.store_batch(read, response);
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(read) = self.requests.remove(&request_id) {
                    debug!(%error, "a blob batch request failed");
                    self.fetcher.failed(read);
                    self.start_reads();
                }
            }
            request_response::Event::ResponseSent { request_id, .. }
            | request_response::Event::InboundFailure { request_id, .. } => {
                self.serving.end(request_id);
                self.serve_next();
            }
        }
    }

    /// Takes a peer's batched request for blobs. Only a member of the blobs' E3 gets an answer with
    /// bytes. The claim costs nothing to check, so it comes first; a peer that claims a member it
    /// cannot prove to be is dropped, so a false claim costs it a new identity and connection.
    fn on_asked(
        &mut self,
        peer: PeerId,
        request: InboundRequestId,
        asked: BlobBatchRequest,
        channel: ResponseChannel<BlobBatchResponse>,
    ) {
        let BlobBatchRequest {
            e3,
            hashes,
            requester,
        } = asked;
        let count = hashes.len();
        if !self.may_read(e3, requester.operator) {
            self.answer_nothing(channel, count);
            return;
        }
        if !self.verify_peer_proof(peer, &requester) {
            if let Some(held_back) = self.refused.pass() {
                let operator = requester.operator;
                warn!(%peer, %operator, held_back, "a peer claimed to be a member it cannot prove to be");
            }
            self.refuse(peer);
            return;
        }
        let member = requester.operator;
        let asked = Asked {
            e3,
            hashes,
            member,
            channel,
        };
        match self.serving.ask(request, member, asked) {
            Ok(()) => self.serve_next(),
            Err(Asked {
                channel, hashes, ..
            }) => self.answer_nothing(channel, hashes.len()),
        }
    }

    fn may_read(&self, e3: E3Id, operator: Address) -> bool {
        let admission = self.admission.borrow();
        admission
            .committees
            .get(&e3)
            .is_some_and(|committee| committee.contains(&operator))
    }

    fn answer_nothing(&mut self, channel: ResponseChannel<BlobBatchResponse>, count: usize) {
        let _ = self.swarm.behaviour_mut().blobs.send_response(
            channel,
            BlobBatchResponse {
                items: vec![None; count],
            },
        );
    }

    /// Starts the blob reads whose turn it is, off this task. A member can lose its seat while it
    /// waits in line, and then finds nothing.
    fn serve_next(&mut self) {
        while let Some((request, asked)) = self.serving.next_turn() {
            let Asked {
                e3,
                hashes,
                member,
                channel,
            } = asked;
            let readable = self.may_read(e3, member);
            let (blobs, served) = (self.blobs.clone(), self.served_writer.clone());
            self.stats
                .blob_batches_served
                .fetch_add(1, Ordering::Relaxed);
            tokio::task::spawn_blocking(move || {
                let items = if readable {
                    hashes
                        .into_iter()
                        .map(|hash| blobs.serve_shared(e3, &hash))
                        .collect()
                } else {
                    vec![None; hashes.len()]
                };
                let _ = served.send(Served {
                    request,
                    channel,
                    response: BlobBatchResponse { items },
                });
            });
        }
    }

    fn on_served(&mut self, served: Served) {
        let Served {
            request,
            channel,
            response,
        } = served;
        self.serving.read(request);
        let blobs = &mut self.swarm.behaviour_mut().blobs;
        if blobs.send_response(channel, response).is_err() {
            self.serving.end(request);
            self.serve_next();
        }
    }

    /// Checks and stores a batch of blobs off this task with a single directory sync.
    fn store_batch(&mut self, read: u64, response: BlobBatchResponse) {
        let Some((e3, expected)) = self.fetcher.expected(read) else {
            self.fetcher.failed(read);
            self.start_reads();
            return;
        };
        let (blobs, stored) = (self.blobs.clone(), self.stored_writer.clone());
        tokio::task::spawn_blocking(move || {
            if response.items.len() != expected.len() {
                let _ = stored.send((
                    read,
                    BatchStored::Done {
                        kept: 0,
                        retry: expected,
                    },
                ));
                return;
            }
            let mut valid: Vec<(BlobRef, Arc<[u8]>)> = Vec::with_capacity(expected.len());
            let mut retry: Vec<BlobRef> = Vec::new();
            for (want, got) in expected.into_iter().zip(response.items) {
                match got {
                    Some(bytes) if BlobRef::of(&bytes) == want => valid.push((want, bytes)),
                    _ => retry.push(want),
                }
            }
            let kept = valid.len();
            let outcome = if valid.is_empty() {
                BatchStored::Done { kept: 0, retry }
            } else {
                let slices: Vec<(&BlobRef, &[u8])> = valid
                    .iter()
                    .map(|(reference, bytes)| (reference, &bytes[..]))
                    .collect();
                match blobs.put_verified_batch(e3, &slices) {
                    Ok(_) => BatchStored::Done { kept, retry },
                    Err(error) => BatchStored::Failed(error.to_string()),
                }
            };
            let _ = stored.send((read, outcome));
        });
    }

    fn on_stored(&mut self, read: u64, stored: BatchStored) {
        match stored {
            BatchStored::Done { kept, retry } => self.fetcher.batch_done(read, kept, retry),
            BatchStored::Failed(error) => self.fetcher.abort(read, NetworkError::Store(error)),
        }
        self.start_reads();
    }

    /// Drops `peer`, and does not dial or keep it for a while.
    fn refuse(&mut self, peer: PeerId) {
        self.forget_verified_peer(&peer);
        let behaviour = self.swarm.behaviour_mut();
        behaviour.peers.reject(peer, Instant::now());
        behaviour.kademlia.remove_peer(&peer);
        let _ = self.swarm.disconnect_peer_id(peer);
    }

    /// A peer of another network or protocol version is dropped and not dialed for a while; a
    /// peer of this one becomes a routing entry at the addresses it listens on, which replace
    /// those it gave before, so a peer cannot make the node keep and dial addresses without end.
    fn on_identify(&mut self, peer: PeerId, info: identify::Info) {
        let standing = self.protocols.standing(&info);
        if standing == Standing::Refused {
            info!(%peer, version = %info.protocol_version, "refused a peer of another network");
            self.refuse(peer);
            return;
        }
        let behaviour = self.swarm.behaviour_mut();
        behaviour.inbound_ip_limits.identified(&peer);
        behaviour
            .peers
            .identified(peer, standing == Standing::Member);
        let live = behaviour.peers.live_addresses(&peer);
        let listeners: Vec<Multiaddr> = self.swarm.listeners().cloned().collect();
        let advertised = advertised(&listeners, info.listen_addrs, &live);
        let before = self.advertised.get(&peer).cloned().unwrap_or_default();
        let kademlia = &mut self.swarm.behaviour_mut().kademlia;
        let retired = before
            .iter()
            .filter(|address| !advertised.contains(address) && !live.contains(address));
        for address in retired {
            remove_address(kademlia, peer, address);
        }
        for address in &advertised {
            kademlia.add_address(&peer, address.clone());
        }
        self.advertised.insert(peer, advertised);
    }
}

/// Removes `address` from `peer`'s route. Kademlia can hold a dial endpoint without its peer ID,
/// and `remove_address` matches only the form it is given, so the entry is rebuilt.
fn remove_address(
    kademlia: &mut kad::Behaviour<kad::store::MemoryStore>,
    peer: PeerId,
    address: &Multiaddr,
) {
    let Some(entry) = kademlia.remove_peer(&peer) else {
        return;
    };
    for kept in entry.node.value.into_vec() {
        let kept = strip_peer_id(kept);
        if kept != *address {
            kademlia.add_address(&peer, kept);
        }
    }
}

/// Whether a copy sent at `sent_at` counts at `now`.
fn fresh(sent_at: u64, now: u64) -> bool {
    sent_at.saturating_add(MAX_COPY_AGE) >= now && sent_at <= now.saturating_add(MAX_CLOCK_AHEAD)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests;
