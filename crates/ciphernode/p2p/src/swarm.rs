// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{inbound_ip_limits::InboundIpLimits, Network, NetworkError};
use alloy_primitives::{Address, B256};
use e3_blobs::{BlobStore, MemoryBlobs};
use e3_protocol::{node::PeerMessage, wire::Envelope, BlobRef, E3Id};
use futures::StreamExt;
use libp2p::{
    connection_limits::{self, ConnectionLimits},
    core::ConnectedPoint,
    gossipsub::{self, IdentTopic, MessageAcceptance, MessageId, PublishError},
    identify,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    multiaddr::Protocol,
    request_response::{self, cbor, OutboundRequestId, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Swarm,
};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, warn};

/// The largest envelope: proofs travel as blobs, so an envelope holds references and public inputs.
const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
/// The largest blob a peer may send, above the old document limit of 26 MiB.
const MAX_BLOB_BYTES: u64 = 32 * 1024 * 1024;
/// Messages whose blobs are on their way at once, and their bytes; past either, a fetch fails and
/// the sender's re-send brings the message again.
const MAX_FETCHING: usize = 4_096;
const MAX_FETCHING_BYTES: u64 = 1024 * 1024 * 1024;
/// Blob references a node serves: those of the messages it published or fetched lately.
const MAX_SERVABLE: usize = 65_536;
/// Messages whose senders a node remembers, to fetch their blobs from.
const MAX_SOURCES: usize = 4_096;
/// A publish waits this long for a peer on the topic, as a node that just started has none.
const PUBLISH_ATTEMPTS: u32 = 6;
const PUBLISH_RETRY: Duration = Duration::from_secs(5);
const REDIAL: Duration = Duration::from_secs(15);
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);
/// A copy counts from `MAX_COPY_AGE` seconds before this node's clock to `MAX_CLOCK_AHEAD` after
/// it. Every send and re-send signs a new copy, so an older one is a replay, which gossip's
/// duplicate cache stops for only a minute.
const MAX_COPY_AGE: u64 = 10 * 60;
const MAX_CLOCK_AHEAD: u64 = 2 * 60;

/// How a node joins its network.
#[derive(Clone, Debug)]
pub struct P2pConfig {
    /// The ed25519 secret of the node's network identity, which peers address it by.
    pub identity: [u8; 32],
    /// Nodes of different networks, or of releases with different protocol versions, never share
    /// a topic or a protocol.
    pub network: String,
    pub protocol_version: u32,
    pub listen: Vec<Multiaddr>,
    /// Peers to dial, again whenever the connection drops. One without its `/p2p/` identity is
    /// dialed by address until a connection shows which peer it is.
    pub peers: Vec<Multiaddr>,
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

/// The protocol names of one network and protocol version.
struct Protocols {
    topic: IdentTopic,
    identify: String,
    kademlia: StreamProtocol,
    blobs: StreamProtocol,
}

impl Protocols {
    fn new(network: &str, protocol_version: u32) -> Self {
        let prefix = format!("interfold/{network}/protocol/{protocol_version}");
        let stream = |name: &str| {
            StreamProtocol::try_from_owned(format!("/{prefix}/{name}"))
                .expect("a protocol name starts with a slash")
        };
        Self {
            topic: IdentTopic::new(format!("{prefix}/messages/2")),
            identify: format!("/{prefix}/identify/2"),
            kademlia: stream("kad/1.0.0"),
            blobs: stream("blobs/1"),
        }
    }
}

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    /// Before the behaviours that prepare an inbound connection, so a refused one costs nothing.
    inbound_ip_limits: InboundIpLimits,
    connection_limits: connection_limits::Behaviour,
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
    /// A request names the blob's E3 and hash: each E3 keeps its own copy of its blobs.
    blobs: cbor::Behaviour<(E3Id, B256), Option<ByteBuf>>,
}

impl Behaviour {
    /// A node that takes no part in the network's `messages` does not subscribe to their topic, so
    /// peers keep it out of their message mesh.
    fn new(key: &Keypair, protocols: &Protocols, messages: bool) -> Result<Self, String> {
        let peer = key.public().to_peer_id();
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            // The library's tick-based defaults (history, gossip windows) assume one second.
            .heartbeat_interval(Duration::from_secs(1))
            .max_transmit_size(MAX_ENVELOPE_BYTES)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .validate_messages()
            .message_id_fn(|message| MessageId::from(Sha256::digest(&message.data).to_vec()))
            .build()
            .map_err(|error| error.to_string())?;
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(key.clone()),
            gossipsub_config,
        )
        .map_err(str::to_owned)?;
        if messages {
            gossipsub
                .subscribe(&protocols.topic)
                .map_err(|error| error.to_string())?;
        }
        let mut kademlia_config = kad::Config::new(protocols.kademlia.clone());
        // Routing entries come only from peers that identify on this network and version.
        kademlia_config.set_kbucket_inserts(kad::BucketInserts::Manual);
        let mut kademlia =
            kad::Behaviour::with_config(peer, MemoryStore::new(peer), kademlia_config);
        kademlia.set_mode(Some(kad::Mode::Server));
        let codec = cbor::codec::Codec::default().set_response_size_maximum(MAX_BLOB_BYTES);
        Ok(Self {
            inbound_ip_limits: InboundIpLimits::default(),
            connection_limits: connection_limits::Behaviour::new(
                ConnectionLimits::default()
                    .with_max_pending_incoming(Some(64))
                    .with_max_pending_outgoing(Some(64))
                    .with_max_established_incoming(Some(80))
                    .with_max_established_outgoing(Some(64))
                    .with_max_established_per_peer(Some(2))
                    .with_max_established(Some(128)),
            ),
            gossipsub,
            identify: identify::Behaviour::new(
                identify::Config::new(protocols.identify.clone(), key.public())
                    .with_agent_version(format!("interfold-node/{}", env!("CARGO_PKG_VERSION"))),
            ),
            kademlia,
            blobs: cbor::Behaviour::with_codec(
                codec,
                [(protocols.blobs.clone(), ProtocolSupport::Full)],
                request_response::Config::default().with_request_timeout(Duration::from_secs(60)),
            ),
        })
    }
}

/// The node's place on the peer-to-peer network.
pub struct P2p {
    commands: mpsc::Sender<Command>,
    admitted: watch::Sender<BTreeSet<Address>>,
    peer: PeerId,
    listening: Vec<Multiaddr>,
}

type Done = oneshot::Sender<Result<(), NetworkError>>;

enum Command {
    Publish { envelope: Envelope, done: Done },
    Fetch { message: PeerMessage, done: Done },
}

impl P2p {
    /// Joins the network as operator `me`. Peer messages for this node arrive on the returned
    /// receiver as their envelopes open; `fetch` brings their blobs into `blobs`.
    pub async fn start(
        config: P2pConfig,
        me: Address,
        blobs: impl BlobStore,
    ) -> Result<(Self, mpsc::Receiver<PeerMessage>), P2pError> {
        Self::join(config, true, me, blobs).await
    }

    /// Joins the network only to help peers find each other: the node answers their lookups and
    /// takes no part in their messages.
    pub async fn bootstrap(config: P2pConfig) -> Result<Self, P2pError> {
        let (p2p, _) = Self::join(config, false, Address::ZERO, MemoryBlobs::default()).await?;
        Ok(p2p)
    }

    async fn join(
        config: P2pConfig,
        messages: bool,
        me: Address,
        blobs: impl BlobStore,
    ) -> Result<(Self, mpsc::Receiver<PeerMessage>), P2pError> {
        let key = Keypair::ed25519_from_bytes(config.identity)
            .map_err(|error| P2pError::Identity(error.to_string()))?;
        let peer = key.public().to_peer_id();
        let protocols = Protocols::new(&config.network, config.protocol_version);
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_quic()
            .with_dns()
            .map_err(|error| P2pError::Transport(error.to_string()))?
            .with_behaviour(|key| Behaviour::new(key, &protocols, messages).map_err(Into::into))
            .map_err(|error| P2pError::Transport(error.to_string()))?
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(60))
            })
            .build();
        for address in &config.listen {
            swarm
                .listen_on(address.clone())
                .map_err(|error| P2pError::Listen(address.clone(), error.to_string()))?;
        }
        let listening = tokio::time::timeout(LISTEN_TIMEOUT, async {
            let mut listening = Vec::new();
            while listening.len() < config.listen.len() {
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
        .map_err(|_| P2pError::Listen(Multiaddr::empty(), "no address in time".into()))??;
        let (inbound, receiver) = mpsc::channel(1_024);
        let (commands, command_receiver) = mpsc::channel(1_024);
        let (admitted, senders) = watch::channel(BTreeSet::new());
        let mut driver = Driver {
            swarm,
            protocols,
            me,
            blobs,
            inbound,
            senders,
            peers: config.peers,
            reached: HashMap::new(),
            servable: Recent::default(),
            sources: Recent::default(),
            fetching: BTreeMap::new(),
            fetch_of: HashMap::new(),
            fetching_bytes: 0,
            next_fetch: 0,
            requests: HashMap::new(),
            publishes: VecDeque::new(),
        };
        driver.dial_peers();
        tokio::spawn(driver.run(command_receiver));
        let p2p = Self {
            commands,
            admitted,
            peer,
            listening,
        };
        Ok((p2p, receiver))
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer
    }

    /// The addresses peers can dial this node at.
    pub fn listening(&self) -> &[Multiaddr] {
        &self.listening
    }
}

impl Network for P2p {
    async fn publish(&self, envelope: Envelope) -> Result<(), NetworkError> {
        let (done, result) = oneshot::channel();
        self.commands
            .send(Command::Publish { envelope, done })
            .await
            .map_err(|_| NetworkError::Stopped)?;
        result.await.map_err(|_| NetworkError::Stopped)?
    }

    async fn fetch(&self, message: PeerMessage) -> Result<(), NetworkError> {
        let (done, result) = oneshot::channel();
        self.commands
            .send(Command::Fetch { message, done })
            .await
            .map_err(|_| NetworkError::Stopped)?;
        result.await.map_err(|_| NetworkError::Stopped)?
    }

    fn admit(&self, senders: BTreeSet<Address>) {
        self.admitted.send_replace(senders);
    }
}

/// The blobs of one message on their way, the peers to ask for them (the publisher first, then the
/// peer that forwarded the message), and the callers that wait for them.
struct Fetching {
    id: B256,
    message: PeerMessage,
    missing: BTreeMap<B256, BlobRef>,
    peers: Vec<PeerId>,
    bytes: u64,
    done: Vec<Done>,
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
}

struct PendingPublish {
    bytes: Vec<u8>,
    attempts: u32,
    done: oneshot::Sender<Result<(), NetworkError>>,
}

struct Driver<S> {
    swarm: Swarm<Behaviour>,
    protocols: Protocols,
    me: Address,
    blobs: S,
    inbound: mpsc::Sender<PeerMessage>,
    /// The operators whose messages the node takes.
    senders: watch::Receiver<BTreeSet<Address>>,
    peers: Vec<Multiaddr>,
    /// The peer at each configured address without a `/p2p/` identity, once a connection to the
    /// address showed it.
    reached: HashMap<Multiaddr, PeerId>,
    /// The blobs this node serves, with their E3s, by hash.
    servable: Recent<(E3Id, B256), BlobRef, MAX_SERVABLE>,
    /// The peers that sent each message, by its ID.
    sources: Recent<B256, Vec<PeerId>, MAX_SOURCES>,
    fetching: BTreeMap<u64, Fetching>,
    /// The fetch on its way for each message, by its ID.
    fetch_of: HashMap<B256, u64>,
    fetching_bytes: u64,
    next_fetch: u64,
    /// The blob each request asks for, and the fetch waiting for it.
    requests: HashMap<OutboundRequestId, (u64, BlobRef, PeerId)>,
    /// Publishes that found no peer on the topic yet.
    publishes: VecDeque<PendingPublish>,
}

impl<S: BlobStore> Driver<S> {
    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        let mut redial = tokio::time::interval(REDIAL);
        let mut retry = tokio::time::interval(PUBLISH_RETRY);
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(Command::Publish { envelope, done }) => self.publish(envelope, done),
                    Some(Command::Fetch { message, done }) => self.fetch(message, done),
                    None => return,
                },
                event = self.swarm.select_next_some() => self.on_event(event),
                _ = redial.tick() => self.dial_peers(),
                _ = retry.tick() => self.retry_publishes(),
            }
        }
    }

    /// Dials the configured peers that are not connected. Kademlia finds the others: it looks
    /// up the network whenever its routing table gains a peer, and connects to the peers it finds.
    fn dial_peers(&mut self) {
        for address in self.peers.clone() {
            let peer = match address.iter().last() {
                Some(Protocol::P2p(peer)) => Some(peer),
                _ => self.reached.get(&address).copied(),
            };
            if peer.is_some_and(|peer| self.swarm.is_connected(&peer)) {
                continue;
            }
            if let Err(error) = self.swarm.dial(address.clone()) {
                debug!(%address, %error, "dialing a configured peer failed");
            }
        }
    }

    fn publish(&mut self, envelope: Envelope, done: Done) {
        self.serve(&envelope.message);
        let pending = PendingPublish {
            bytes: envelope.encode(),
            attempts: 0,
            done,
        };
        self.try_publish(pending);
    }

    fn try_publish(&mut self, mut pending: PendingPublish) {
        let topic = self.protocols.topic.clone();
        let result = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, pending.bytes.clone());
        match result {
            Ok(_) => {
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
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => self.on_identify(peer_id, info),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint: ConnectedPoint::Dialer { address, .. },
                ..
            } => {
                let bare: Multiaddr = address
                    .iter()
                    .filter(|protocol| !matches!(protocol, Protocol::P2p(_)))
                    .collect();
                if self.peers.contains(&bare) {
                    self.reached.insert(bare, peer_id);
                }
            }
            _ => {}
        }
    }

    /// Passes on every fresh envelope that opens and comes from an admitted sender, whoever it is
    /// for; delivers the ones for this node at once, and remembers who sent each, to fetch its
    /// blobs from. Another sender's envelope, or an old copy, is ignored without blaming the peer
    /// that passed it on: a node whose chain reader is ahead may know an operator this one does
    /// not yet, and a clock may be off.
    fn on_gossip(&mut self, propagation: PeerId, id: MessageId, message: gossipsub::Message) {
        let envelope = Envelope::decode(&message.data);
        let fresh = envelope
            .as_ref()
            .is_some_and(|envelope| fresh(envelope.sent_at, unix_now()));
        let opened = envelope.and_then(Envelope::open);
        let admitted = fresh
            && opened
                .as_ref()
                .is_some_and(|opened| self.senders.borrow().contains(&opened.sender));
        let acceptance = match (&opened, admitted) {
            (Some(_), true) => MessageAcceptance::Accept,
            (Some(_), false) => MessageAcceptance::Ignore,
            (None, _) => MessageAcceptance::Reject,
        };
        self.swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&id, &propagation, acceptance);
        let Some(peer_message) = opened.filter(|opened| admitted && opened.is_for(self.me)) else {
            return;
        };
        let mut peers: Vec<PeerId> = message.source.into_iter().collect();
        if !peers.contains(&propagation) {
            peers.push(propagation);
        }
        self.sources.insert(peer_message.id(), peers);
        if self.inbound.try_send(peer_message).is_err() {
            warn!("the node is not taking peer messages; dropping one");
        }
    }

    /// Fetches the blobs `message` names that the store lacks. A fetch already on its way for the
    /// same message answers this caller too.
    fn fetch(&mut self, message: PeerMessage, done: Done) {
        let id = message.id();
        if let Some(fetching) = self
            .fetch_of
            .get(&id)
            .and_then(|fetch| self.fetching.get_mut(fetch))
        {
            fetching.done.push(done);
            return;
        }
        let missing: BTreeMap<B256, BlobRef> = message
            .blobs()
            .into_iter()
            .filter(|blob| !self.blobs.has(message.e3, blob))
            .map(|blob| (blob.hash, blob))
            .collect();
        if missing.is_empty() {
            self.serve(&message);
            let _ = done.send(Ok(()));
            return;
        }
        let bytes = missing
            .values()
            .fold(0u64, |sum, blob| sum.saturating_add(blob.len));
        let (Some(peers), true) = (
            self.sources.get(&id).cloned(),
            missing.values().all(|blob| blob.len <= MAX_BLOB_BYTES),
        ) else {
            let _ = done.send(Err(NetworkError::Unavailable));
            return;
        };
        if self.fetching.len() >= MAX_FETCHING
            || self.fetching_bytes.saturating_add(bytes) > MAX_FETCHING_BYTES
        {
            let _ = done.send(Err(NetworkError::Busy));
            return;
        }
        let fetch = self.next_fetch;
        self.next_fetch += 1;
        let (first, blobs) = (peers[0], missing.clone());
        self.fetching_bytes += bytes;
        self.fetch_of.insert(id, fetch);
        let fetching = Fetching {
            id,
            message,
            missing,
            peers,
            bytes,
            done: vec![done],
        };
        self.fetching.insert(fetch, fetching);
        for blob in blobs.into_values() {
            self.request(fetch, blob, first);
        }
    }

    fn request(&mut self, fetch: u64, blob: BlobRef, peer: PeerId) {
        let e3 = self.fetching[&fetch].message.e3;
        let request = self
            .swarm
            .behaviour_mut()
            .blobs
            .send_request(&peer, (e3, blob.hash));
        self.requests.insert(request, (fetch, blob, peer));
    }

    fn on_blobs(&mut self, event: request_response::Event<(E3Id, B256), Option<ByteBuf>>) {
        match event {
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let (e3, _) = request;
                let bytes = self
                    .servable
                    .get(&request)
                    .and_then(|blob| self.blobs.get(e3, blob).ok())
                    .map(ByteBuf::from);
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .blobs
                    .send_response(channel, bytes);
            }
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                let Some((fetch, blob, peer)) = self.requests.remove(&request_id) else {
                    return;
                };
                let bytes = response.map(ByteBuf::into_vec);
                match bytes.filter(|bytes| BlobRef::of(bytes) == blob) {
                    Some(bytes) => self.received(fetch, blob, &bytes),
                    None => self.ask_next(fetch, blob, peer),
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some((fetch, blob, peer)) = self.requests.remove(&request_id) {
                    debug!(%peer, %error, "a blob request failed");
                    self.ask_next(fetch, blob, peer);
                }
            }
            _ => {}
        }
    }

    /// Stores a blob of a fetch still on its way; a fetch that ended keeps nothing.
    fn received(&mut self, fetch: u64, blob: BlobRef, bytes: &[u8]) {
        if !self.fetching.contains_key(&fetch) {
            return;
        }
        let e3 = self.fetching[&fetch].message.e3;
        if let Err(error) = self.blobs.put(e3, bytes) {
            self.finish(fetch, Err(NetworkError::Store(error.to_string())));
            return;
        }
        let fetching = self
            .fetching
            .get_mut(&fetch)
            .expect("the fetch is on its way");
        fetching.missing.remove(&blob.hash);
        if fetching.missing.is_empty() {
            self.finish(fetch, Ok(()));
        }
    }

    /// Asks the next peer for a blob that `asked` could not give, or ends the fetch.
    fn ask_next(&mut self, fetch: u64, blob: BlobRef, asked: PeerId) {
        let Some(fetching) = self.fetching.get(&fetch) else {
            return;
        };
        let next = fetching
            .peers
            .iter()
            .skip_while(|peer| **peer != asked)
            .nth(1)
            .copied();
        match next {
            Some(peer) => self.request(fetch, blob, peer),
            None => self.finish(fetch, Err(NetworkError::Unavailable)),
        }
    }

    fn finish(&mut self, fetch: u64, result: Result<(), NetworkError>) {
        let Some(fetching) = self.fetching.remove(&fetch) else {
            return;
        };
        self.fetch_of.remove(&fetching.id);
        self.fetching_bytes -= fetching.bytes;
        if result.is_ok() {
            self.serve(&fetching.message);
        }
        for done in fetching.done {
            let _ = done.send(result.clone());
        }
    }

    fn serve(&mut self, message: &PeerMessage) {
        for blob in message.blobs() {
            self.servable.insert((message.e3, blob.hash), blob);
        }
    }

    /// A peer of another network or protocol version is dropped; a peer of this one becomes a
    /// routing entry at the addresses it listens on.
    fn on_identify(&mut self, peer: PeerId, info: identify::Info) {
        if info.protocol_version != self.protocols.identify {
            let _ = self.swarm.disconnect_peer_id(peer);
            return;
        }
        let listeners: Vec<Multiaddr> = self.swarm.listeners().cloned().collect();
        let kademlia = &mut self.swarm.behaviour_mut().kademlia;
        for address in routable(&listeners, info.listen_addrs).take(8) {
            kademlia.add_address(&peer, address);
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

/// The addresses a peer gave that the node shares through Kademlia. A loopback address reaches
/// the peer only from its own host, so a node that other hosts reach drops it: Kademlia would hand
/// it to remote peers, which then dial themselves. Nodes that listen only on loopback share one
/// host and keep it.
fn routable(listeners: &[Multiaddr], given: Vec<Multiaddr>) -> impl Iterator<Item = Multiaddr> {
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

#[cfg(test)]
mod tests;
