// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The node's place on the network: one task owns the swarm, and everything else talks to it
//! through commands that never wait. Disk reads and writes run off that task.

use crate::{
    behaviour::{Behaviour, BehaviourEvent, IDLE_CONNECTION, MAX_BLOB_BYTES},
    fetcher::{Done, Fetcher, Wanted},
    inbox::{inbox, Inbox, InboxWriter},
    peers::{advertised, strip_peer_id, PeerBook},
    protocols::{Protocols, Standing},
    serving::{BlobRequest, Serving},
    transport::{DialGuard, RecentDials},
    Network, NetworkError,
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
use serde_bytes::ByteBuf;
use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
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
        let mut driver = Driver {
            connected: connected.clone(),
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
            fetcher: Fetcher::default(),
            requests: HashMap::new(),
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
}

struct PendingPublish {
    bytes: Vec<u8>,
    attempts: u32,
    done: Done,
}

/// A member's request for a blob, on its way through the line.
struct Asked {
    e3: E3Id,
    hash: B256,
    member: Address,
    channel: ResponseChannel<Option<ByteBuf>>,
}

/// A blob read for a member, ready to send.
struct Served {
    request: InboundRequestId,
    channel: ResponseChannel<Option<ByteBuf>>,
    bytes: Option<ByteBuf>,
}

/// What became of a blob that arrived.
enum Stored {
    Kept,
    /// The bytes were not the blob's: another peer may have the real ones.
    Wrong,
    Failed(String),
}

struct Driver<S> {
    connected: Arc<AtomicUsize>,
    swarm: Swarm<Behaviour>,
    protocols: Protocols,
    /// Whether the node takes part in the network's messages; a bootstrap node does not.
    messages: bool,
    /// The operator this node is, and its word for it, which every blob request shows.
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
    fetcher: Fetcher<PeerId>,
    /// The read each request belongs to.
    requests: HashMap<OutboundRequestId, u64>,
    /// Publishes that found no peer on the topic yet.
    publishes: VecDeque<PendingPublish>,
    serving: Serving<InboundRequestId, Asked>,
    served_writer: mpsc::UnboundedSender<Served>,
    served: mpsc::UnboundedReceiver<Served>,
    stored_writer: mpsc::UnboundedSender<(u64, Stored)>,
    stored: mpsc::UnboundedReceiver<(u64, Stored)>,
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

    fn publish(&mut self, envelope: Envelope, done: Done) {
        let pending = PendingPublish {
            bytes: envelope.encode(),
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
                ..
            } => self
                .swarm
                .behaviour_mut()
                .peers
                .closed(peer_id, connection_id),
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
        let mut peers: Vec<PeerId> = message.source.into_iter().collect();
        if !peers.contains(&propagation) {
            peers.push(propagation);
        }
        // A bootstrap peer offers no blobs. Who carried a message does not matter otherwise: its
        // signature says who wrote it, and refusing the first copy would make the network's own
        // duplicate filter drop the honest copies behind it.
        let book = &self.swarm.behaviour().peers;
        peers.retain(|peer| !book.takes_no_messages(peer));
        if !peers.is_empty() {
            self.sources.insert(peer_message.id(), peers);
        }
        let sender = peer_message.sender;
        if !self.inbox.push(peer_message, message.data.len() as u64) {
            if let Some(held_back) = self.refused.pass() {
                warn!(%sender, held_back, "the node's inbox has no room for this sender");
            }
        }
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
        let (Some(peers), true) = (
            self.sources.get(&id).cloned(),
            missing.iter().all(|blob| blob.len <= MAX_BLOB_BYTES),
        ) else {
            let _ = done.send(Err(NetworkError::Unavailable));
            return;
        };
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
            let request = self.swarm.behaviour_mut().blobs.send_request(
                &read.peer,
                BlobRequest {
                    e3: read.e3,
                    hash: read.hash,
                    requester: self.proof.clone(),
                },
            );
            self.requests.insert(request, read.ticket);
        }
    }

    fn on_blobs(&mut self, event: request_response::Event<BlobRequest, Option<ByteBuf>>) {
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
                match response {
                    Some(bytes) => self.store(read, bytes.into_vec()),
                    None => {
                        self.fetcher.failed(read);
                        self.start_reads();
                    }
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(read) = self.requests.remove(&request_id) {
                    debug!(%error, "a blob request failed");
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

    /// Takes a peer's request for a blob. Only a member of the blob's E3 gets an answer with
    /// bytes. The claim costs nothing to check, so it comes first; a peer that claims a member it
    /// cannot prove to be is dropped, so a false claim costs it a new identity and connection.
    fn on_asked(
        &mut self,
        peer: PeerId,
        request: InboundRequestId,
        asked: BlobRequest,
        channel: ResponseChannel<Option<ByteBuf>>,
    ) {
        let BlobRequest {
            e3,
            hash,
            requester,
        } = asked;
        if !self.may_read(e3, requester.operator) {
            self.answer_nothing(channel);
            return;
        }
        if !requester.holds_for(&peer.to_bytes()) {
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
            hash,
            member,
            channel,
        };
        match self.serving.ask(request, member, asked) {
            Ok(()) => self.serve_next(),
            Err(Asked { channel, .. }) => self.answer_nothing(channel),
        }
    }

    fn may_read(&self, e3: E3Id, operator: Address) -> bool {
        let admission = self.admission.borrow();
        admission
            .committees
            .get(&e3)
            .is_some_and(|committee| committee.contains(&operator))
    }

    fn answer_nothing(&mut self, channel: ResponseChannel<Option<ByteBuf>>) {
        let _ = self
            .swarm
            .behaviour_mut()
            .blobs
            .send_response(channel, None);
    }

    /// Starts the disk reads whose turn it is, off this task. A member can lose its seat while it
    /// waits in line, and then finds nothing.
    fn serve_next(&mut self) {
        while let Some((request, asked)) = self.serving.next_turn() {
            let Asked {
                e3,
                hash,
                member,
                channel,
            } = asked;
            let readable = self.may_read(e3, member);
            let (blobs, served) = (self.blobs.clone(), self.served_writer.clone());
            tokio::task::spawn_blocking(move || {
                let bytes = readable
                    .then(|| blobs.serve(e3, &hash))
                    .flatten()
                    .map(ByteBuf::from);
                let _ = served.send(Served {
                    request,
                    channel,
                    bytes,
                });
            });
        }
    }

    fn on_served(&mut self, served: Served) {
        let Served {
            request,
            channel,
            bytes,
        } = served;
        self.serving.read(request);
        let blobs = &mut self.swarm.behaviour_mut().blobs;
        if blobs.send_response(channel, bytes).is_err() {
            self.serving.end(request);
            self.serve_next();
        }
    }

    /// Checks and stores a blob off this task. A fetch that ended keeps nothing.
    fn store(&mut self, read: u64, bytes: Vec<u8>) {
        let Some((e3, blob)) = self.fetcher.expected(read) else {
            self.fetcher.failed(read);
            self.start_reads();
            return;
        };
        let (blobs, stored) = (self.blobs.clone(), self.stored_writer.clone());
        tokio::task::spawn_blocking(move || {
            let outcome = if BlobRef::of(&bytes) != blob {
                Stored::Wrong
            } else {
                match blobs.put(e3, &bytes) {
                    Ok(_) => Stored::Kept,
                    Err(error) => Stored::Failed(error.to_string()),
                }
            };
            let _ = stored.send((read, outcome));
        });
    }

    fn on_stored(&mut self, read: u64, stored: Stored) {
        match stored {
            Stored::Kept => self.fetcher.stored(read),
            Stored::Wrong => self.fetcher.failed(read),
            Stored::Failed(error) => self.fetcher.abort(read, NetworkError::Store(error)),
        }
        self.start_reads();
    }

    /// Drops `peer`, and does not dial or keep it for a while.
    fn refuse(&mut self, peer: PeerId) {
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
