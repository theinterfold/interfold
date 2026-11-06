// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{inbound_ip_limits::InboundIpLimits, Network, NetworkError, SharedBlobs};
use alloy_primitives::{Address, B256};
use e3_protocol::{node::PeerMessage, wire::Envelope, BlobRef};
use futures::StreamExt;
use libp2p::{
    connection_limits::{self, ConnectionLimits},
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
    collections::{BTreeMap, HashMap, VecDeque},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

/// The largest envelope: proofs travel as blobs, so an envelope holds references and public inputs.
const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
/// The largest blob a peer may send, above the old document limit of 26 MiB.
const MAX_BLOB_BYTES: u64 = 32 * 1024 * 1024;
/// Messages that wait for blobs at once; past it a message is dropped and comes again with its
/// sender's re-send.
const MAX_WAITING: usize = 4_096;
/// Blob references a node serves: those of the messages it published or delivered lately.
const MAX_SERVABLE: usize = 65_536;
/// A publish waits this long for a peer on the topic, as a node that just started has none.
const PUBLISH_ATTEMPTS: u32 = 6;
const PUBLISH_RETRY: Duration = Duration::from_secs(5);
const REDIAL: Duration = Duration::from_secs(15);
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Peers to dial, each with its `/p2p/` identity, again whenever the connection drops.
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
    blobs: cbor::Behaviour<B256, Option<ByteBuf>>,
}

impl Behaviour {
    fn new(key: &Keypair, protocols: &Protocols) -> Result<Self, String> {
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
        gossipsub
            .subscribe(&protocols.topic)
            .map_err(|error| error.to_string())?;
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
    peer: PeerId,
    listening: Vec<Multiaddr>,
}

enum Command {
    Publish {
        envelope: Envelope,
        done: oneshot::Sender<Result<(), NetworkError>>,
    },
}

impl P2p {
    /// Joins the network as operator `me`. Peer messages for this node arrive on the returned
    /// receiver once the blobs it needs from them are in `blobs`.
    pub async fn start(
        config: P2pConfig,
        me: Address,
        blobs: SharedBlobs,
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
            .with_behaviour(|key| Behaviour::new(key, &protocols).map_err(Into::into))
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
        let mut driver = Driver {
            swarm,
            protocols,
            me,
            blobs,
            inbound,
            peers: config.peers,
            servable: Servable::default(),
            waiting: BTreeMap::new(),
            next_wait: 0,
            requests: HashMap::new(),
            publishes: VecDeque::new(),
        };
        driver.dial_peers();
        tokio::spawn(driver.run(command_receiver));
        let p2p = Self {
            commands,
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
}

/// A peer message that waits for blobs, and the peers to ask for them: the publisher first, then
/// the peer that forwarded the message.
struct Waiting {
    message: PeerMessage,
    missing: BTreeMap<B256, BlobRef>,
    peers: Vec<PeerId>,
}

/// The blob references a node serves, oldest dropped first.
#[derive(Default)]
struct Servable {
    blobs: HashMap<B256, BlobRef>,
    order: VecDeque<B256>,
}

impl Servable {
    fn insert(&mut self, blob: BlobRef) {
        if self.blobs.insert(blob.hash, blob).is_none() {
            self.order.push_back(blob.hash);
        }
        while self.order.len() > MAX_SERVABLE {
            if let Some(oldest) = self.order.pop_front() {
                self.blobs.remove(&oldest);
            }
        }
    }
}

struct PendingPublish {
    bytes: Vec<u8>,
    attempts: u32,
    done: oneshot::Sender<Result<(), NetworkError>>,
}

struct Driver {
    swarm: Swarm<Behaviour>,
    protocols: Protocols,
    me: Address,
    blobs: SharedBlobs,
    inbound: mpsc::Sender<PeerMessage>,
    peers: Vec<Multiaddr>,
    servable: Servable,
    waiting: BTreeMap<u64, Waiting>,
    next_wait: u64,
    /// The blob each request asks for, and the message waiting for it.
    requests: HashMap<OutboundRequestId, (u64, BlobRef, PeerId)>,
    /// Publishes that found no peer on the topic yet.
    publishes: VecDeque<PendingPublish>,
}

impl Driver {
    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        let mut redial = tokio::time::interval(REDIAL);
        let mut retry = tokio::time::interval(PUBLISH_RETRY);
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(Command::Publish { envelope, done }) => self.publish(envelope, done),
                    None => return,
                },
                event = self.swarm.select_next_some() => self.on_event(event),
                _ = redial.tick() => self.dial_peers(),
                _ = retry.tick() => self.retry_publishes(),
            }
        }
    }

    /// Dials the configured peers that are not connected, and looks for more peers.
    fn dial_peers(&mut self) {
        // Fails while the routing table is empty; the next round tries again.
        let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
        for address in self.peers.clone() {
            let Some(Protocol::P2p(peer)) = address.iter().last() else {
                warn!(%address, "a configured peer needs its /p2p/ identity");
                continue;
            };
            if !self.swarm.is_connected(&peer) {
                if let Err(error) = self.swarm.dial(address.clone()) {
                    debug!(%address, %error, "dialing a configured peer failed");
                }
            }
        }
    }

    fn publish(&mut self, envelope: Envelope, done: oneshot::Sender<Result<(), NetworkError>>) {
        for blob in envelope.message.blobs() {
            self.servable.insert(blob);
        }
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
            _ => {}
        }
    }

    /// Accepts for forwarding every envelope that opens, whoever it is for; delivers the ones for
    /// this node once their blobs are here.
    fn on_gossip(&mut self, propagation: PeerId, id: MessageId, message: gossipsub::Message) {
        let opened = Envelope::decode(&message.data).and_then(Envelope::open);
        let acceptance = match opened {
            Some(_) => MessageAcceptance::Accept,
            None => MessageAcceptance::Reject,
        };
        self.swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&id, &propagation, acceptance);
        let Some(peer_message) = opened.filter(|opened| opened.is_for(self.me)) else {
            return;
        };
        let missing: BTreeMap<B256, BlobRef> = peer_message
            .blobs()
            .into_iter()
            .filter(|blob| !self.blobs.has(blob))
            .map(|blob| (blob.hash, blob))
            .collect();
        if missing.is_empty() {
            self.deliver(peer_message);
            return;
        }
        if self.waiting.len() >= MAX_WAITING {
            warn!("too many messages wait for blobs; dropping one");
            return;
        }
        let mut peers: Vec<PeerId> = message.source.into_iter().collect();
        if !peers.contains(&propagation) {
            peers.push(propagation);
        }
        let wait = self.next_wait;
        self.next_wait += 1;
        let first = peers[0];
        for blob in missing.values() {
            self.request(wait, *blob, first);
        }
        let waiting = Waiting {
            message: peer_message,
            missing,
            peers,
        };
        self.waiting.insert(wait, waiting);
    }

    fn request(&mut self, wait: u64, blob: BlobRef, peer: PeerId) {
        let request = self
            .swarm
            .behaviour_mut()
            .blobs
            .send_request(&peer, blob.hash);
        self.requests.insert(request, (wait, blob, peer));
    }

    fn on_blobs(&mut self, event: request_response::Event<B256, Option<ByteBuf>>) {
        match event {
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let bytes = self
                    .servable
                    .blobs
                    .get(&request)
                    .and_then(|blob| self.blobs.get(blob).ok())
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
                let Some((wait, blob, peer)) = self.requests.remove(&request_id) else {
                    return;
                };
                let bytes = response.map(ByteBuf::into_vec);
                match bytes.filter(|bytes| BlobRef::of(bytes) == blob) {
                    Some(bytes) => self.received(wait, blob, &bytes),
                    None => self.ask_next(wait, blob, peer),
                }
            }
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some((wait, blob, peer)) = self.requests.remove(&request_id) {
                    debug!(%peer, %error, "a blob request failed");
                    self.ask_next(wait, blob, peer);
                }
            }
            _ => {}
        }
    }

    fn received(&mut self, wait: u64, blob: BlobRef, bytes: &[u8]) {
        if let Err(error) = self.blobs.put(bytes) {
            warn!(%error, "storing a peer's blob failed");
            self.waiting.remove(&wait);
            return;
        }
        let Some(waiting) = self.waiting.get_mut(&wait) else {
            return;
        };
        waiting.missing.remove(&blob.hash);
        if waiting.missing.is_empty() {
            let waiting = self.waiting.remove(&wait).expect("the message waits");
            self.deliver(waiting.message);
        }
    }

    /// Asks the next peer for a blob that `asked` could not give, or drops the message: its
    /// sender's re-send brings it again.
    fn ask_next(&mut self, wait: u64, blob: BlobRef, asked: PeerId) {
        let Some(waiting) = self.waiting.get(&wait) else {
            return;
        };
        let next = waiting
            .peers
            .iter()
            .skip_while(|peer| **peer != asked)
            .nth(1)
            .copied();
        match next {
            Some(peer) => self.request(wait, blob, peer),
            None => {
                debug!(e3 = %waiting.message.e3, "no peer had a message's blob");
                self.waiting.remove(&wait);
            }
        }
    }

    fn deliver(&mut self, message: PeerMessage) {
        for blob in message.blobs() {
            self.servable.insert(blob);
        }
        if self.inbound.try_send(message).is_err() {
            warn!("the node is not taking peer messages; dropping one");
        }
    }

    /// A peer of another network or protocol version is dropped; a peer of this one becomes a
    /// routing entry at the addresses it listens on.
    fn on_identify(&mut self, peer: PeerId, info: identify::Info) {
        if info.protocol_version != self.protocols.identify {
            let _ = self.swarm.disconnect_peer_id(peer);
            return;
        }
        let kademlia = &mut self.swarm.behaviour_mut().kademlia;
        for address in info.listen_addrs.into_iter().take(8) {
            kademlia.add_address(&peer, address);
        }
    }
}

#[cfg(test)]
mod tests;
