// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::net_interface_handle::NetEventSubscriber;
use crate::{
    direct_responder::DirectResponder,
    domain::wire::{decode, MAX_GOSSIP_BYTES},
    ContentHash,
};
use actix::Message;
use anyhow::{anyhow, bail, Context, Result};
use derivative::Derivative;
use e3_events::{
    CorrelationId, DocumentMeta, EventContextAccessors, EventSource, InterfoldEvent, Sequenced,
    Unsequenced,
};
use e3_utils::{ArcBytes, OnceTake};
use libp2p::{
    gossipsub::{MessageId, PublishError, TopicHash},
    kad::{store, GetRecordError, PutRecordError},
    request_response::ResponseChannel,
    swarm::{dial_opts::DialOpts, ConnectionId, DialError},
    Multiaddr,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    hash::Hash,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc};
use tracing::trace;

use libp2p::PeerId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRejectionKind {
    Transient,
    Permanent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipPublishFailure {
    NoPeersSubscribed,
    Transient(String),
    Permanent(String),
}

impl GossipPublishFailure {
    pub fn from_libp2p(error: PublishError) -> Self {
        match error {
            PublishError::NoPeersSubscribedToTopic => Self::NoPeersSubscribed,
            PublishError::AllQueuesFull(count) => {
                Self::Transient(PublishError::AllQueuesFull(count).to_string())
            }
            error => Self::Permanent(error.to_string()),
        }
    }

    pub fn transient(reason: impl Into<String>) -> Self {
        Self::Transient(reason.into())
    }

    pub fn permanent(reason: impl Into<String>) -> Self {
        Self::Permanent(reason.into())
    }
}

impl std::fmt::Display for GossipPublishFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPeersSubscribed => formatter.write_str("no peers are subscribed to the topic"),
            Self::Transient(reason) | Self::Permanent(reason) => formatter.write_str(reason),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PeerTarget {
    Random,
    Specific(PeerId),
}

/// Incoming/Outgoing GossipData. We disambiguate on concerns relative to the net package.
#[derive(Derivative, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[derivative(Debug)]
pub enum GossipData {
    // Serialized InterfoldEvent
    GossipBytes(#[derivative(Debug(format_with = "e3_utils::formatters::hexf"))] Vec<u8>),
    DocumentPublishedNotification(DocumentPublishedNotification),
}

impl GossipData {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).context("Could not serialize GossipData")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_GOSSIP_BYTES).context("Could not deserialize GossipData")
    }
}

impl TryFrom<InterfoldEvent<Sequenced>> for GossipData {
    type Error = anyhow::Error;
    fn try_from(value: InterfoldEvent<Sequenced>) -> Result<Self, Self::Error> {
        let bytes = value
            .clone_unsequenced() // Note serializing UNSEQUENCED
            .to_bytes()
            .context("Could not convert event to bytes for serialization!")?;
        Ok(GossipData::GossipBytes(bytes))
    }
}

impl TryFrom<GossipData> for InterfoldEvent<Unsequenced> {
    type Error = anyhow::Error;
    fn try_from(value: GossipData) -> Result<Self, Self::Error> {
        let GossipData::GossipBytes(bytes) = value else {
            bail!("GossipData was not the GossipBytes variant");
        };

        Ok(InterfoldEvent::from_bytes(&bytes)?.with_source(EventSource::Net))
    }
}

#[derive(Derivative, Clone, serde::Serialize, serde::Deserialize)]
#[derivative(Debug)]
pub enum ProtocolResponse {
    /// The transport encodes the bytes as one CBOR byte string, so a reply's frame is its bytes
    /// plus a few header bytes. As a CBOR integer array, a byte above 23 would take two.
    Ok(
        #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
        #[serde(with = "serde_bytes")]
        Vec<u8>,
    ),
    BadRequest(String),
    Error(String),
}

pub type ProtocolResponseChannel = ResponseChannel<ProtocolResponse>;

#[derive(Message, Clone, Debug)]
#[rtype("()")]
/// Remote has sent us a request
pub struct IncomingRequest {
    /// Authenticated libp2p peer which opened the request stream. This is transport-local metadata
    /// and is not part of the sync wire payload.
    pub peer: PeerId,
    pub responder: DirectResponder,
}

#[derive(Clone, Debug)]
/// We are responding to a remote request
pub struct IncomingResponse {
    pub responder: DirectResponder,
}

impl IncomingResponse {
    pub fn new(responder: DirectResponder) -> Self {
        Self { responder }
    }
}

#[derive(Debug, Clone)]
pub struct OutgoingRequest {
    pub correlation_id: CorrelationId,
    pub payload: Vec<u8>,
    pub target: PeerTarget,
}

impl OutgoingRequest {
    pub fn new_with_correlation(
        id: CorrelationId,
        target: PeerTarget,
        payload: impl TryInto<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self {
            correlation_id: id,
            payload: payload.try_into().map_err(|_| {
                anyhow!(
                    "could not serialize payload for outgoing request with correlation_id={id} and target={target:?}."
                )
            })?,
            target,
        })
    }
    pub fn to_random_peer(payload: impl TryInto<Vec<u8>>) -> Result<Self> {
        Self::new_with_correlation(CorrelationId::new(), PeerTarget::Random, payload)
    }

    pub fn new(target: PeerId, payload: impl TryInto<Vec<u8>>) -> Result<Self> {
        Self::new_with_correlation(CorrelationId::new(), PeerTarget::Specific(target), payload)
    }
}

#[derive(Message, Clone, Debug)]
#[rtype("()")]
pub struct OutgoingRequestSucceeded {
    pub payload: ProtocolResponse,
    pub correlation_id: CorrelationId,
}

#[derive(Debug, Clone)]
pub struct OutgoingRequestFailed {
    pub correlation_id: CorrelationId,
    pub error: String,
}

/// Libp2pNetInterface Commands are sent to the network peer over a mspc channel
#[derive(Debug, Clone)]
pub enum NetCommand {
    /// Publish message to gossipsub
    GossipPublish {
        topic: String,
        data: GossipData,
        correlation_id: CorrelationId,
        delivery_id: Option<[u8; 16]>,
    },
    /// Dial peer
    Dial(OnceTake<DialOpts>),
    /// Bind a configured address to the identity admitted after its initial dial.
    ConfiguredPeerAdmitted {
        address: Multiaddr,
        peer_id: PeerId,
    },
    /// Store a document in this node's own Kademlia store, without uploading it to other peers.
    /// Peers that look its key up can then fetch it from this node.
    DhtStoreLocal {
        correlation_id: CorrelationId,
        expires: Option<Instant>,
        value: ArcBytes,
        key: ContentHash,
    },
    /// Command to PublishDocument to Kademlia
    DhtPutRecord {
        correlation_id: CorrelationId,
        expires: Option<Instant>,
        value: ArcBytes,
        key: ContentHash,
    },
    /// End the Kademlia queries of a key's DHT puts that are in their upload phase. It has no
    /// reply. This is not a full cancel: requests that a query already gave to the connection
    /// handlers, queued or in progress, still go out, and a put that still looks up its closest
    /// peers runs on and then uploads the record.
    DhtCancelPut {
        key: ContentHash,
    },
    /// Fetch Document from Kademlia
    DhtGetRecord {
        correlation_id: CorrelationId,
        key: ContentHash,
    },
    /// Remove DHT records associated with a completed E3
    DhtRemoveRecords {
        keys: Vec<ContentHash>,
    },
    /// Shutdown signal
    Shutdown,
    /// Send a request to a peer and await response
    OutgoingRequest(OutgoingRequest),
    IncomingResponse(IncomingResponse),
    /// List the connected peers that passed network admission (`NetEvent::AdmittedPeers`).
    AdmittedPeers {
        correlation_id: CorrelationId,
    },
}

impl NetCommand {
    pub fn gossip_publish(topic: String, data: GossipData, correlation_id: CorrelationId) -> Self {
        Self::GossipPublish {
            topic,
            data,
            correlation_id,
            delivery_id: None,
        }
    }

    /// Create a new transport delivery for protocol data that was published before.
    pub fn gossip_republish(
        topic: String,
        data: GossipData,
        correlation_id: CorrelationId,
    ) -> Self {
        Self::GossipPublish {
            topic,
            data,
            correlation_id,
            delivery_id: Some(rand::random()),
        }
    }

    /// Short description for logs and errors. It never formats payload bytes, which can be
    /// megabytes for DHT documents.
    pub fn summary(&self) -> String {
        use NetCommand as N;
        match self {
            N::GossipPublish {
                topic,
                correlation_id,
                data,
                ..
            } => {
                let kind = match data {
                    GossipData::GossipBytes(bytes) => format!("event, {} bytes", bytes.len()),
                    GossipData::DocumentPublishedNotification(_) => "document notification".into(),
                };
                format!("GossipPublish {{ topic: {topic}, correlation_id: {correlation_id}, {kind} }}")
            }
            N::DhtStoreLocal {
                correlation_id,
                key,
                value,
                ..
            } => format!(
                "DhtStoreLocal {{ correlation_id: {correlation_id}, key: {key:?}, value_bytes: {} }}",
                value.size()
            ),
            N::DhtPutRecord {
                correlation_id,
                key,
                value,
                ..
            } => format!(
                "DhtPutRecord {{ correlation_id: {correlation_id}, key: {key:?}, value_bytes: {} }}",
                value.size()
            ),
            N::DhtGetRecord {
                correlation_id,
                key,
            } => format!("DhtGetRecord {{ correlation_id: {correlation_id}, key: {key:?} }}"),
            N::DhtCancelPut { key } => format!("DhtCancelPut {{ key: {key:?} }}"),
            N::DhtRemoveRecords { keys } => format!("DhtRemoveRecords {{ keys: {} }}", keys.len()),
            N::OutgoingRequest(OutgoingRequest { correlation_id, .. }) => {
                format!("OutgoingRequest {{ correlation_id: {correlation_id} }}")
            }
            N::Dial(_) => "Dial".into(),
            N::ConfiguredPeerAdmitted { peer_id, .. } => {
                format!("ConfiguredPeerAdmitted {{ peer_id: {peer_id} }}")
            }
            N::Shutdown => "Shutdown".into(),
            N::IncomingResponse(_) => "IncomingResponse".into(),
            N::AdmittedPeers { correlation_id } => {
                format!("AdmittedPeers {{ correlation_id: {correlation_id} }}")
            }
        }
    }

    pub fn correlation_id(&self) -> Option<CorrelationId> {
        use NetCommand as N;
        match self {
            N::DhtStoreLocal { correlation_id, .. } => Some(*correlation_id),
            N::DhtPutRecord { correlation_id, .. } => Some(*correlation_id),
            N::DhtGetRecord { correlation_id, .. } => Some(*correlation_id),
            N::GossipPublish { correlation_id, .. } => Some(*correlation_id),
            N::OutgoingRequest(OutgoingRequest { correlation_id, .. }) => Some(*correlation_id),
            N::AdmittedPeers { correlation_id } => Some(*correlation_id),
            _ => None,
        }
    }
}

/// NetEvents are broadcast over a broadcast channel to whom ever wishes to listen
#[derive(Message, Clone, Debug)]
#[rtype(result = "anyhow::Result<()>")]
pub enum NetEvent {
    /// Bytes have been broadcast over the network
    GossipData(GossipData),
    /// A protocol event with transient propagation-peer attribution.
    GossipIngress {
        propagation_source: PeerId,
        data: GossipData,
    },
    /// A document notification with local transport attribution.
    DocumentIngress(Box<DocumentIngress>),
    /// There was an Error publishing bytes over the network
    GossipPublishError {
        correlation_id: CorrelationId,
        error: Arc<GossipPublishFailure>,
    },
    /// Data was successfully published over the network as far as we know.
    GossipPublished {
        correlation_id: CorrelationId,
        message_id: MessageId,
    },
    /// There was an error Dialing a peer
    DialError {
        error: Arc<DialError>,
    },
    /// A connection was established to a peer
    ConnectionEstablished {
        connection_id: ConnectionId,
    },
    /// The authenticated peer behind a completed configured dial.
    ConfiguredDialAdmitted {
        connection_id: ConnectionId,
        peer_id: PeerId,
    },
    /// A transport connection failed the Interfold Identify admission policy.
    PeerRejected {
        connection_id: ConnectionId,
        kind: PeerRejectionKind,
        reason: String,
    },
    /// There was an error creating a connection
    OutgoingConnectionError {
        connection_id: ConnectionId,
        error: Arc<DialError>,
    },
    /// This node received a document from a Kademlia Request
    DhtGetRecordSucceeded {
        key: ContentHash,
        correlation_id: CorrelationId,
        value: ArcBytes,
    },
    /// This node received a document from a Kademlia Request
    DhtPutRecordSucceeded {
        key: ContentHash,
        correlation_id: CorrelationId,
    },
    /// This node stored a document in its own Kademlia store.
    DhtStoreLocalSucceeded {
        key: ContentHash,
        correlation_id: CorrelationId,
    },
    /// This node could not store a document in its own Kademlia store.
    DhtStoreLocalError {
        correlation_id: CorrelationId,
        error: store::Error,
    },
    /// There was an error receiving the document
    DhtGetRecordError {
        correlation_id: CorrelationId,
        error: GetRecordError,
    },
    /// There was an error putting the document
    DhtPutRecordError {
        correlation_id: CorrelationId,
        error: PutOrStoreError,
    },
    /// GossipSubscribed
    GossipSubscribed {
        count: usize,
        topic: TopicHash,
    },
    /// A peer made a request to this node
    IncomingRequest(IncomingRequest),
    /// Received response from a peer in response to an outgoing request
    OutgoingRequestSucceeded(OutgoingRequestSucceeded),
    OutgoingRequestFailed(OutgoingRequestFailed),
    /// All configured peers have been dialed (not all necessarily connected).
    AllPeersDialed {
        /// Number of peers that successfully connected.
        connected: usize,
        /// Total number of peers that were dialed.
        total: usize,
    },
    /// Connected peers that passed network admission, in reply to `NetCommand::AdmittedPeers`.
    AdmittedPeers {
        correlation_id: CorrelationId,
        peers: Vec<PeerId>,
    },
    /// The startup buffer sends this on its output after the last event that it held, so a
    /// consumer knows that every later event is live. The network interface never sends it.
    StartupBufferReleased,
}

#[derive(Clone, Debug)]
pub enum PutOrStoreError {
    PutRecordError(PutRecordError),
    StoreError(store::Error),
}

impl NetEvent {
    /// Whether post-sync application consumers need this event.
    ///
    /// Historical-sync and connection-control events use the raw network receiver and must not
    /// also occupy the startup application buffer.
    pub(crate) fn requires_application_delivery(&self) -> bool {
        // Keep this match exhaustive. Each new event must select one delivery path.
        match self {
            Self::GossipData(_)
            | Self::GossipIngress { .. }
            | Self::DocumentIngress(_)
            | Self::GossipPublishError { .. }
            | Self::GossipPublished { .. }
            | Self::DhtGetRecordSucceeded { .. }
            | Self::DhtPutRecordSucceeded { .. }
            | Self::DhtGetRecordError { .. }
            | Self::DhtPutRecordError { .. }
            | Self::DhtStoreLocalSucceeded { .. }
            | Self::DhtStoreLocalError { .. }
            | Self::StartupBufferReleased => true,
            Self::DialError { .. }
            | Self::ConnectionEstablished { .. }
            | Self::ConfiguredDialAdmitted { .. }
            | Self::PeerRejected { .. }
            | Self::OutgoingConnectionError { .. }
            | Self::GossipSubscribed { .. }
            | Self::IncomingRequest(_)
            | Self::OutgoingRequestSucceeded(_)
            | Self::OutgoingRequestFailed(_)
            | Self::AllPeersDialed { .. }
            | Self::AdmittedPeers { .. } => false,
        }
    }

    /// Conservative size used by the bounded startup buffer.
    ///
    /// The enum's inline storage is always counted. Heap-backed protocol payloads that can be
    /// remotely large are added explicitly; small library error metadata remains covered by the
    /// event-count limit.
    pub(crate) fn buffered_size_bytes(&self) -> usize {
        let dynamic = match self {
            Self::GossipData(data) | Self::GossipIngress { data, .. } => serialized_size(data),
            Self::DocumentIngress(ingress) => std::mem::size_of::<DocumentIngress>()
                .saturating_add(serialized_size(&ingress.notification)),
            Self::GossipPublished { message_id, .. } => message_id.0.len(),
            Self::DhtGetRecordSucceeded { value, .. } => value.len(),
            Self::DhtGetRecordError { error, .. } => match error {
                GetRecordError::NotFound { key, closest_peers } => {
                    key.as_ref().len().saturating_add(
                        closest_peers
                            .len()
                            .saturating_mul(std::mem::size_of::<PeerId>()),
                    )
                }
                GetRecordError::QuorumFailed { key, records, .. } => {
                    records
                        .iter()
                        .fold(key.as_ref().len(), |total, peer_record| {
                            total
                                .saturating_add(peer_record.record.key.as_ref().len())
                                .saturating_add(peer_record.record.value.len())
                        })
                }
                GetRecordError::Timeout { key } => key.as_ref().len(),
            },
            Self::GossipSubscribed { topic, .. } => topic.as_str().len(),
            Self::IncomingRequest(request) => request.responder.request_len(),
            Self::OutgoingRequestSucceeded(response) => serialized_size(&response.payload),
            Self::OutgoingRequestFailed(response) => response.error.len(),
            Self::GossipPublishError { error, .. } => error.to_string().len(),
            Self::PeerRejected { reason, .. } => reason.len(),
            Self::AdmittedPeers { peers, .. } => {
                peers.len().saturating_mul(std::mem::size_of::<PeerId>())
            }
            Self::DialError { .. }
            | Self::ConnectionEstablished { .. }
            | Self::ConfiguredDialAdmitted { .. }
            | Self::OutgoingConnectionError { .. }
            | Self::DhtPutRecordSucceeded { .. }
            | Self::DhtPutRecordError { .. }
            | Self::DhtStoreLocalSucceeded { .. }
            | Self::DhtStoreLocalError { .. }
            | Self::AllPeersDialed { .. }
            | Self::StartupBufferReleased => 0,
        };

        std::mem::size_of::<Self>().saturating_add(dynamic)
    }

    pub fn correlation_id(&self) -> Option<CorrelationId> {
        use NetEvent as N;
        match self {
            N::GossipPublished { correlation_id, .. } => Some(*correlation_id),
            N::GossipPublishError { correlation_id, .. } => Some(*correlation_id),
            N::DhtGetRecordError { correlation_id, .. } => Some(*correlation_id),
            N::DhtGetRecordSucceeded { correlation_id, .. } => Some(*correlation_id),
            N::DhtPutRecordError { correlation_id, .. } => Some(*correlation_id),
            N::DhtPutRecordSucceeded { correlation_id, .. } => Some(*correlation_id),
            N::DhtStoreLocalSucceeded { correlation_id, .. } => Some(*correlation_id),
            N::DhtStoreLocalError { correlation_id, .. } => Some(*correlation_id),
            N::OutgoingRequestSucceeded(msg) => Some(msg.correlation_id),
            N::OutgoingRequestFailed(msg) => Some(msg.correlation_id),
            N::AdmittedPeers { correlation_id, .. } => Some(*correlation_id),
            _ => None,
        }
    }
}

fn serialized_size(value: &impl Serialize) -> usize {
    bincode::serialized_size(value)
        .ok()
        .and_then(|size| usize::try_from(size).ok())
        .unwrap_or(usize::MAX)
}

/// Transient ingress metadata. In-process notifications share one unattributed queue.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct DocumentIngress {
    pub propagation_source: Option<PeerId>,
    pub notification: DocumentPublishedNotification,
}

/// Payload that is dispatched as a net -> net gossip event from Kademlia. This event signals that
/// a document was published and that this node might be interested in it.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct DocumentPublishedNotification {
    pub meta: DocumentMeta,
    pub key: ContentHash,
    pub ts: u128,
}

impl DocumentPublishedNotification {
    pub fn new(meta: DocumentMeta, key: ContentHash, ts: u128) -> Self {
        Self { meta, key, ts }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).context("Could not serialize DocumentPublishedNotification")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_GOSSIP_BYTES)
            .context("Could not deserialize DocumentPublishedNotification")
    }
}

/// Sends a command and waits for its result event.
///
/// The result arrives through a oneshot channel registered for the command's correlation id at the
/// network interface's event channel, also when `net_events` reads the startup buffer. So neither
/// broadcast lag nor the buffer can drop it. `matcher` converts the result event; it returns `None`
/// for an event that is not a result of this command.
pub async fn call_and_await_response<F, R>(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: NetEventSubscriber,
    command: NetCommand,
    matcher: F,
    timeout: Duration,
) -> Result<R>
where
    F: Fn(&NetEvent) -> Option<Result<R>>,
{
    let Some(id) = command.correlation_id() else {
        return Err(anyhow::anyhow!(
            "Command must have a correlation_id but this does not: {}",
            command.summary()
        ));
    };

    // The command moves into the channel, so keep its description for the errors below.
    let command_summary = command.summary();

    // Register before sending the command so the result cannot arrive first.
    let response = net_events.expect_response(id)?;

    trace!(
        "call_and_await_response: sending command {} with timeout {:?}",
        command_summary,
        timeout
    );
    // One deadline covers the queue admission and the response, so a full command queue cannot
    // hold the caller past its timeout. An expired send drops the command with it.
    let event = tokio::time::timeout(timeout, async move {
        net_cmds.send(command).await?;
        response.recv().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timed out waiting for response from {command_summary}"))??;
    matcher(&event)
        .unwrap_or_else(|| Err(anyhow::anyhow!("Unexpected response to {command_summary}")))
}

pub async fn await_event<F, R>(
    net_events: &NetEventSubscriber,
    matcher: F,
    timeout: Duration,
) -> Result<R>
where
    F: Fn(&NetEvent) -> Option<R>,
{
    let mut rx = net_events.subscribe();

    let result = tokio::time::timeout(timeout, async {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Some(result) = matcher(&event) {
                        return Ok(result);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!(format!("Timed out waiting for event")))?;
    result
}

pub fn estimate_hashmap_size<K, V>(map: &HashMap<K, V>) -> usize {
    let entry_size = size_of::<K>() + size_of::<V>();
    let capacity = map.capacity();

    // HashMap uses ~1 byte of overhead per slot for metadata
    capacity * (entry_size + 1) + size_of::<HashMap<K, V>>()
}

/// Send `payload` through the transport frame of a direct reply, and return the bytes that the
/// reader decodes. Fails when the frame exceeds the 10 MiB response limit.
#[cfg(test)]
pub(crate) async fn through_reply_frame(payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    use futures::io::Cursor;
    use libp2p::request_response::{cbor::codec::Codec, Codec as _};

    let protocol = libp2p::StreamProtocol::new("/interfold/test-sync");
    let mut codec = Codec::<Vec<u8>, ProtocolResponse>::default();
    let mut frame = Cursor::new(Vec::new());
    codec
        .write_response(&protocol, &mut frame, ProtocolResponse::Ok(payload))
        .await?;
    anyhow::ensure!(
        frame.get_ref().len() <= crate::domain::wire::MAX_DIRECT_MESSAGE_BYTES,
        "the reply frame exceeds the response limit"
    );
    let mut reader = Cursor::new(frame.into_inner());
    match codec.read_response(&protocol, &mut reader).await? {
        ProtocolResponse::Ok(bytes) => Ok(bytes),
        _ => anyhow::bail!("the reply decoded to another response"),
    }
}

#[cfg(test)]
mod tests {
    use e3_events::{
        CorrelationId, EventConstructorWithTimestamp, EventSource, InterfoldEvent, Sequenced,
        TestEvent, Unsequenced,
    };
    use e3_utils::ArcBytes;

    use std::time::Duration;

    use anyhow::Context;
    use tokio::sync::mpsc;

    use super::{call_and_await_response, GossipData, NetCommand, NetEvent, ProtocolResponse};

    /// A reply of the largest sync envelope, with bytes that a CBOR integer array would double,
    /// fits one transport frame and decodes to the same bytes.
    #[tokio::test]
    async fn a_largest_sync_reply_fits_one_transport_frame() {
        let payload: Vec<u8> = (0..crate::domain::wire::MAX_SYNC_ENVELOPE_BYTES)
            .map(|index| 24 + (index % 232) as u8)
            .collect();
        let decoded = super::through_reply_frame(payload.clone())
            .await
            .expect("the reply fits one frame");
        assert!(decoded == payload);
    }
    use crate::{
        net_interface_handle::{NetEventChannel, NetEventSubscriber},
        ContentHash,
    };

    /// Starts a DHT get for `value` on the given event channel and returns the call and the
    /// correlation id of its command.
    async fn start_get(
        events: &NetEventChannel,
        value: &ArcBytes,
        timeout: Duration,
    ) -> anyhow::Result<(
        tokio::task::JoinHandle<anyhow::Result<ArcBytes>>,
        CorrelationId,
    )> {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        let call = tokio::spawn(call_and_await_response(
            cmd_tx,
            NetEventSubscriber::from(events),
            NetCommand::DhtGetRecord {
                correlation_id: CorrelationId::new(),
                key: ContentHash::from_content(value),
            },
            |event| match event {
                NetEvent::DhtGetRecordSucceeded { value, .. } => Some(Ok(value.clone())),
                _ => None,
            },
            timeout,
        ));
        let command = cmd_rx.recv().await.context("the call sent no command")?;
        let id = command.correlation_id().context("the command has no id")?;
        Ok((call, id))
    }

    #[tokio::test]
    async fn command_result_survives_broadcast_lag() -> anyhow::Result<()> {
        let events = NetEventChannel::new(1);
        let _observer = events.subscribe();
        let value = ArcBytes::from_bytes(b"document");
        let (call, correlation_id) = start_get(&events, &value, Duration::from_secs(2)).await?;

        // The next event replaces the result in the one-slot broadcast before the caller runs.
        events.send(NetEvent::DhtGetRecordSucceeded {
            key: ContentHash::from_content(&value),
            correlation_id,
            value: value.clone(),
        })?;
        events.send(NetEvent::GossipData(GossipData::GossipBytes(vec![1])))?;

        assert_eq!(call.await??, value);
        Ok(())
    }

    #[tokio::test]
    async fn command_wait_ends_when_the_event_channel_closes() -> anyhow::Result<()> {
        let events = NetEventChannel::new(1);
        let value = ArcBytes::from_bytes(b"document");
        let (call, _) = start_get(&events, &value, Duration::from_secs(60)).await?;

        drop(events);

        let error = tokio::time::timeout(Duration::from_secs(5), call)
            .await
            .context("the call waited for its timeout")??
            .unwrap_err();
        assert!(format!("{error:#}").contains("closed"));
        Ok(())
    }

    /// The deadline includes the wait for room in the command queue. A queue that is full and not
    /// drained ends the call at its own timeout, drops its command and releases its correlation id.
    #[tokio::test(start_paused = true)]
    async fn command_deadline_includes_queue_wait() -> anyhow::Result<()> {
        let events = NetEventChannel::new(1);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        cmd_tx.send(NetCommand::Shutdown).await?;
        let correlation_id = CorrelationId::new();
        let call = call_and_await_response(
            cmd_tx,
            NetEventSubscriber::from(&events),
            NetCommand::DhtGetRecord {
                correlation_id,
                key: ContentHash::from_content(b"document".as_ref()),
            },
            |event| match event {
                NetEvent::DhtGetRecordSucceeded { value, .. } => Some(Ok(value.clone())),
                _ => None,
            },
            Duration::from_secs(30),
        );

        let error = tokio::time::timeout(Duration::from_secs(31), call)
            .await
            .context("the call outlived its deadline")?
            .unwrap_err();
        assert!(format!("{error:#}").contains("Timed out"));
        assert!(matches!(cmd_rx.try_recv(), Ok(NetCommand::Shutdown)));
        assert!(
            cmd_rx.try_recv().is_err(),
            "the expired command was not queued"
        );
        drop(NetEventSubscriber::from(&events).expect_response(correlation_id)?);
        Ok(())
    }

    #[test]
    fn command_summary_reports_sizes_without_payload_bytes() {
        let value = ArcBytes::from_bytes(&vec![0x5a; 1_776_213]);
        let key = ContentHash::from_content(&value);
        let summary = NetCommand::DhtPutRecord {
            correlation_id: CorrelationId::new(),
            expires: None,
            value,
            key,
        }
        .summary();
        assert!(summary.contains("value_bytes: 1776213"), "{summary}");
        assert!(summary.len() < 256, "{summary}");
    }

    #[test]
    fn net_event_debug_formats_payload_bytes_through_hexf() {
        let bytes = vec![0x5a; 1_776_213];
        for text in [
            format!(
                "{:?}",
                NetEvent::GossipData(GossipData::GossipBytes(bytes.clone()))
            ),
            format!("{:?}", ProtocolResponse::Ok(bytes)),
        ] {
            assert!(text.contains("1776213"), "{text}");
            assert!(text.len() < 256, "{text}");
        }
    }

    #[test]
    fn test_interfold_event_gossip_lifecycle() -> anyhow::Result<()> {
        // event is created locally
        let event: InterfoldEvent<Unsequenced> = InterfoldEvent::new_with_timestamp(
            TestEvent::new("fish", 42).into(),
            None,
            31415,
            None,
            EventSource::Local,
        );

        // event is sequenced after bus.publish() adds a sequence number
        let event: InterfoldEvent<Sequenced> = event.into_sequenced(90210);

        // event is broadcast
        let gossip_data: GossipData = event.try_into()?;

        let GossipData::GossipBytes(_) = gossip_data else {
            panic!("events must only be serialized to GossipBytes");
        };

        // received gossip data from libp2p convert to unsequenced event
        let event: InterfoldEvent<Unsequenced> = gossip_data.try_into()?;
        let (data, ts) = event.split();

        assert_eq!(data, TestEvent::new("fish", 42).into());
        assert_eq!(ts, 31415);

        Ok(())
    }

    #[test]
    fn gossip_decode_rejects_forged_collection_length() {
        let mut bytes = 0_u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());

        assert!(GossipData::from_bytes(&bytes).is_err());
    }

    #[test]
    fn gossip_decode_rejects_trailing_bytes() {
        let mut bytes = GossipData::GossipBytes(vec![1, 2, 3]).to_bytes().unwrap();
        bytes.push(0);

        let error = GossipData::from_bytes(&bytes).unwrap_err();
        assert!(format!("{error:#}").contains("trailing bytes"));
    }
}
