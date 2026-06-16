// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{direct_responder::DirectResponder, ContentHash};
use actix::Message;
use anyhow::{anyhow, bail, Context, Result};
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
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    hash::Hash,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, trace, warn};

use libp2p::PeerId;

#[derive(Clone, Copy, Debug)]
pub enum PeerTarget {
    Random,
    Specific(PeerId),
}

/// Incoming/Outgoing GossipData. We disambiguate on concerns relative to the net package.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum GossipData {
    GossipBytes(Vec<u8>), // Serialized InterfoldEvent
    DocumentPublishedNotification(DocumentPublishedNotification),
}

impl GossipData {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).context("Could not serialize GossipData")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).context("Could not deserialize GossipData")
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProtocolResponse {
    Ok(Vec<u8>),
    BadRequest(String),
    Error(String),
}

pub type ProtocolResponseChannel = ResponseChannel<ProtocolResponse>;

#[derive(Message, Clone, Debug)]
#[rtype("()")]
/// Remote has sent us a request
pub struct IncomingRequest {
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
    },
    /// Dial peer
    Dial(OnceTake<DialOpts>),
    /// Command to PublishDocument to Kademlia
    DhtPutRecord {
        correlation_id: CorrelationId,
        expires: Option<Instant>,
        value: ArcBytes,
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
}

impl NetCommand {
    pub fn correlation_id(&self) -> Option<CorrelationId> {
        use NetCommand as N;
        match self {
            N::DhtPutRecord { correlation_id, .. } => Some(*correlation_id),
            N::DhtGetRecord { correlation_id, .. } => Some(*correlation_id),
            N::GossipPublish { correlation_id, .. } => Some(*correlation_id),
            N::OutgoingRequest(OutgoingRequest { correlation_id, .. }) => Some(*correlation_id),
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
    /// There was an Error publishing bytes over the network
    GossipPublishError {
        correlation_id: CorrelationId,
        error: Arc<PublishError>,
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
}

#[derive(Clone, Debug)]
pub enum PutOrStoreError {
    PutRecordError(PutRecordError),
    StoreError(store::Error),
}

impl NetEvent {
    pub fn correlation_id(&self) -> Option<CorrelationId> {
        use NetEvent as N;
        match self {
            N::GossipPublished { correlation_id, .. } => Some(*correlation_id),
            N::GossipPublishError { correlation_id, .. } => Some(*correlation_id),
            N::DhtGetRecordError { correlation_id, .. } => Some(*correlation_id),
            N::DhtGetRecordSucceeded { correlation_id, .. } => Some(*correlation_id),
            N::DhtPutRecordError { correlation_id, .. } => Some(*correlation_id),
            N::DhtPutRecordSucceeded { correlation_id, .. } => Some(*correlation_id),
            N::OutgoingRequestSucceeded(msg) => Some(msg.correlation_id),
            N::OutgoingRequestFailed(msg) => Some(msg.correlation_id),
            _ => None,
        }
    }
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
        bincode::deserialize(bytes).context("Could not deserialize DocumentPublishedNotification")
    }
}

/// Generic helper for the command-response pattern with correlation IDs
pub async fn call_and_await_response<F, R>(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: Arc<broadcast::Receiver<NetEvent>>,
    command: NetCommand,
    matcher: F,
    timeout: Duration,
) -> Result<R>
where
    F: Fn(&NetEvent) -> Option<Result<R>>,
{
    // Resubscribe first to avoid missing events
    let mut rx = net_events.resubscribe();

    // Extract correlation_id from command
    let Some(id) = command.correlation_id() else {
        return Err(anyhow::anyhow!(format!(
            "Command must have a correlation_id but this does not: {:?}",
            command
        )));
    };

    // We don't have access to this later and we cannot clone command
    let debug_cmd = format!("{:?}", command);

    // Send the command to Libp2pNetInterface
    trace!(
        "call_and_await_response: sending command {:?} with timeout {:?}",
        command,
        timeout
    );
    net_cmds.send(command).await?;

    let result = tokio::time::timeout(timeout, async {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    // Only process events matching our correlation ID
                    if event.correlation_id() == Some(id) {
                        if let Some(result) = matcher(&event) {
                            return result;
                        } // None means unexpected event type, keep waiting
                        trace!("matcher did not match event, skipping...");
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("broadcast receiver lagged by {n} messages");
                    continue;
                }
                Err(e) => {
                    error!("broadcast channel error: {:?}", e);
                    return Err(e.into());
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!(format!("Timed out waiting for response from {}", debug_cmd)))?;
    result
}

pub async fn await_event<F, R>(
    net_events: &Arc<broadcast::Receiver<NetEvent>>,
    matcher: F,
    timeout: Duration,
) -> Result<R>
where
    F: Fn(&NetEvent) -> Option<R>,
{
    let mut rx = net_events.resubscribe();

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

#[cfg(test)]
mod tests {
    use e3_events::{
        EventConstructorWithTimestamp, EventSource, InterfoldEvent, Sequenced, TestEvent,
        Unsequenced,
    };

    use super::GossipData;

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
}
