// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Every libp2p setting of the node, in one place, each with its reason.

use crate::{
    inbound_ip_limits::InboundIpLimits, peers::PeerBook, protocols::Protocols, serving::BlobRequest,
};
use libp2p::{
    connection_limits::{self, ConnectionLimits},
    gossipsub::{self, MessageId, WhitelistSubscriptionFilter},
    identify,
    identity::Keypair,
    kad::{self, store::MemoryStore, StoreInserts},
    request_response::{self, cbor, ProtocolSupport},
    swarm::NetworkBehaviour,
};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, time::Duration};

/// The largest envelope: proofs travel as blobs, so an envelope holds references and public inputs.
pub(crate) const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
/// The largest blob a peer may send, above the old document limit of 26 MiB.
pub(crate) const MAX_BLOB_BYTES: u64 = 32 * 1024 * 1024;
/// A blob's response carries CBOR framing on top of its bytes.
const RESPONSE_FRAMING: u64 = 64 * 1024;
/// A request names an E3, a hash and a proof. Anyone can open a stream and send this much before
/// the node knows who it is.
const MAX_BLOB_REQUEST_BYTES: u64 = 1024;
/// How long a blob request may take, its wait for a place included: long enough for a dealer on
/// the slowest supported uplink to reach the last of a large committee.
const BLOB_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// The blob requests that may run at once on one connection.
const BLOB_STREAMS: usize = 8;
/// The library's tick-based defaults (history, gossip windows) assume one second.
const GOSSIP_HEARTBEAT: Duration = Duration::from_secs(1);
/// Often enough to see a peer's new addresses, rarely enough not to cost anything.
const IDENTIFY_INTERVAL: Duration = Duration::from_secs(60);

pub(crate) type Gossipsub =
    gossipsub::Behaviour<gossipsub::IdentityTransform, WhitelistSubscriptionFilter>;

/// A connection with no protocol using it closes after this; a peer reconnects when it needs to.
pub(crate) const IDLE_CONNECTION: Duration = Duration::from_secs(10);

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    /// Before the behaviours that prepare an inbound connection, so a refused one costs nothing.
    pub(crate) inbound_ip_limits: InboundIpLimits,
    pub(crate) connection_limits: connection_limits::Behaviour,
    /// Decides who the node dials and keeps connected. It sees every outbound dial.
    pub(crate) peers: PeerBook,
    pub(crate) gossipsub: Gossipsub,
    pub(crate) identify: identify::Behaviour,
    pub(crate) kademlia: kad::Behaviour<MemoryStore>,
    /// A request names the blob's E3 and hash: each E3 keeps its own copy of its blobs.
    pub(crate) blobs: cbor::Behaviour<BlobRequest, Option<ByteBuf>>,
}

impl Behaviour {
    /// A node that takes no part in the network's `messages` does not subscribe to their topic and
    /// offers no blobs, so peers keep it out of their message mesh and see that it is a bootstrap
    /// node.
    pub(crate) fn new(
        key: &Keypair,
        protocols: &Protocols,
        messages: bool,
        peers: PeerBook,
    ) -> Result<Self, String> {
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
            peers,
            gossipsub: gossipsub(key, protocols, messages)?,
            // The raw address cache would hand out addresses outside the node's own filter and
            // bounds.
            identify: identify::Behaviour::new(
                identify::Config::new(protocols.identify.clone(), key.public())
                    .with_agent_version(format!("interfold-node/{}", env!("CARGO_PKG_VERSION")))
                    .with_interval(IDENTIFY_INTERVAL)
                    .with_cache_size(0),
            ),
            kademlia: kademlia(key, protocols),
            blobs: blobs(protocols, messages),
        })
    }
}

fn gossipsub(key: &Keypair, protocols: &Protocols, messages: bool) -> Result<Gossipsub, String> {
    let config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(GOSSIP_HEARTBEAT)
        .max_transmit_size(MAX_ENVELOPE_BYTES)
        .validation_mode(gossipsub::ValidationMode::Strict)
        .validate_messages()
        .message_id_fn(|message| MessageId::from(Sha256::digest(&message.data).to_vec()))
        .build()
        .map_err(|error| error.to_string())?;
    // Only the network's own topic: a peer cannot make the node keep state for others.
    let topics = HashSet::from([protocols.topic.hash()]);
    let mut gossipsub = Gossipsub::new_with_subscription_filter(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        config,
        WhitelistSubscriptionFilter(topics),
    )
    .map_err(str::to_owned)?;
    let mut score = gossipsub::PeerScoreParams::default();
    // Delivery penalties are off: a committee's members publish little, and a quiet peer is not a
    // bad one. Sending an invalid message is.
    score.topics.insert(
        protocols.topic.hash(),
        gossipsub::TopicScoreParams {
            time_in_mesh_quantum: Duration::from_secs(1),
            time_in_mesh_cap: 10.0,
            first_message_deliveries_cap: 100.0,
            mesh_message_deliveries_weight: 0.0,
            mesh_failure_penalty_weight: 0.0,
            invalid_message_deliveries_weight: -10.0,
            ..Default::default()
        },
    );
    gossipsub.with_peer_score(score, gossipsub::PeerScoreThresholds::default())?;
    if messages {
        gossipsub
            .subscribe(&protocols.topic)
            .map_err(|error| error.to_string())?;
    }
    Ok(gossipsub)
}

fn kademlia(key: &Keypair, protocols: &Protocols) -> kad::Behaviour<MemoryStore> {
    let peer = key.public().to_peer_id();
    let mut config = kad::Config::new(protocols.kademlia.clone());
    // Routing entries come only from peers that identify on this network and version, and the
    // node stores nothing for anyone: lookups find peers, and blobs travel by request.
    config
        .set_kbucket_inserts(kad::BucketInserts::Manual)
        .set_record_filtering(StoreInserts::FilterBoth)
        .set_replication_interval(None)
        .set_publication_interval(None);
    let mut kademlia = kad::Behaviour::with_config(peer, MemoryStore::new(peer), config);
    kademlia.set_mode(Some(kad::Mode::Server));
    kademlia
}

fn blobs(protocols: &Protocols, messages: bool) -> cbor::Behaviour<BlobRequest, Option<ByteBuf>> {
    let codec = cbor::codec::Codec::default()
        .set_request_size_maximum(MAX_BLOB_REQUEST_BYTES)
        .set_response_size_maximum(MAX_BLOB_BYTES + RESPONSE_FRAMING);
    let support = match messages {
        true => ProtocolSupport::Full,
        false => ProtocolSupport::Outbound,
    };
    cbor::Behaviour::with_codec(
        codec,
        [(protocols.blobs.clone(), support)],
        request_response::Config::default()
            .with_request_timeout(BLOB_REQUEST_TIMEOUT)
            .with_max_concurrent_streams(BLOB_STREAMS),
    )
}
