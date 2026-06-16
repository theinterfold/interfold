// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    dialer::dial_peers,
    events::{
        GossipData, IncomingRequest, NetCommand, NetEvent, OutgoingRequestFailed,
        OutgoingRequestSucceeded, PeerTarget, PutOrStoreError,
    },
    ContentHash,
};
use crate::{
    direct_responder::{ChannelType, DirectResponder},
    domain::{correlator::Correlator, peer_failure_tracker::PeerFailureTracker},
    events::{IncomingResponse, OutgoingRequest, ProtocolResponse},
    keypair::Libp2pKeypair,
    net_interface_handle::NetInterfaceHandle,
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
        Behaviour as KademliaBehaviour, Config as KademliaConfig, GetRecordOk, QueryResult, Quorum,
        Record, RecordKey,
    },
    multiaddr::Protocol,
    request_response::{
        self, cbor, Event as RequestResponseEvent, Message as RequestResponseMessage,
        ProtocolSupport,
    },
    swarm::{dial_opts::DialOpts, DialError, NetworkBehaviour, SwarmEvent},
    Multiaddr, StreamProtocol, Swarm,
};
use rand::prelude::IteratorRandom;
use std::{
    io::Error,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    select,
    sync::{broadcast, mpsc},
};
use tracing::{debug, error, info, trace, warn};

const PROTOCOL_NAME: StreamProtocol = StreamProtocol::new("/interfold/kad/1.0.0");
const MAX_KADEMLIA_PAYLOAD_MB: usize = 100;
const MAX_KADEMLIA_RECORD_MB: usize = 25; // Largest record: ~21MB ThresholdShare with prod params
const DHT_MAX_RECORDS: usize = 4096;
const MAX_GOSSIP_MSG_SIZE_KB: usize = 10240; // 10MB — prod params C6 proofs are ~4.6MB
const MAX_CONSECUTIVE_DIAL_FAILURES: u32 = 40;
const EVENT_CHANNEL_SIZE: usize = 1000;
const CMD_CHANNEL_SIZE: usize = 1000;

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

#[derive(NetworkBehaviour)]
pub struct NodeBehaviour {
    gossipsub: gossipsub::Behaviour,
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
    /// Broadcast channel to report NetEvents to listeners
    event_tx: broadcast::Sender<NetEvent>,
    /// Transmission channel to send NetCommands to the Libp2pNetInterface
    cmd_tx: mpsc::Sender<NetCommand>,
    /// Local receiver to process NetCommands from
    cmd_rx: mpsc::Receiver<NetCommand>,
}

impl Libp2pNetInterface {
    pub fn new(
        id: Libp2pKeypair,
        peers: Vec<String>,
        udp_port: Option<u16>,
        topic: &str,
    ) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_SIZE);
        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_SIZE);

        let swarm = libp2p::SwarmBuilder::with_existing_identity(id.into_keypair())
            .with_tokio()
            .with_quic()
            .with_dns()
            .map_err(|e| anyhow::anyhow!("Failed to enable DNS: {e}"))?
            .with_behaviour(create_behaviour)?
            .build();

        // TODO: Use topics to manage network traffic instead of just using a single topic
        let topic = gossipsub::IdentTopic::new(topic);

        Ok(Self {
            swarm,
            peers,
            udp_port,
            topic,
            event_tx,
            cmd_tx,
            cmd_rx,
        })
    }

    pub fn handle(&self) -> NetInterfaceHandle {
        NetInterfaceHandle::new(self.cmd_tx.clone(), self.event_tx.subscribe())
    }

    pub async fn start(&mut self) -> Result<()> {
        let event_tx = self.event_tx.clone();
        let cmd_tx = self.cmd_tx.clone();
        let cmd_rx = &mut self.cmd_rx;
        let mut correlator = Correlator::new();
        let mut peer_failures = PeerFailureTracker::new();
        // Tracks WrongPeerId occurrences per stale peer ID, separately from
        // generic dial failures: a node that was offline accumulates ordinary
        // failures before coming back with new keys, and the first mismatch
        // must still be treated as the first (triggering redial + bootstrap).
        let mut peer_id_mismatches = PeerFailureTracker::new();
        // This is to make sure we dont spam warnings in the logs
        let mut last_backpressure_warn = Instant::now();

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
                 // Process commands
                Some(command) = cmd_rx.recv() => {
                    if let NetCommand::Shutdown = command {
                        if let Err(e) = handle_shutdown(&mut self.swarm).await {
                            error!("Error processing NetCommand: {e}");
                        }
                        break;
                    }

                    if let Err(e) = process_swarm_command(&mut self.swarm, &event_tx, &mut correlator, command).await {
                        error!("Error processing NetCommand: {e}")
                    }
                }
                // Process events
                event = self.swarm.select_next_some() =>  {
                    match process_swarm_event(&mut self.swarm, &event_tx, &cmd_tx, &mut correlator, &mut peer_failures, &mut peer_id_mismatches, event).await {
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
) -> std::result::Result<NodeBehaviour, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let peer_id = key.public().to_peer_id();
    let connection_limits = connection_limits::Behaviour::new(ConnectionLimits::default());
    let identify = IdentifyBehaviour::new(
        IdentifyConfig::new("/interfold/0.0.1".into(), key.public())
            .with_interval(Duration::from_secs(60)),
    );

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .max_transmit_size(MAX_GOSSIP_MSG_SIZE_KB * 1024)
        .validation_mode(gossipsub::ValidationMode::Strict)
        .build()
        .map_err(Error::other)?;

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub_config,
    )?;
    let request_response_config =
        request_response::Config::default().with_request_timeout(Duration::from_secs(30));

    let request_response = cbor::Behaviour::<Vec<u8>, ProtocolResponse>::new(
        [(
            StreamProtocol::new("/interfold/sync/0.0.1"),
            ProtocolSupport::Full,
        )],
        request_response_config,
    );
    let mut config = KademliaConfig::new(PROTOCOL_NAME);
    config
        .set_max_packet_size(MAX_KADEMLIA_PAYLOAD_MB * 1024 * 1024)
        .set_query_timeout(Duration::from_secs(30));
    let store_config = MemoryStoreConfig {
        max_records: DHT_MAX_RECORDS,
        max_value_bytes: MAX_KADEMLIA_RECORD_MB * 1024 * 1024,
        max_providers_per_key: usize::MAX,
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
    event_tx: &broadcast::Sender<NetEvent>,
    cmd_tx: &mpsc::Sender<NetCommand>,
    correlator: &mut Correlator,
    peer_failures: &mut PeerFailureTracker,
    peer_id_mismatches: &mut PeerFailureTracker,
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
            // Reset failure counts on successful connection
            peer_failures.reset(&peer_id);
            peer_id_mismatches.reset(&peer_id);
            if num_established.get() == 1 {
                let total = swarm.connected_peers().count();
                info!("Peer connected: {peer_id} (total: {total})");
            }
            let remote_addr = endpoint.get_remote_address().clone();
            if !(should_filter_loopback(swarm) && is_loopback_addr(&remote_addr)) {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, remote_addr.clone());
            }

            // Trigger Kademlia bootstrap to discover peers beyond direct connections
            if num_established.get() == 1 {
                if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                    debug!("Kademlia bootstrap not possible yet: {e}");
                }
            }

            event_tx.send(NetEvent::ConnectionEstablished { connection_id })?;
        }

        SwarmEvent::OutgoingConnectionError {
            peer_id,
            error,
            connection_id,
        } => {
            if let Some(ref failed_peer) = peer_id {
                if let DialError::WrongPeerId {
                    obtained,
                    ref endpoint,
                } = error
                {
                    // The node at this address has a new PeerId (e.g. restarted with new keys).
                    // Remove the stale entry and add the new one so we don't loop.
                    // The stale entry can be re-learned from other peers' routing tables,
                    // so repeats are expected: handle them quietly (debug, no bootstrap)
                    // to avoid flooding the logs and re-fueling the dial loop.
                    let remote_addr = endpoint.get_remote_address().clone();
                    let mismatch_count = peer_id_mismatches.record_failure(failed_peer);
                    // The stale ID is being removed from the routing table, so its
                    // generic dial-failure history is no longer meaningful.
                    peer_failures.reset(failed_peer);
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

                        // Only publish the address to Kademlia if it wouldn't leak a
                        // loopback address to remote peers (see should_filter_loopback).
                        if !(should_filter_loopback(swarm) && is_loopback_addr(&remote_addr)) {
                            swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&obtained, corrected_addr.clone());
                        }

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

                    // Trigger Kademlia bootstrap to discover peers beyond direct
                    // connections — but only on the first mismatch: bootstrapping on
                    // every repeat re-learns the stale entry from neighbours and
                    // redials it, creating a self-sustaining loop.
                    if mismatch_count == 1 {
                        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                            debug!(
                                "Kademlia bootstrap after peer ID replacement not possible yet: {e}"
                            );
                        }
                    }
                } else {
                    let count = peer_failures.record_failure(failed_peer);

                    if count >= MAX_CONSECUTIVE_DIAL_FAILURES {
                        info!(
                            "Evicting unreachable peer {failed_peer} after {count} consecutive failures"
                        );
                        swarm.behaviour_mut().kademlia.remove_peer(failed_peer);
                        peer_failures.reset(failed_peer);
                    } else {
                        debug!(
                            "Dial failure for {failed_peer} (attempt {count}/{MAX_CONSECUTIVE_DIAL_FAILURES}): {error}"
                        );
                    }
                }
            } else {
                warn!("Failed to dial unknown peer: {error}");
            }

            event_tx.send(NetEvent::OutgoingConnectionError {
                connection_id,
                error: Arc::new(error),
            })?;
        }

        SwarmEvent::IncomingConnectionError { error, .. } => {
            let error_str = format!("{:#}", anyhow::Error::from(error));
            // Downgrade benign handshake failures to debug:
            // - "Local peer ID": self-dial attempt
            // - "aborted by peer": simultaneous connection dedup (both sides dialed,
            //   libp2p keeps one connection and the other side aborts the handshake)
            if error_str.contains("Local peer ID") || error_str.contains("aborted by peer") {
                debug!("{}", error_str);
            } else {
                warn!("Incoming connection error: {}", error_str);
            }
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
                error!("step={:?} error={}", step, e);
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
                    debug!("PUT RECORD SUCCESS: {:?}", key);
                    event_tx.send(NetEvent::DhtPutRecordSucceeded {
                        key,
                        correlation_id,
                    })?;
                }
                Err(error) => {
                    error!("PUT RECORD FAILED: {}", error);
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
            let gossip_data = GossipData::from_bytes(&message.data)?;
            event_tx.send(NetEvent::GossipData(gossip_data))?;
        }

        SwarmEvent::NewListenAddr { address, .. } => {
            trace!("Local node is listening on {address}");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed {
            peer_id,
            topic,
        })) => {
            debug!("Peer {} subscribed to {}", peer_id, topic);
            let count = swarm.behaviour().gossipsub.mesh_peers(&topic).count();
            event_tx.send(NetEvent::GossipSubscribed { count, topic })?;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::RequestResponse(
            RequestResponseEvent::Message {
                message:
                    RequestResponseMessage::Request {
                        request,
                        channel,
                        request_id,
                    },
                ..
            },
        )) => {
            debug!("Incoming request received (id={})", request_id);
            let responder = DirectResponder::new(request_id, ChannelType::Channel(channel), cmd_tx)
                .with_request(request);

            // received a request for events
            event_tx.send(NetEvent::IncomingRequest(IncomingRequest { responder }))?;
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
                request_id,
                error,
            },
        )) => {
            warn!(
                "Outbound request failed: peer={}, id={}, error={:?}",
                peer, request_id, error
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
                request_id,
                error,
            },
        )) => {
            warn!(
                "Inbound request failed: peer={}, id={}, error={:?}",
                peer, request_id, error
            );
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::RequestResponse(
            RequestResponseEvent::ResponseSent { peer, request_id },
        )) => {
            debug!("Response sent to peer={}, id={}", peer, request_id);
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Identify(
            libp2p::identify::Event::Received { peer_id, info, .. },
        )) => {
            debug!("Identify received from {peer_id}: {:?}", info.observed_addr);
            let filter = should_filter_loopback(swarm);
            for addr in &info.listen_addrs {
                if !(filter && is_loopback_addr(addr)) {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                }
            }
            if !is_loopback_addr(&info.observed_addr) {
                swarm.add_external_address(info.observed_addr);
            }
        }

        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            cause,
            ..
        } => {
            if num_established == 0 {
                let total = swarm.connected_peers().count();
                info!("Peer disconnected: {peer_id} (total: {total}, cause: {cause:?})");
            }
        }

        SwarmEvent::ListenerClosed {
            addresses, reason, ..
        } => {
            warn!("Listener closed on {addresses:?}: {reason:?}");
        }

        SwarmEvent::ListenerError { error, .. } => {
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
    event_tx: &broadcast::Sender<NetEvent>,
    correlator: &mut Correlator,
    command: NetCommand,
) -> Result<()> {
    match command {
        NetCommand::GossipPublish {
            data,
            topic,
            correlation_id,
        } => {
            handle_gossip_publish(swarm, event_tx, data, topic, correlation_id)?;
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
            if let Err(e) =
                handle_outgoing_request(swarm, correlator, correlation_id, payload, target)
            {
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
    event_tx: &broadcast::Sender<NetEvent>,
    data: GossipData,
    topic: String,
    correlation_id: CorrelationId,
) -> Result<()> {
    let bytes = data.to_bytes()?;
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
                error: Arc::new(e),
            })?;
        }
    }
    Ok(())
}

fn handle_dial(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &broadcast::Sender<NetEvent>,
    dial_opts: DialOpts,
) -> Result<()> {
    trace!("DIAL: {:?}", dial_opts);
    match swarm.dial(dial_opts) {
        Ok(v) => trace!("Dial returned {:?}", v),
        Err(error) => {
            warn!("Dialing error! {}", error);
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

fn handle_put_record(
    swarm: &mut Swarm<NodeBehaviour>,
    event_tx: &broadcast::Sender<NetEvent>,
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
    correlation_id: CorrelationId,
    payload: Vec<u8>,
    target: PeerTarget,
) -> Result<()> {
    let peer = match target {
        PeerTarget::Random => swarm
            .connected_peers()
            .choose(&mut rand::rng())
            .copied()
            .context("No connected peers available")?,
        PeerTarget::Specific(peer_id) => peer_id,
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
    use libp2p::kad::store::{MemoryStore, MemoryStoreConfig, RecordStore};
    use libp2p::kad::{Record, RecordKey};
    use libp2p::PeerId;
    use std::time::{Duration, Instant};

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
