// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{collections::HashMap, sync::Arc};

use e3_net::{
    events::{NetCommand, NetEvent},
    ContentHash, NetChannelBridge, NetInterfaceInverted,
};
use e3_utils::ArcBytes;
use libp2p::{gossipsub::MessageId, kad::GetRecordError, PeerId};
use tokio::sync::{broadcast, RwLock};
use tracing::{error, warn};

#[derive(Debug, Clone)]
pub struct Libp2pMock {
    store: Arc<RwLock<HashMap<ContentHash, ArcBytes>>>,
    nodes: Arc<RwLock<HashMap<PeerId, NetChannelBridge>>>,
}

impl Default for Libp2pMock {
    fn default() -> Self {
        Self::new()
    }
}

impl Libp2pMock {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
            nodes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_node(&self, peer_id: PeerId, handle: NetChannelBridge) {
        self.nodes.write().await.insert(peer_id, handle.clone());

        let src_event_tx = handle.event_tx();
        let mut src_cmd_rx = handle.cmd_rx();
        let store = self.store.clone();
        let nodes = self.nodes.clone();
        let self_peer_id = peer_id;

        tokio::spawn(async move {
            loop {
                match src_cmd_rx.recv().await {
                    Ok(NetCommand::GossipPublish {
                        data,
                        correlation_id,
                        ..
                    }) => {
                        // Broadcast to all other nodes
                        let peers = nodes.read().await;
                        for (id, peer) in peers.iter() {
                            if *id == self_peer_id {
                                continue;
                            }
                            if let Err(e) = peer.event_tx().send(NetEvent::GossipData(data.clone()))
                            {
                                error!("Libp2pMock: failed to forward GossipData to {id}: {e}");
                            }
                        }

                        let message_id =
                            MessageId::new(&format!("{correlation_id:?}").into_bytes());
                        if let Err(e) = src_event_tx.send(NetEvent::GossipPublished {
                            correlation_id,
                            message_id,
                        }) {
                            error!("Libp2pMock: failed to send GossipPublished: {e}");
                        }
                    }
                    Ok(NetCommand::DhtPutRecord {
                        correlation_id,
                        key,
                        value,
                        ..
                    }) => {
                        store.write().await.insert(key.clone(), value);

                        if let Err(e) = src_event_tx.send(NetEvent::DhtPutRecordSucceeded {
                            key,
                            correlation_id,
                        }) {
                            error!("Libp2pMock: failed to send DhtPutRecordSucceeded: {e}");
                        }
                    }
                    Ok(NetCommand::DhtGetRecord {
                        correlation_id,
                        key,
                    }) => {
                        let maybe_value = store.read().await.get(&key).cloned();

                        if let Some(value) = maybe_value {
                            if let Err(e) = src_event_tx.send(NetEvent::DhtGetRecordSucceeded {
                                key,
                                correlation_id,
                                value,
                            }) {
                                error!("Libp2pMock: failed to send DhtGetRecordSucceeded: {e}");
                            }
                        } else if let Err(e) = src_event_tx.send(NetEvent::DhtGetRecordError {
                            correlation_id,
                            error: GetRecordError::NotFound {
                                key: libp2p::kad::RecordKey::new(&key.into_inner()),
                                closest_peers: vec![],
                            },
                        }) {
                            error!("Libp2pMock: failed to send DhtGetRecordError: {e}");
                        }
                    }
                    Ok(NetCommand::DhtRemoveRecords { keys }) => {
                        let mut s = store.write().await;
                        for key in keys {
                            s.remove(&key);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Libp2pMock: cmd receiver lagged by {n} messages");
                        continue;
                    }
                    Err(_) => break,
                    _ => continue,
                }
            }
        });
    }
}
