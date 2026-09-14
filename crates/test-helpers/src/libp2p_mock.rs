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
                let command = match src_cmd_rx.recv().await {
                    Ok(command) => command,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Libp2pMock: cmd receiver lagged by {n} messages");
                        continue;
                    }
                    Err(_) => break,
                };

                if !nodes.read().await.contains_key(&self_peer_id) {
                    continue;
                }

                match command {
                    NetCommand::GossipPublish {
                        data,
                        correlation_id,
                        ..
                    } => {
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
                    NetCommand::DhtPutRecord {
                        correlation_id,
                        key,
                        value,
                        ..
                    } => {
                        store.write().await.insert(key.clone(), value);

                        if let Err(e) = src_event_tx.send(NetEvent::DhtPutRecordSucceeded {
                            key,
                            correlation_id,
                        }) {
                            error!("Libp2pMock: failed to send DhtPutRecordSucceeded: {e}");
                        }
                    }
                    NetCommand::DhtGetRecord {
                        correlation_id,
                        key,
                    } => {
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
                    NetCommand::DhtRemoveRecords { keys } => {
                        let mut s = store.write().await;
                        for key in keys {
                            s.remove(&key);
                        }
                    }
                    _ => continue,
                }
            }
        });
    }

    pub async fn disconnect_node(&self, peer_id: PeerId) {
        self.nodes.write().await.remove(&peer_id);
    }

    pub async fn reconnect_node(&self, peer_id: PeerId, handle: NetChannelBridge) {
        self.nodes.write().await.insert(peer_id, handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::CorrelationId;
    use e3_net::create_channel_bridge;
    use e3_net::events::GossipData;
    use std::time::Duration;

    #[tokio::test]
    async fn disconnected_node_cannot_publish_dht_records() {
        let mock = Libp2pMock::new();
        let peer_id = PeerId::random();
        let (_, bridge) = create_channel_bridge();
        mock.add_node(peer_id, bridge.clone()).await;

        let offline_key = ContentHash::from_content(b"offline");
        mock.disconnect_node(peer_id).await;
        bridge
            .cmd_tx()
            .send(NetCommand::DhtPutRecord {
                correlation_id: CorrelationId::new(),
                expires: None,
                value: ArcBytes::from_bytes(b"offline"),
                key: offline_key.clone(),
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!mock.store.read().await.contains_key(&offline_key));

        let online_key = ContentHash::from_content(b"online");
        mock.reconnect_node(peer_id, bridge.clone()).await;
        let mut events = bridge.event_rx();
        bridge
            .cmd_tx()
            .send(NetCommand::DhtPutRecord {
                correlation_id: CorrelationId::new(),
                expires: None,
                value: ArcBytes::from_bytes(b"online"),
                key: online_key.clone(),
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(NetEvent::DhtPutRecordSucceeded { key, .. }) = events.recv().await {
                    if key == online_key {
                        break;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert!(mock.store.read().await.contains_key(&online_key));
        assert!(!mock.store.read().await.contains_key(&offline_key));
    }

    #[tokio::test]
    async fn disconnected_node_cannot_gossip_to_peers() {
        let mock = Libp2pMock::new();
        let sender_id = PeerId::random();
        let receiver_id = PeerId::random();
        let (_, sender) = create_channel_bridge();
        let (_, receiver) = create_channel_bridge();
        mock.add_node(sender_id, sender.clone()).await;
        mock.add_node(receiver_id, receiver.clone()).await;
        let mut received = receiver.event_rx();

        mock.disconnect_node(sender_id).await;
        sender
            .cmd_tx()
            .send(NetCommand::GossipPublish {
                topic: "test".into(),
                data: GossipData::GossipBytes(vec![1]),
                correlation_id: CorrelationId::new(),
            })
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), async {
            loop {
                if let Ok(NetEvent::GossipData(_)) = received.recv().await {
                    break;
                }
            }
        })
        .await
        .is_err());

        mock.reconnect_node(sender_id, sender.clone()).await;
        sender
            .cmd_tx()
            .send(NetCommand::GossipPublish {
                topic: "test".into(),
                data: GossipData::GossipBytes(vec![2]),
                correlation_id: CorrelationId::new(),
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(NetEvent::GossipData(GossipData::GossipBytes(bytes))) =
                    received.recv().await
                {
                    if bytes == [2] {
                        break;
                    }
                }
            }
        })
        .await
        .unwrap();
    }
}
