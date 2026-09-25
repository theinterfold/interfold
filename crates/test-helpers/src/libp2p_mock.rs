// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use e3_net::{
    events::{GossipData, NetCommand, NetEvent},
    ContentHash, NetChannelBridge, NetInterfaceInverted,
};
use e3_utils::ArcBytes;
use libp2p::{gossipsub::MessageId, kad::GetRecordError, PeerId};
use tokio::sync::{broadcast, watch, RwLock};
use tracing::{error, warn};

#[derive(Debug, Clone)]
pub struct Libp2pMock {
    store: Arc<RwLock<HashMap<ContentHash, ArcBytes>>>,
    state: Arc<RwLock<MockState>>,
    next_generation: Arc<AtomicU64>,
    /// Counts commands dropped because their node was offline or replaced.
    dropped_commands: Arc<watch::Sender<u64>>,
}

#[derive(Debug, Default)]
struct MockState {
    nodes: HashMap<PeerId, (u64, NetChannelBridge)>,
    generations: HashMap<PeerId, u64>,
    // The bridge has no historical peer-sync RPC. Retain gossip only during a test restart.
    missed_gossip: HashMap<PeerId, Vec<GossipData>>,
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
            state: Arc::new(RwLock::new(MockState::default())),
            next_generation: Arc::new(AtomicU64::new(1)),
            dropped_commands: Arc::new(watch::Sender::new(0)),
        }
    }

    pub async fn add_node(&self, peer_id: PeerId, handle: NetChannelBridge) {
        self.add_node_replacing(None, peer_id, handle).await;
    }

    pub async fn add_replacement_node(
        &self,
        old_peer_id: PeerId,
        peer_id: PeerId,
        handle: NetChannelBridge,
    ) {
        self.add_node_replacing(Some(old_peer_id), peer_id, handle)
            .await;
    }

    async fn add_node_replacing(
        &self,
        old_peer_id: Option<PeerId>,
        peer_id: PeerId,
        handle: NetChannelBridge,
    ) {
        let src_event_tx = handle.event_tx();
        let mut src_cmd_rx = handle.cmd_rx();
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        {
            let mut state = self.state.write().await;
            if let Some(old_peer_id) = old_peer_id {
                state.generations.remove(&old_peer_id);
                if let Some(missed) = state.missed_gossip.remove(&old_peer_id) {
                    state
                        .missed_gossip
                        .entry(peer_id)
                        .or_default()
                        .extend(missed);
                }
            }
            state.generations.insert(peer_id, generation);
            state.nodes.insert(peer_id, (generation, handle.clone()));
            if let Some(missed) = state.missed_gossip.remove(&peer_id) {
                for data in missed {
                    if let Err(e) = handle.event_tx().send(NetEvent::GossipData(data)) {
                        error!("Libp2pMock: failed to replay missed GossipData to {peer_id}: {e}");
                    }
                }
            }
        }
        let store = self.store.clone();
        let state = self.state.clone();
        let dropped_commands = self.dropped_commands.clone();
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

                let state_snapshot = state.read().await;
                if state_snapshot.generations.get(&self_peer_id) != Some(&generation) {
                    dropped_commands.send_modify(|count| *count += 1);
                    break;
                }
                let active = state_snapshot.nodes.contains_key(&self_peer_id);
                drop(state_snapshot);
                if !active {
                    dropped_commands.send_modify(|count| *count += 1);
                    continue;
                }

                match command {
                    NetCommand::GossipPublish {
                        data,
                        correlation_id,
                        ..
                    } => {
                        // Broadcast to all other nodes
                        let mut state = state.write().await;
                        for (id, (_, peer)) in state.nodes.iter() {
                            if *id == self_peer_id {
                                continue;
                            }
                            if let Err(e) = peer.event_tx().send(NetEvent::GossipData(data.clone()))
                            {
                                error!("Libp2pMock: failed to forward GossipData to {id}: {e}");
                            }
                        }
                        for (id, missed) in state.missed_gossip.iter_mut() {
                            if *id != self_peer_id {
                                missed.push(data.clone());
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
        let mut state = self.state.write().await;
        state.nodes.remove(&peer_id);
        state.missed_gossip.remove(&peer_id);
    }

    pub async fn disconnect_node_for_restart(&self, peer_id: PeerId) {
        let mut state = self.state.write().await;
        state.nodes.remove(&peer_id);
        state.missed_gossip.entry(peer_id).or_default();
    }

    pub async fn reconnect_node(&self, peer_id: PeerId, handle: NetChannelBridge) {
        let mut state = self.state.write().await;
        let Some(&generation) = state.generations.get(&peer_id) else {
            warn!("Libp2pMock: cannot reconnect unknown peer {peer_id}");
            return;
        };
        state.nodes.insert(peer_id, (generation, handle.clone()));
        if let Some(missed) = state.missed_gossip.remove(&peer_id) {
            for data in missed {
                if let Err(e) = handle.event_tx().send(NetEvent::GossipData(data)) {
                    error!("Libp2pMock: failed to replay missed GossipData to {peer_id}: {e}");
                }
            }
        }
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
        let mut dropped = mock.dropped_commands.subscribe();
        bridge
            .cmd_tx()
            .send(NetCommand::DhtPutRecord {
                correlation_id: CorrelationId::new(),
                expires: None,
                value: ArcBytes::from_bytes(b"offline"),
                key: offline_key.clone(),
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), dropped.changed())
            .await
            .unwrap()
            .unwrap();
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
        let mut dropped = mock.dropped_commands.subscribe();
        sender
            .cmd_tx()
            .send(NetCommand::gossip_publish(
                "test".into(),
                GossipData::GossipBytes(vec![1]),
                CorrelationId::new(),
            ))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), dropped.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            received.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        mock.reconnect_node(sender_id, sender.clone()).await;
        sender
            .cmd_tx()
            .send(NetCommand::gossip_publish(
                "test".into(),
                GossipData::GossipBytes(vec![2]),
                CorrelationId::new(),
            ))
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

    #[tokio::test]
    async fn replacement_receives_gossip_missed_during_restart() {
        let mock = Libp2pMock::new();
        let sender_id = PeerId::random();
        let receiver_id = PeerId::random();
        let (_, sender) = create_channel_bridge();
        let (_, old_receiver) = create_channel_bridge();
        let (_, new_receiver) = create_channel_bridge();
        mock.add_node(sender_id, sender.clone()).await;
        mock.add_node(receiver_id, old_receiver.clone()).await;
        let mut sender_events = sender.event_rx();
        let mut receiver_events = new_receiver.event_rx();

        mock.disconnect_node_for_restart(receiver_id).await;
        sender
            .cmd_tx()
            .send(NetCommand::gossip_publish(
                "test".into(),
                GossipData::GossipBytes(vec![7]),
                CorrelationId::new(),
            ))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(NetEvent::GossipPublished { .. }) = sender_events.recv().await {
                    break;
                }
            }
        })
        .await
        .unwrap();

        mock.add_replacement_node(receiver_id, PeerId::random(), new_receiver)
            .await;
        let recovered = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(NetEvent::GossipData(data)) = receiver_events.recv().await {
                    break data;
                }
            }
        })
        .await
        .unwrap();
        assert!(matches!(recovered, GossipData::GossipBytes(bytes) if bytes == [7]));

        let stale_key = ContentHash::from_content(b"stale");
        let mut dropped = mock.dropped_commands.subscribe();
        old_receiver
            .cmd_tx()
            .send(NetCommand::DhtPutRecord {
                correlation_id: CorrelationId::new(),
                expires: None,
                value: ArcBytes::from_bytes(b"stale"),
                key: stale_key.clone(),
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), dropped.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(!mock.store.read().await.contains_key(&stale_key));
    }
}
