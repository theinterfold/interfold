// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Thread-safe, read-only projection of live libp2p connection state.
//!
//! This is operational state, not protocol state. It is rebuilt by libp2p as
//! connections change and is therefore intentionally not in the EventStore.

use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectedPeer {
    pub peer_id: String,
    pub remote_address: String,
    pub direction: String,
    pub connections: u32,
    pub connected_at_ms: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct NetworkSnapshot {
    pub configured_peers: usize,
    pub connected_peers: Vec<ConnectedPeer>,
    pub listen_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Default)]
struct NetworkState {
    configured_peers: usize,
    connected_peers: BTreeMap<String, ConnectedPeer>,
    listen_addresses: Vec<String>,
    last_error: Option<String>,
}

/// Cheaply cloneable handle shared by the transport and node dashboard.
#[derive(Clone, Default)]
pub struct NetworkStatus(Arc<RwLock<NetworkState>>);

impl std::fmt::Debug for NetworkStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkStatus")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl NetworkStatus {
    pub fn new(configured_peers: usize) -> Self {
        Self(Arc::new(RwLock::new(NetworkState {
            configured_peers,
            ..NetworkState::default()
        })))
    }

    pub fn connected(
        &self,
        peer_id: impl Into<String>,
        remote_address: impl Into<String>,
        direction: impl Into<String>,
        connections: u32,
    ) {
        let peer_id = peer_id.into();
        if let Ok(mut state) = self.0.write() {
            let connected_at_ms = state
                .connected_peers
                .get(&peer_id)
                .map(|peer| peer.connected_at_ms)
                .unwrap_or_else(now_ms);
            state.connected_peers.insert(
                peer_id.clone(),
                ConnectedPeer {
                    peer_id,
                    remote_address: remote_address.into(),
                    direction: direction.into(),
                    connections,
                    connected_at_ms,
                },
            );
            state.last_error = None;
        }
    }

    pub fn disconnected(&self, peer_id: &str, remaining_connections: u32) {
        if let Ok(mut state) = self.0.write() {
            if remaining_connections == 0 {
                state.connected_peers.remove(peer_id);
            } else if let Some(peer) = state.connected_peers.get_mut(peer_id) {
                peer.connections = remaining_connections;
            }
        }
    }

    pub fn listening_on(&self, address: impl Into<String>) {
        let address = address.into();
        if let Ok(mut state) = self.0.write() {
            if !state.listen_addresses.contains(&address) {
                state.listen_addresses.push(address);
                state.listen_addresses.sort();
            }
        }
    }

    pub fn stopped_listening<I, S>(&self, addresses: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if let Ok(mut state) = self.0.write() {
            for address in addresses {
                state
                    .listen_addresses
                    .retain(|current| current != address.as_ref());
            }
        }
    }

    pub fn record_error(&self, error: impl Into<String>) {
        if let Ok(mut state) = self.0.write() {
            state.last_error = Some(error.into());
        }
    }

    pub fn snapshot(&self) -> NetworkSnapshot {
        self.0
            .read()
            .map(|state| NetworkSnapshot {
                configured_peers: state.configured_peers,
                connected_peers: state.connected_peers.values().cloned().collect(),
                listen_addresses: state.listen_addresses.clone(),
                last_error: state.last_error.clone(),
            })
            .unwrap_or_default()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_connections_without_resetting_first_seen_time() {
        let status = NetworkStatus::new(2);
        status.connected("peer-a", "/ip4/127.0.0.1", "outbound", 1);
        let first_seen = status.snapshot().connected_peers[0].connected_at_ms;

        status.connected("peer-a", "/ip4/127.0.0.1", "outbound", 2);
        status.listening_on("/ip4/127.0.0.1/udp/9090/quic-v1");
        let snapshot = status.snapshot();
        assert_eq!(snapshot.configured_peers, 2);
        assert_eq!(snapshot.connected_peers.len(), 1);
        assert_eq!(snapshot.connected_peers[0].connections, 2);
        assert_eq!(snapshot.connected_peers[0].connected_at_ms, first_seen);

        status.stopped_listening(["/ip4/127.0.0.1/udp/9090/quic-v1"]);
        assert!(status.snapshot().listen_addresses.is_empty());

        status.disconnected("peer-a", 0);
        assert!(status.snapshot().connected_peers.is_empty());
    }
}
