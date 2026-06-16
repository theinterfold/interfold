// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Addr;
use anyhow::Result;
use e3_data::{DataStore, InMemStore, StoreAddr};
use e3_events::{BusHandle, HistoryCollector, InterfoldEvent};
use e3_net::NetChannelBridge;
use libp2p::PeerId;

/// The kind of network interface backing a ciphernode.
#[derive(Debug, Clone)]
pub enum NetInterfaceKind {
    /// Real libp2p networking (production).
    Libp2p,
    /// In-process channel bridge (tests / benchmarks).
    ChannelBridge(NetChannelBridge),
}

impl NetInterfaceKind {
    /// Extract the channel bridge, failing if this is a libp2p interface.
    pub fn into_channel_bridge(self) -> Result<NetChannelBridge> {
        match self {
            NetInterfaceKind::ChannelBridge(bridge) => Ok(bridge),
            NetInterfaceKind::Libp2p => Err(anyhow::anyhow!(
                "No channel bridge exists — node is using libp2p networking"
            )),
        }
    }
}

/// A sharable handle to a Ciphernode. Clones are available for use in the
/// CiphernodeSystem but they cannot await the task.
#[derive(Debug)]
pub struct CiphernodeHandle {
    pub address: String,
    pub store: DataStore,
    pub bus: BusHandle,
    /// Optional event history collector. Populated when the builder is configured
    /// with [`CiphernodeBuilder::with_history_collector`].
    pub history: Option<Addr<HistoryCollector<InterfoldEvent>>>,
    /// Optional error event collector. Populated when the builder is configured
    /// with [`CiphernodeBuilder::with_error_collector`].
    pub errors: Option<Addr<HistoryCollector<InterfoldEvent>>>,
    pub peer_id: PeerId,
    pub net_interface: NetInterfaceKind,
}

impl PartialEq for CiphernodeHandle {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.peer_id == other.peer_id
    }
}

impl Eq for CiphernodeHandle {}

impl CiphernodeHandle {
    pub fn new(
        address: String,
        store: DataStore,
        bus: BusHandle,
        history: Option<Addr<HistoryCollector<InterfoldEvent>>>,
        errors: Option<Addr<HistoryCollector<InterfoldEvent>>>,
        peer_id: PeerId,
        net_interface: NetInterfaceKind,
    ) -> Self {
        Self {
            address,
            store,
            bus,
            history,
            errors,
            peer_id,
            net_interface,
        }
    }

    pub fn bus(&self) -> &BusHandle {
        &self.bus
    }

    pub fn history(&self) -> Option<Addr<HistoryCollector<InterfoldEvent>>> {
        self.history.clone()
    }

    pub fn errors(&self) -> Option<Addr<HistoryCollector<InterfoldEvent>>> {
        self.errors.clone()
    }

    pub fn address(&self) -> String {
        self.address.clone()
    }

    pub fn store(&self) -> &DataStore {
        &self.store
    }

    /// Extract the channel bridge for test network simulation.
    /// Returns an error if the node is using libp2p networking.
    pub fn channel_bridge(&self) -> Result<NetChannelBridge> {
        self.net_interface.clone().into_channel_bridge()
    }

    pub fn in_mem_store(&self) -> Option<&Addr<InMemStore>> {
        let addr = self.store.get_addr();
        if let StoreAddr::InMem(ref store) = addr {
            return Some(store);
        }
        None
    }
}
