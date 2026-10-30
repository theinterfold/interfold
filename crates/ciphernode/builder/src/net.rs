// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The network interface and the network policy of the node.

use super::{startup::Storage, CiphernodeBuilder};
use crate::NetInterfaceKind;
use anyhow::Result;
use e3_config::NetworkProfile;
use e3_data::RepositoriesFactory;
use e3_events::{AggregateId, BusHandle, E3id};
use e3_evm::Chains;
use e3_net::{
    create_channel_bridge_with_application_event_capacity, recover_document_state,
    setup_libp2p_keypair, setup_net_interface, setup_net_with_limits_and_interests,
    NetEventBufferHandle, NetRepositoryFactory, NetworkPolicy, NetworkStatus,
};
use e3_sync::NodeRole;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};

/// The started network of the node.
pub(super) struct Network {
    pub peer_id: PeerId,
    pub kind: NetInterfaceKind,
    pub status: NetworkStatus,
    pub buffer: NetEventBufferHandle,
}

impl CiphernodeBuilder {
    /// Recover the document state of the restored committees, then start the network interface
    /// and its event buffer.
    pub(super) async fn start_network(
        &self,
        storage: &Storage,
        bus: &BusHandle,
        selected_party_ids: HashMap<E3id, u64>,
    ) -> Result<Network> {
        let network = self.network_policy(&storage.chains)?;
        let recovered_documents = recover_document_state(
            &storage.seq_eventstore,
            &storage
                .eventstore_aggregate_config
                .indexed_ids()
                .into_iter()
                .map(AggregateId::new)
                .collect::<Vec<_>>(),
            &selected_party_ids.keys().cloned().collect::<HashSet<_>>(),
        )
        .await?;
        let (peer_id, interface, kind) = self.setup_networking(&storage.store, &network).await?;
        let status = interface.status();
        let buffer = setup_net_with_limits_and_interests(
            &network,
            bus.clone(),
            storage.eventstore.ts(),
            interface,
            self.max_buffered_net_events,
            self.max_buffered_net_bytes,
            selected_party_ids,
            recovered_documents,
            // A bootstrap node uses no E3 history, so it starts without it when no peer can serve
            // it. A lone seed would otherwise wait for its startup deadline while an E3 is open.
            self.role() == NodeRole::Bootstrap,
        )?;
        Ok(Network {
            peer_id,
            kind,
            status,
            buffer,
        })
    }

    /// Start libp2p when networking is configured, and an in-process channel bridge otherwise.
    async fn setup_networking(
        &self,
        store: &e3_data::DataStore,
        network: &NetworkPolicy,
    ) -> Result<(PeerId, e3_net::NetInterfaceHandle, NetInterfaceKind)> {
        if let Some(net_config) = &self.net_config {
            let repositories = store.repositories();
            let keypair = setup_libp2p_keypair(repositories.libp2p_keypair(), &self.cipher).await?;
            let peer_id = keypair.peer_id();
            let interface = setup_net_interface(
                network.clone(),
                keypair,
                net_config.peers.clone(),
                net_config.quic_port,
                self.max_buffered_net_events,
            )?;
            Ok((peer_id, interface, NetInterfaceKind::Libp2p))
        } else {
            let (interface, channel_bridge) =
                create_channel_bridge_with_application_event_capacity(self.max_buffered_net_events);
            let peer_id = PeerId::random();
            Ok((
                peer_id,
                interface,
                NetInterfaceKind::ChannelBridge(channel_bridge),
            ))
        }
    }

    fn network_policy(&self, chains: &Chains) -> Result<NetworkPolicy> {
        let profile = self
            .net_config
            .as_ref()
            .map(|config| config.network.clone())
            .unwrap_or_else(NetworkProfile::local);
        let mut deployments = Vec::new();
        for chain in chains.enabled() {
            deployments.push((
                chain.chain_id,
                chain.config.contracts.interfold.address()?.into_array(),
            ));
        }
        if deployments.is_empty() && profile.name() == "local" {
            return Ok(NetworkPolicy::local_unrestricted());
        }
        NetworkPolicy::new(profile, deployments)
    }
}
