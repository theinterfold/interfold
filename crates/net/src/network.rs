// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::collections::HashMap;

use anyhow::{ensure, Result};
use e3_config::{current_node_release, NetworkId, NetworkProfile};
use e3_events::{E3id, Event, EventContextAccessors, InterfoldEvent, SeqState};
use libp2p::{identify::Info, StreamProtocol};
use sha2::{Digest, Sha256};

pub(crate) const GOSSIP_WIRE_MAJOR: u16 = 3;
pub(crate) const SYNC_WIRE_MAJOR: u16 = 3;
const IDENTIFY_MAJOR: u16 = 1;
const KADEMLIA_VERSION: &str = "1.0.0";

/// Exact libp2p protocol names supported by this release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolSet {
    gossip_topic: String,
    identify_protocol: String,
    kademlia_protocol: StreamProtocol,
    sync_protocols: Vec<StreamProtocol>,
}

impl ProtocolSet {
    pub fn new(network_id: NetworkId) -> Result<Self> {
        Self::with_deployments(network_id, deployment_fingerprint(&HashMap::new()))
    }

    fn with_deployments(network_id: NetworkId, deployments: [u8; 32]) -> Result<Self> {
        Self::with_protocol_version(
            network_id,
            deployments,
            current_node_release().protocol_version,
        )
    }

    fn with_protocol_version(
        network_id: NetworkId,
        deployments: [u8; 32],
        protocol_version: u32,
    ) -> Result<Self> {
        let network_id = network_id.to_string();
        let deployments = hex::encode(deployments);
        let prefix = format!("interfold/{network_id}/protocol/{protocol_version}");
        let kademlia_protocol =
            StreamProtocol::try_from_owned(format!("/{prefix}/kad/{KADEMLIA_VERSION}"))?;
        let sync_protocol =
            StreamProtocol::try_from_owned(format!("/{prefix}/sync/{SYNC_WIRE_MAJOR}.0.0"))?;
        Ok(Self {
            gossip_topic: format!("{prefix}/events/{GOSSIP_WIRE_MAJOR}"),
            identify_protocol: format!("{prefix}/deployments/{deployments}/{IDENTIFY_MAJOR}"),
            kademlia_protocol,
            // New protocols must be inserted first. Multistream-select uses this order for
            // outbound negotiation. Keep an older protocol only while its wire schema is safe.
            sync_protocols: vec![sync_protocol],
        })
    }

    pub fn gossip_topic(&self) -> &str {
        &self.gossip_topic
    }

    pub fn identify_protocol(&self) -> &str {
        &self.identify_protocol
    }

    pub fn kademlia_protocol(&self) -> StreamProtocol {
        self.kademlia_protocol.clone()
    }

    pub fn sync_protocols(&self) -> &[StreamProtocol] {
        &self.sync_protocols
    }

    pub fn supports_peer(&self, info: &Info) -> Result<()> {
        ensure!(
            info.protocol_version == self.identify_protocol,
            "peer network identity '{}' does not match '{}'",
            info.protocol_version,
            self.identify_protocol
        );
        ensure!(
            info.protocols.contains(&self.kademlia_protocol),
            "peer does not support {}",
            self.kademlia_protocol
        );
        ensure!(
            self.sync_protocols
                .iter()
                .any(|protocol| info.protocols.contains(protocol)),
            "peer does not support a compatible historical-sync protocol"
        );
        Ok(())
    }
}

/// Network and deployment checks applied before peer data reaches the EventBus.
#[derive(Clone, Debug)]
pub struct NetworkPolicy {
    profile: NetworkProfile,
    protocols: ProtocolSet,
    deployments: HashMap<u64, [u8; 20]>,
    unrestricted: bool,
}

impl NetworkPolicy {
    pub fn new(
        profile: NetworkProfile,
        deployments: impl IntoIterator<Item = (u64, [u8; 20])>,
    ) -> Result<Self> {
        let mut deployment_map = HashMap::new();
        for (chain_id, address) in deployments {
            if let Some(existing) = deployment_map.insert(chain_id, address) {
                ensure!(
                    existing == address,
                    "chain {chain_id} has conflicting Interfold deployment addresses"
                );
            }
        }
        ensure!(
            !deployment_map.is_empty(),
            "network policy requires at least one Interfold deployment"
        );
        let protocols =
            ProtocolSet::with_deployments(profile.id(), deployment_fingerprint(&deployment_map))?;
        Ok(Self {
            profile,
            protocols,
            deployments: deployment_map,
            unrestricted: false,
        })
    }

    pub fn local_unrestricted() -> Self {
        let profile = NetworkProfile::local();
        let deployments = HashMap::new();
        let protocols =
            ProtocolSet::with_deployments(profile.id(), deployment_fingerprint(&deployments))
                .expect("local network protocols are valid");
        Self {
            profile,
            protocols,
            deployments,
            unrestricted: true,
        }
    }

    pub fn profile(&self) -> &NetworkProfile {
        &self.profile
    }

    pub fn protocols(&self) -> &ProtocolSet {
        &self.protocols
    }

    pub fn allows_chain(&self, chain_id: u64) -> bool {
        self.unrestricted || self.deployments.contains_key(&chain_id)
    }

    /// Return the configured Interfold deployment binding for a chain.
    ///
    /// Local test policies use an all-zero binding because they do not configure contracts.
    pub fn deployment_binding(&self, chain_id: u64) -> Result<[u8; 20]> {
        if self.unrestricted {
            return Ok([0; 20]);
        }
        self.deployments.get(&chain_id).copied().ok_or_else(|| {
            anyhow::anyhow!(
                "chain {chain_id} is not part of the '{}' network profile",
                self.profile.name()
            )
        })
    }

    pub fn validate_e3_id(&self, e3_id: &E3id) -> Result<()> {
        self.deployment_binding(e3_id.chain_id())?;
        Ok(())
    }

    pub fn validate_event<S: SeqState>(&self, event: &InterfoldEvent<S>) -> Result<()> {
        let e3_id = event.get_e3_id().ok_or_else(|| {
            anyhow::anyhow!(
                "network event type {} does not contain an E3 ID",
                event.event_type()
            )
        })?;
        self.validate_e3_id(&e3_id)?;
        ensure!(
            event.aggregate_id().to_chain_id() == Some(e3_id.chain_id()),
            "network event aggregate {} does not match E3 chain {}",
            event.aggregate_id(),
            e3_id.chain_id()
        );
        Ok(())
    }
}

fn deployment_fingerprint(deployments: &HashMap<u64, [u8; 20]>) -> [u8; 32] {
    let mut entries: Vec<_> = deployments.iter().collect();
    entries.sort_unstable_by_key(|(chain_id, _)| **chain_id);
    let mut hasher = Sha256::new();
    for (chain_id, address) in entries {
        hasher.update(chain_id.to_be_bytes());
        hasher.update(address);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_ids_produce_disjoint_protocol_names() {
        let mainnet = ProtocolSet::new(NetworkProfile::mainnet().id()).unwrap();
        let sepolia = ProtocolSet::new(NetworkProfile::sepolia().id()).unwrap();

        assert_ne!(mainnet.gossip_topic(), sepolia.gossip_topic());
        assert_ne!(mainnet.identify_protocol(), sepolia.identify_protocol());
        assert_ne!(mainnet.kademlia_protocol(), sepolia.kademlia_protocol());
        assert_ne!(mainnet.sync_protocols(), sepolia.sync_protocols());
        assert!(!mainnet
            .identify_protocol()
            .contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn protocol_set_does_not_enable_the_unscoped_legacy_protocol() {
        let protocols = ProtocolSet::new(NetworkProfile::mainnet().id()).unwrap();
        assert!(protocols
            .sync_protocols()
            .iter()
            .all(|protocol| protocol.as_ref() != "/interfold/sync/0.0.1"));
        assert_ne!(protocols.gossip_topic(), "interfold-gossip");
    }

    #[test]
    fn deployment_changes_produce_different_identify_networks() {
        let first = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])]).unwrap();
        let second = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [2; 20])]).unwrap();
        assert_ne!(
            first.protocols().identify_protocol(),
            second.protocols().identify_protocol()
        );
        assert_eq!(
            first.protocols().gossip_topic(),
            second.protocols().gossip_topic()
        );
    }

    #[test]
    fn protocol_versions_produce_disjoint_networks() {
        let network_id = NetworkProfile::mainnet().id();
        let deployments = deployment_fingerprint(&HashMap::new());
        let first = ProtocolSet::with_protocol_version(network_id, deployments, 1).unwrap();
        let second = ProtocolSet::with_protocol_version(network_id, deployments, 2).unwrap();

        assert_ne!(first.gossip_topic(), second.gossip_topic());
        assert_ne!(first.identify_protocol(), second.identify_protocol());
        assert_ne!(first.kademlia_protocol(), second.kademlia_protocol());
        assert_ne!(first.sync_protocols(), second.sync_protocols());
    }

    #[test]
    fn conflicting_deployments_for_one_chain_are_rejected() {
        let error = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20]), (1, [2; 20])])
            .unwrap_err();
        assert!(error.to_string().contains("conflicting"));
    }

    #[test]
    fn empty_production_policy_is_rejected() {
        let error = NetworkPolicy::new(NetworkProfile::mainnet(), []).unwrap_err();
        assert!(error.to_string().contains("at least one"));
    }

    #[test]
    fn local_unrestricted_policy_explicitly_allows_unconfigured_chains() {
        let policy = NetworkPolicy::local_unrestricted();
        assert!(policy.allows_chain(31_337));
        assert_eq!(policy.deployment_binding(31_337).unwrap(), [0; 20]);
    }
}
