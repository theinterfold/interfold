// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{collections::BTreeSet, fmt, str::FromStr};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::chain_config::ChainConfig;

pub const MAINNET_BOOTSTRAP_PEER: &str = "/dnsaddr/bootstrap.interfold.network";
pub const SEPOLIA_BOOTSTRAP_PEER: &str = "/dnsaddr/bootstrap-sepolia.interfold.network";

// Built-in IDs are hardcoded SHA-256 digests of the documented UTF-8 labels.
// The digest input does not include a trailing newline.
// Do not change an ID after its network is released.
// Changing an ID creates a separate P2P network.
//
// Label: `interfold:p2p-network:v1:mainnet`
const MAINNET_NETWORK_ID: &str = "c3e81f904b0a8129dce0a85a8d48958a3ca5ee3aea6c32b623fcf66b35728acb";
// Label: `interfold:p2p-network:v1:sepolia`
const SEPOLIA_NETWORK_ID: &str = "ab33954b5b3fadf808f03a7c8a7dd159a29ac5950e6c3d724f76ed4c26c9e5c2";
// Label: `interfold:p2p-network:v1:local`
const LOCAL_NETWORK_ID: &str = "d7cec7f3c090b451f4ff10461b424728e320f72cf3dada907c5bdfe5570a5807";

/// Stable network identity used by every Interfold libp2p protocol.
///
/// A release or contract upgrade must not change this value. A separate
/// deployment must use a different value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetworkId([u8; 32]);

impl NetworkId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl FromStr for NetworkId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let bytes = hex::decode(value).context("network_id must be hexadecimal")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("network_id must contain exactly 32 bytes"))?;
        Ok(Self(bytes))
    }
}

impl Serialize for NetworkId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NetworkId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Resolved network identity and bootstrap policy for one node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkProfile {
    name: String,
    id: NetworkId,
    bootstrap_peers: Vec<String>,
}

impl NetworkProfile {
    pub fn resolve(
        configured_name: Option<&str>,
        configured_id: Option<NetworkId>,
        chains: &[ChainConfig],
    ) -> Result<Self> {
        let name = match configured_name {
            Some(name) => normalize_name(name)?,
            None => infer_name(chains)?,
        };

        if let Some(profile) = Self::builtin(&name) {
            if let Some(configured_id) = configured_id {
                ensure!(
                    configured_id == profile.id,
                    "node.network_id does not match the fixed {name} network ID"
                );
            }
            profile.validate_chains(chains)?;
            return Ok(profile);
        }

        let id = configured_id.ok_or_else(|| {
            anyhow::anyhow!(
                "custom network '{name}' requires node.network_id with exactly 32 bytes of hexadecimal data"
            )
        })?;
        Ok(Self {
            name,
            id,
            bootstrap_peers: Vec::new(),
        })
    }

    pub fn mainnet() -> Self {
        Self::builtin("mainnet").expect("mainnet profile is fixed")
    }

    pub fn sepolia() -> Self {
        Self::builtin("sepolia").expect("Sepolia profile is fixed")
    }

    pub fn local() -> Self {
        Self::builtin("local").expect("local profile is fixed")
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> NetworkId {
        self.id
    }

    pub fn bootstrap_peers(&self) -> &[String] {
        &self.bootstrap_peers
    }

    /// Use explicit peers when present. Otherwise, use the profile bootstrap peers.
    pub fn resolve_peers(&self, peers: Vec<String>) -> Result<Vec<String>> {
        if peers.is_empty() {
            return Ok(self.bootstrap_peers.clone());
        }
        self.normalize_explicit_peers(peers)
    }

    /// Normalize explicit peers without adding profile bootstrap peers.
    pub fn normalize_explicit_peers(&self, peers: Vec<String>) -> Result<Vec<String>> {
        let mut resolved = BTreeSet::new();
        for peer in peers {
            let peer = match (self.name.as_str(), peer.as_str()) {
                ("sepolia", MAINNET_BOOTSTRAP_PEER) => SEPOLIA_BOOTSTRAP_PEER.to_string(),
                ("mainnet", SEPOLIA_BOOTSTRAP_PEER) => {
                    bail!(
                        "the configured peer is a Sepolia bootstrap; remove it or use {MAINNET_BOOTSTRAP_PEER}"
                    )
                }
                ("local", MAINNET_BOOTSTRAP_PEER | SEPOLIA_BOOTSTRAP_PEER) => {
                    bail!("the local network profile cannot use a public Interfold bootstrap peer")
                }
                _ => peer,
            };
            resolved.insert(peer);
        }
        Ok(resolved.into_iter().collect())
    }

    fn builtin(name: &str) -> Option<Self> {
        let (id, peers) = match name {
            "mainnet" => (MAINNET_NETWORK_ID, vec![MAINNET_BOOTSTRAP_PEER.to_string()]),
            "sepolia" => (SEPOLIA_NETWORK_ID, vec![SEPOLIA_BOOTSTRAP_PEER.to_string()]),
            "local" => (LOCAL_NETWORK_ID, Vec::new()),
            _ => return None,
        };
        Some(Self {
            name: name.to_string(),
            id: id.parse().expect("built-in network ID is valid"),
            bootstrap_peers: peers,
        })
    }

    fn validate_chains(&self, chains: &[ChainConfig]) -> Result<()> {
        for chain in chains.iter().filter(|chain| chain.enabled.unwrap_or(true)) {
            let inferred = infer_name(std::slice::from_ref(chain))?;
            ensure!(
                inferred == self.name,
                "chain '{}' belongs to the {inferred} P2P network, not {}",
                chain.name,
                self.name
            );
        }
        Ok(())
    }
}

impl Default for NetworkProfile {
    fn default() -> Self {
        Self::local()
    }
}

fn normalize_name(name: &str) -> Result<String> {
    let name = name.trim().to_ascii_lowercase();
    ensure!(!name.is_empty(), "node.network must not be empty");
    ensure!(name.len() <= 32, "node.network must not exceed 32 bytes");
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "node.network can contain only lowercase letters, digits, and hyphens"
    );
    Ok(match name.as_str() {
        "localhost" | "hardhat" | "devnet" => "local".to_string(),
        _ => name,
    })
}

fn infer_name(chains: &[ChainConfig]) -> Result<String> {
    let mut names = BTreeSet::new();
    for chain in chains.iter().filter(|chain| chain.enabled.unwrap_or(true)) {
        let inferred = match chain.chain_id {
            Some(1) => Some("mainnet"),
            Some(11_155_111) => Some("sepolia"),
            Some(1_337 | 31_337) => Some("local"),
            Some(_) => None,
            None => match chain.name.trim().to_ascii_lowercase().as_str() {
                "mainnet" => Some("mainnet"),
                "sepolia" => Some("sepolia"),
                "local" | "localhost" | "hardhat" | "devnet" => Some("local"),
                _ => None,
            },
        };
        let inferred = inferred.ok_or_else(|| {
            anyhow::anyhow!(
                "cannot infer the P2P network from chain '{}'; set node.network and node.network_id",
                chain.name
            )
        })?;
        names.insert(inferred);
    }

    match names.len() {
        0 => Ok("local".to_string()),
        1 => Ok(names
            .into_iter()
            .next()
            .expect("one inferred network")
            .to_string()),
        _ => bail!(
            "enabled chains map to different P2P networks; set one explicit node.network profile"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{contract::ContractAddresses, rpc::RpcAuth, Contract};

    fn chain(name: &str, chain_id: Option<u64>) -> ChainConfig {
        let contract =
            || Contract::AddressOnly("0x0000000000000000000000000000000000000000".to_string());
        ChainConfig {
            enabled: Some(true),
            name: name.to_string(),
            rpc_url: "http://127.0.0.1:8545".to_string(),
            rpc_auth: RpcAuth::default(),
            contracts: ContractAddresses {
                interfold: contract(),
                ciphernode_registry: contract(),
                bonding_registry: contract(),
                e3_program: None,
                fee_token: None,
                slashing_manager: None,
                dkg_fold_attestation_verifier: None,
                faucet: None,
            },
            finalization_ms: None,
            chain_id,
            data_availability: None,
        }
    }

    #[test]
    fn infers_builtin_profiles_from_chain_id() {
        assert_eq!(
            NetworkProfile::resolve(None, None, &[chain("ethereum", Some(1))])
                .unwrap()
                .name(),
            "mainnet"
        );
        assert_eq!(
            NetworkProfile::resolve(None, None, &[chain("ethereum", Some(11_155_111))])
                .unwrap()
                .name(),
            "sepolia"
        );
    }

    #[test]
    fn builtin_network_ids_remain_stable() {
        assert_eq!(
            NetworkProfile::mainnet().id().to_string(),
            "c3e81f904b0a8129dce0a85a8d48958a3ca5ee3aea6c32b623fcf66b35728acb"
        );
        assert_eq!(
            NetworkProfile::sepolia().id().to_string(),
            "ab33954b5b3fadf808f03a7c8a7dd159a29ac5950e6c3d724f76ed4c26c9e5c2"
        );
        assert_eq!(
            NetworkProfile::local().id().to_string(),
            "d7cec7f3c090b451f4ff10461b424728e320f72cf3dada907c5bdfe5570a5807"
        );
    }

    #[test]
    fn migrates_sepolia_away_from_the_old_alias() {
        let peers = NetworkProfile::sepolia()
            .resolve_peers(vec![MAINNET_BOOTSTRAP_PEER.to_string()])
            .unwrap();
        assert_eq!(peers, vec![SEPOLIA_BOOTSTRAP_PEER]);
    }

    #[test]
    fn rejects_the_sepolia_alias_on_mainnet() {
        let error = NetworkProfile::mainnet()
            .resolve_peers(vec![SEPOLIA_BOOTSTRAP_PEER.to_string()])
            .unwrap_err();
        assert!(error.to_string().contains("Sepolia bootstrap"));
    }

    #[test]
    fn custom_profiles_require_an_explicit_id() {
        let error = NetworkProfile::resolve(Some("partner-net"), None, &[]).unwrap_err();
        assert!(error.to_string().contains("requires node.network_id"));
    }

    #[test]
    fn explicit_builtin_profile_rejects_a_chain_from_another_network() {
        let error =
            NetworkProfile::resolve(Some("mainnet"), None, &[chain("sepolia", Some(11_155_111))])
                .unwrap_err();
        assert!(error.to_string().contains("not mainnet"));
    }
}
