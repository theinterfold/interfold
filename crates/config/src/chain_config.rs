// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::hash::Hash;

use crate::{
    contract::ContractAddresses,
    rpc::{RpcAuth, RPC},
};
use anyhow::*;
use e3_events::EvmEventConfigChain;
use serde::{Deserialize, Serialize};
use tracing::error;

const PUBLIC_RPC_CONFIRMATIONS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataAvailabilityMode {
    Avail,
    MockHttp,
}

/// Read configuration for content-addressed objects referenced by Ethereum events.
#[derive(Debug, Clone, PartialEq, Hash, Eq, Deserialize, Serialize)]
pub struct DataAvailabilityConfig {
    pub mode: DataAvailabilityMode,
    /// Avail HTTP RPC for `avail`, or the local object-service URL for `mock_http`.
    pub rpc_url: String,
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, Deserialize, Serialize)]
pub struct ChainConfig {
    pub enabled: Option<bool>,
    pub name: String,
    pub rpc_url: String, // We may need multiple per chain for redundancy at a later point
    #[serde(default)]
    pub rpc_auth: RpcAuth,
    pub contracts: ContractAddresses,
    pub finalization_ms: Option<u64>,
    pub chain_id: Option<u64>,
    #[serde(default)]
    pub data_availability: Option<DataAvailabilityConfig>,
}

impl ChainConfig {
    pub fn rpc_url(&self) -> Result<RPC> {
        Ok(RPC::from_url(&self.rpc_url)
            .map_err(|e| anyhow!("Failed to parse RPC URL for chain {}: {}", self.name, e))?)
    }

    /// Return the fixed ingestion depth for this RPC class.
    pub fn ingestion_confirmations(&self) -> Result<u64> {
        Ok(if self.rpc_url()?.is_local() {
            0
        } else {
            PUBLIC_RPC_CONFIRMATIONS
        })
    }
}

impl TryFrom<&ChainConfig> for EvmEventConfigChain {
    type Error = anyhow::Error;
    fn try_from(value: &ChainConfig) -> std::result::Result<Self, Self::Error> {
        let rpc = value.rpc_url()?;
        let contracts = value.contracts.contracts();
        let mut lowest_block: Option<u64> = None;
        for contract in contracts {
            let deploy_block = contract.deploy_block();
            if deploy_block.unwrap_or(0) == 0 && !rpc.is_local() {
                let rpc_url = rpc.url().to_string();
                let contract_address = contract.address_str();
                error!(
                   "Querying from block 0 on a non-local node ({}) without a specific deploy_block is not allowed.",
                   rpc_url
                );
                bail!(
                    "Misconfiguration: Attempted to query historical events from genesis on a non-local node. \
                    Please specify a `deploy_block` for contract address {contract_address} on rpc {rpc_url}"
                );
            }
            lowest_block = [lowest_block, deploy_block].into_iter().flatten().min();
        }
        let start_block = lowest_block.unwrap_or(0);
        Ok(EvmEventConfigChain::new(start_block)
            .with_confirmations(value.ingestion_confirmations()?))
    }
}

impl TryFrom<ChainConfig> for EvmEventConfigChain {
    type Error = anyhow::Error;
    fn try_from(value: ChainConfig) -> std::result::Result<Self, Self::Error> {
        let r = &value;
        r.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{contract::Contract, rpc::RpcAuth};

    fn chain(rpc_url: &str) -> ChainConfig {
        let contract = || Contract::Full {
            address: "0x0000000000000000000000000000000000000000".to_string(),
            deploy_block: Some(1),
        };
        ChainConfig {
            enabled: Some(true),
            name: "test".to_string(),
            rpc_url: rpc_url.to_string(),
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
            chain_id: Some(1),
            data_availability: None,
        }
    }

    #[test]
    fn non_local_chain_uses_a_safe_default() {
        let config = EvmEventConfigChain::try_from(&chain("wss://example.com")).unwrap();
        assert_eq!(config.confirmations(), PUBLIC_RPC_CONFIRMATIONS);
    }

    #[test]
    fn local_chain_can_read_the_head() {
        let config = EvmEventConfigChain::try_from(&chain("ws://127.0.0.1:8545")).unwrap();
        assert_eq!(config.confirmations(), 0);
    }
}
