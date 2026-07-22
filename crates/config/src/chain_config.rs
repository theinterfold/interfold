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

#[derive(Debug, Clone, PartialEq, Hash, Eq, Deserialize, Serialize)]
pub struct ChainConfig {
    pub enabled: Option<bool>,
    pub name: String,
    pub rpc_url: String, // We may need multiple per chain for redundancy at a later point
    #[serde(default)]
    pub rpc_auth: RpcAuth,
    pub contracts: ContractAddresses,
    pub finalization_ms: Option<u64>,
    /// Number of block confirmations to wait before ingesting an on-chain log.
    /// Non-local RPCs must configure a positive value. Local development RPCs
    /// may use `None`/`0` to read directly to head.
    pub reorg_confirmations: Option<u64>,
    pub chain_id: Option<u64>,
}

impl ChainConfig {
    pub fn rpc_url(&self) -> Result<RPC> {
        Ok(RPC::from_url(&self.rpc_url)
            .map_err(|e| anyhow!("Failed to parse RPC URL for chain {}: {}", self.name, e))?)
    }
}

impl TryFrom<&ChainConfig> for EvmEventConfigChain {
    type Error = anyhow::Error;
    fn try_from(value: &ChainConfig) -> std::result::Result<Self, Self::Error> {
        let rpc = value.rpc_url()?;
        let confirmations = value.reorg_confirmations.unwrap_or(0);
        if !rpc.is_local() && confirmations == 0 {
            bail!(
                "Misconfiguration: chain '{}' uses non-local RPC {} but has no positive \
                 reorg_confirmations finality policy",
                value.name,
                rpc.url()
            );
        }
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
        Ok(EvmEventConfigChain::new(start_block).with_confirmations(confirmations))
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
    use crate::contract::{Contract, ContractAddresses};

    fn chain(rpc_url: &str, confirmations: Option<u64>) -> ChainConfig {
        let contract = || Contract::Full {
            address: "0x0000000000000000000000000000000000000001".to_owned(),
            deploy_block: Some(1),
        };
        ChainConfig {
            enabled: Some(true),
            name: "test".to_owned(),
            rpc_url: rpc_url.to_owned(),
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
            reorg_confirmations: confirmations,
            chain_id: Some(1),
        }
    }

    #[test]
    fn remote_rpc_requires_positive_confirmations() {
        for confirmations in [None, Some(0)] {
            let error = EvmEventConfigChain::try_from(&chain(
                "wss://ethereum-sepolia-rpc.publicnode.com",
                confirmations,
            ))
            .unwrap_err();

            assert!(error.to_string().contains("positive reorg_confirmations"));
        }
    }

    #[test]
    fn remote_rpc_preserves_configured_confirmations() {
        let config = EvmEventConfigChain::try_from(&chain("wss://example.com", Some(64))).unwrap();

        assert_eq!(config.confirmations(), 64);
    }

    #[test]
    fn local_rpc_may_read_directly_to_head() {
        let config = EvmEventConfigChain::try_from(&chain("ws://127.0.0.1:8545", None)).unwrap();

        assert_eq!(config.confirmations(), 0);
    }
}
