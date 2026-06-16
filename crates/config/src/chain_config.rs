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
    /// `None`/`0` reads to head; a positive value makes historical/backfill
    /// ingestion reorg-safe by only acting on logs buried this deep.
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
            .with_confirmations(value.reorg_confirmations.unwrap_or(0)))
    }
}

impl TryFrom<ChainConfig> for EvmEventConfigChain {
    type Error = anyhow::Error;
    fn try_from(value: ChainConfig) -> std::result::Result<Self, Self::Error> {
        let r = &value;
        r.try_into()
    }
}
