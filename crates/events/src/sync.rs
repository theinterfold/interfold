// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

type ChainId = u64;
type DeployBlock = u64;

/// Configuration value object for starting the evm reader for a specific chain
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvmEventConfigChain {
    deploy_block: DeployBlock,
    /// Number of block confirmations required before a log is ingested. `0`
    /// preserves reading to the chain head; a positive value gates ingestion to
    /// make the append-only log reorg-safe by construction.
    confirmations: u64,
}

impl EvmEventConfigChain {
    pub fn new(deploy_block: DeployBlock) -> Self {
        Self {
            deploy_block,
            confirmations: 0,
        }
    }

    /// Builder: set the required confirmation depth for reorg safety.
    pub fn with_confirmations(mut self, confirmations: u64) -> Self {
        self.confirmations = confirmations;
        self
    }

    pub fn deploy_block(&self) -> u64 {
        self.deploy_block
    }

    pub fn confirmations(&self) -> u64 {
        self.confirmations
    }
}

/// Configuration value object for starting the evm reader for all chains
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvmEventConfig {
    config: BTreeMap<ChainId, EvmEventConfigChain>, // Need BTreeMap because of Hash
}

impl Default for EvmEventConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EvmEventConfig {
    pub fn new() -> Self {
        Self {
            config: BTreeMap::new(),
        }
    }

    pub fn from_config(config: impl Into<BTreeMap<ChainId, EvmEventConfigChain>>) -> Self {
        EvmEventConfig {
            config: config.into(),
        }
    }

    pub fn get(&self, chain_id: &ChainId) -> Option<&EvmEventConfigChain> {
        self.config.get(chain_id)
    }

    pub fn insert(&mut self, key: ChainId, value: EvmEventConfigChain) {
        self.config.insert(key, value);
    }

    pub fn chains(&self) -> HashSet<u64> {
        self.config.keys().cloned().collect()
    }

    pub fn deploy_block(&self, chain_id: u64) -> Option<u64> {
        self.get(&chain_id).map(|c| c.deploy_block())
    }
}
