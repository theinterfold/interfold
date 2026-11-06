// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Contracts, RawLog, Rpc, RpcError, Sortition};
use alloy::{eips::BlockId, providers::Provider, rpc::types::Filter};
use alloy_primitives::{Address, U256};
use e3_evm_contracts::{ICiphernodeRegistry, IInterfold};
use e3_protocol::{
    dkg::DkgTiming,
    node::{CommitteeSeed, LogPosition},
    UnixSecs,
};
use std::collections::BTreeMap;

/// A chain node over JSON-RPC.
pub struct ChainNode<P> {
    provider: P,
    contracts: Contracts,
}

impl<P> ChainNode<P> {
    pub fn new(provider: P, contracts: Contracts) -> Self {
        Self {
            provider,
            contracts,
        }
    }
}

impl<P: Provider + Send + Sync> Rpc for ChainNode<P> {
    async fn head(&self) -> Result<u64, RpcError> {
        self.provider
            .get_block_number()
            .await
            .map_err(RpcError::new)
    }

    async fn logs(&self, from: u64, to: u64) -> Result<Vec<RawLog>, RpcError> {
        let c = &self.contracts;
        let addresses: Vec<Address> = [c.interfold, c.registry, c.bonding]
            .into_iter()
            .chain(c.randomness.iter().copied())
            .collect();
        let filter = Filter::new()
            .address(addresses)
            .from_block(from)
            .to_block(to);
        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .map_err(RpcError::new)?;
        let mut times: BTreeMap<u64, UnixSecs> = BTreeMap::new();
        let mut raw = Vec::with_capacity(logs.len());
        for log in logs {
            let (Some(block), Some(log_index), Some(transaction)) =
                (log.block_number, log.log_index, log.transaction_hash)
            else {
                return Err(RpcError("a log without its block position".into()));
            };
            let time = match log.block_timestamp.or_else(|| times.get(&block).copied()) {
                Some(time) => time,
                None => self.block_time(block).await?,
            };
            times.insert(block, time);
            raw.push(RawLog {
                address: log.address(),
                topics: log.topics().to_vec(),
                data: log.data().data.clone(),
                at: LogPosition {
                    chain_id: c.chain_id,
                    block,
                    log_index,
                },
                time,
                transaction,
            });
        }
        raw.sort_by_key(|log| log.at);
        Ok(raw)
    }

    async fn sortition(&self, e3: U256, block: u64) -> Result<Sortition, RpcError> {
        let registry = ICiphernodeRegistry::new(self.contracts.registry, &self.provider);
        let at = BlockId::number(block);
        let request = registry
            .getSortitionRequest(e3)
            .block(at)
            .call()
            .await
            .map_err(RpcError::new)?;
        let seed = registry
            .sortitionSeed(e3)
            .block(at)
            .call()
            .await
            .map_err(RpcError::new)?;
        Ok(Sortition {
            ticket_price: request.ticketPrice,
            seed: seed.ready.then(|| CommitteeSeed {
                seed: seed.seed,
                deadline: secs(request.committeeDeadline),
            }),
        })
    }

    async fn dkg_timing(&self, e3: U256, block: u64) -> Result<DkgTiming, RpcError> {
        let interfold = IInterfold::new(self.contracts.interfold, &self.provider);
        let at = BlockId::number(block);
        let deadlines = interfold
            .getDeadlines(e3)
            .block(at)
            .call()
            .await
            .map_err(RpcError::new)?;
        let windows = interfold
            .getE3TimeoutConfig(e3)
            .block(at)
            .call()
            .await
            .map_err(RpcError::new)?;
        Ok(DkgTiming {
            deadline: secs(deadlines.dkgDeadline),
            window: secs(windows.dkgWindow),
        })
    }

    async fn decryption_deadline(&self, e3: U256, block: u64) -> Result<UnixSecs, RpcError> {
        let interfold = IInterfold::new(self.contracts.interfold, &self.provider);
        let deadlines = interfold
            .getDeadlines(e3)
            .block(BlockId::number(block))
            .call()
            .await
            .map_err(RpcError::new)?;
        Ok(secs(deadlines.decryptionDeadline))
    }
}

impl<P: Provider> ChainNode<P> {
    async fn block_time(&self, block: u64) -> Result<UnixSecs, RpcError> {
        let header = self
            .provider
            .get_block_by_number(block.into())
            .await
            .map_err(RpcError::new)?
            .ok_or_else(|| RpcError(format!("the node has no block {block}").into()))?;
        Ok(header.header.timestamp)
    }
}

fn secs(value: U256) -> UnixSecs {
    UnixSecs::try_from(value).unwrap_or(UnixSecs::MAX)
}
