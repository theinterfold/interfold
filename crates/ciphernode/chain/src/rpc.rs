// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Contracts, Deadlines, LogsError, RawLog, Rpc, RpcError, Sortition};
use alloy::{
    eips::BlockId,
    providers::Provider,
    pubsub::{PubSubFrontend, SubscriptionStream},
    rpc::types::{Filter, Log},
};
use alloy_primitives::{Address, B256, U256};
use e3_evm::log_window::is_range_limit_error;
use e3_evm_contracts::{IBondingRegistry, ICiphernodeRegistry, IInterfold};
use e3_protocol::{node::LogPosition, UnixSecs};
use futures::{
    ready,
    stream::{self, BoxStream},
    Stream, StreamExt, TryStreamExt,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
};

const MAX_CACHED_BLOCK_TIMES: usize = 4_096;
const MAX_CONCURRENT_RPC: usize = 16;

#[derive(Default)]
struct BlockTimeCache {
    times: HashMap<u64, UnixSecs>,
    order: VecDeque<u64>,
}

impl BlockTimeCache {
    fn get(&self, block: u64) -> Option<UnixSecs> {
        self.times.get(&block).copied()
    }

    fn insert(&mut self, block: u64, time: UnixSecs) {
        if self.times.insert(block, time).is_none() {
            self.order.push_back(block);
        }
        while self.order.len() > MAX_CACHED_BLOCK_TIMES {
            if let Some(oldest) = self.order.pop_front() {
                self.times.remove(&oldest);
            }
        }
    }
}

/// A chain node over JSON-RPC.
#[derive(Clone)]
pub struct ChainNode<P> {
    provider: P,
    contracts: Contracts,
    timestamps: Arc<Mutex<BlockTimeCache>>,
}

impl<P> ChainNode<P> {
    pub fn new(provider: P, contracts: Contracts) -> Self {
        Self {
            provider,
            contracts,
            timestamps: Arc::new(Mutex::new(BlockTimeCache::default())),
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

    async fn announce(
        &self,
        addresses: &[Address],
    ) -> Result<Option<BoxStream<'static, u64>>, RpcError> {
        let Some(frontend) = self.provider.client().pubsub_frontend().cloned() else {
            return Ok(None);
        };
        let filter = Filter::new().address(addresses.to_vec());
        let subscription = self
            .provider
            .subscribe_logs(&filter)
            .await
            .map_err(RpcError::new)?;
        Ok(Some(Box::pin(LogBlocks {
            id: *subscription.local_id(),
            logs: subscription.into_stream(),
            frontend,
        })))
    }

    async fn logs(
        &self,
        addresses: &[Address],
        from: u64,
        to: u64,
    ) -> Result<Vec<RawLog>, LogsError> {
        let c = &self.contracts;
        let filter = Filter::new()
            .address(addresses.to_vec())
            .from_block(from)
            .to_block(to);
        let logs = self.provider.get_logs(&filter).await.map_err(|error| {
            let refused = is_range_limit_error(&error.to_string());
            let error = RpcError::new(error);
            match refused {
                true => LogsError::TooWide(error),
                false => LogsError::Failed(error),
            }
        })?;

        let mut times: BTreeMap<u64, UnixSecs> = BTreeMap::new();
        let mut missing: BTreeSet<u64> = BTreeSet::new();
        {
            let cache = self
                .timestamps
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for log in &logs {
                let (Some(block), Some(_), Some(_)) =
                    (log.block_number, log.log_index, log.transaction_hash)
                else {
                    return Err(RpcError("a log without its block position".into()).into());
                };
                if let Some(time) = log.block_timestamp {
                    times.insert(block, time);
                } else if let Some(time) = cache.get(block) {
                    times.insert(block, time);
                } else if !times.contains_key(&block) {
                    missing.insert(block);
                }
            }
        }

        if !missing.is_empty() {
            let fetched: Vec<(u64, UnixSecs)> =
                stream::iter(missing)
                    .map(|block| async move {
                        Ok::<_, RpcError>((block, self.block_time(block).await?))
                    })
                    .buffer_unordered(MAX_CONCURRENT_RPC)
                    .try_collect()
                    .await?;
            let mut cache = self
                .timestamps
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for (block, time) in fetched {
                cache.insert(block, time);
                times.insert(block, time);
            }
        } else if !times.is_empty() {
            let mut cache = self
                .timestamps
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for (&block, &time) in &times {
                cache.insert(block, time);
            }
        }

        let mut raw = Vec::with_capacity(logs.len());
        for log in logs {
            let (Some(block), Some(log_index), Some(transaction)) =
                (log.block_number, log.log_index, log.transaction_hash)
            else {
                return Err(RpcError("a log without its block position".into()).into());
            };
            let time = log
                .block_timestamp
                .or_else(|| times.get(&block).copied())
                .ok_or_else(|| RpcError(format!("missing timestamp for block {block}").into()))?;
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
        let req_call = registry.getSortitionRequest(e3).block(at);
        let seed_call = registry.sortitionSeed(e3).block(at);
        let (request, seed) = tokio::try_join!(
            async { req_call.call().await.map_err(RpcError::new) },
            async { seed_call.call().await.map_err(RpcError::new) },
        )?;
        Ok(Sortition {
            ticket_price: request.ticketPrice,
            committee_deadline: secs(request.committeeDeadline),
            seed: seed.ready.then_some(seed.seed),
        })
    }

    async fn deadlines(&self, e3: U256, block: u64) -> Result<Deadlines, RpcError> {
        let deadlines = IInterfold::new(self.contracts.interfold, &self.provider)
            .getDeadlines(e3)
            .block(BlockId::number(block))
            .call()
            .await
            .map_err(RpcError::new)?;
        Ok(Deadlines {
            dkg: secs(deadlines.dkgDeadline),
            compute: secs(deadlines.computeDeadline),
            decryption: secs(deadlines.decryptionDeadline),
        })
    }

    async fn dkg_window(&self, e3: U256, block: u64) -> Result<UnixSecs, RpcError> {
        let windows = IInterfold::new(self.contracts.interfold, &self.provider)
            .getE3TimeoutConfig(e3)
            .block(BlockId::number(block))
            .call()
            .await
            .map_err(RpcError::new)?;
        Ok(secs(windows.dkgWindow))
    }

    async fn listed(&self, block: u64) -> Result<u64, RpcError> {
        let listed = ICiphernodeRegistry::new(self.contracts.registry, &self.provider)
            .numCiphernodes()
            .block(BlockId::number(block))
            .call()
            .await
            .map_err(RpcError::new)?;
        Ok(listed.saturating_to())
    }

    async fn eligible(
        &self,
        operators: &[Address],
        at: UnixSecs,
    ) -> Result<BTreeSet<Address>, RpcError> {
        let bonding = IBondingRegistry::new(self.contracts.bonding, &self.provider);
        let reads: Vec<_> = operators
            .iter()
            .copied()
            .map(|operator| {
                let read = bonding.eligibilityAt(operator, U256::from(at));
                async move { read.call().await.map(|answer| (operator, answer.active)) }
            })
            .collect();
        let answers: Vec<(Address, bool)> = stream::iter(reads)
            .buffer_unordered(MAX_CONCURRENT_RPC)
            .try_collect()
            .await
            .map_err(RpcError::new)?;
        Ok(answers
            .into_iter()
            .filter_map(|(operator, active)| active.then_some(operator))
            .collect())
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

/// The blocks of the logs a subscription announces; dropping it ends the subscription.
struct LogBlocks {
    logs: SubscriptionStream<Log>,
    frontend: PubSubFrontend,
    id: B256,
}

impl Stream for LogBlocks {
    type Item = u64;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<u64>> {
        loop {
            match ready!(self.logs.poll_next_unpin(cx)) {
                Some(Log {
                    block_number: Some(block),
                    ..
                }) => return Poll::Ready(Some(block)),
                // A log of a pending block, which has no number yet.
                Some(_) => {}
                None => return Poll::Ready(None),
            }
        }
    }
}

impl Drop for LogBlocks {
    fn drop(&mut self) {
        // A node that is gone has no subscription left to end.
        let _ = self.frontend.unsubscribe(self.id);
    }
}

fn secs(value: U256) -> UnixSecs {
    UnixSecs::try_from(value).unwrap_or(UnixSecs::MAX)
}
