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
use futures::{future::try_join_all, ready, stream::BoxStream, Stream, StreamExt};
use std::{
    collections::{BTreeMap, BTreeSet},
    pin::Pin,
    task::{Context, Poll},
};

/// A chain node over JSON-RPC.
#[derive(Clone)]
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
        let mut raw = Vec::with_capacity(logs.len());
        for log in logs {
            let (Some(block), Some(log_index), Some(transaction)) =
                (log.block_number, log.log_index, log.transaction_hash)
            else {
                return Err(RpcError("a log without its block position".into()).into());
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
        let reads = operators.iter().map(|operator| {
            let read = bonding.eligibilityAt(*operator, U256::from(at));
            async move { read.call().await.map(|answer| (*operator, answer.active)) }
        });
        let answers = try_join_all(reads).await.map_err(RpcError::new)?;
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
