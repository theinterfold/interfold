// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::messages::{EvmEventProcessor, EvmLog, InterfoldEvmEvent};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use anyhow::{anyhow, Context as _};
use async_trait::async_trait;
use e3_events::CorrelationId;
use std::time::Duration;
use tracing::{debug, info, warn};

const GET_LOGS_CHUNK_SIZE: u64 = 10_000;
const GET_LOGS_MAX_RETRIES: u32 = 3;
const BLOCK_TIMESTAMP_MAX_ATTEMPTS: u32 = 4;
const BLOCK_TIMESTAMP_RETRY_BASE: Duration = Duration::from_millis(250);

/// Trait abstracting provider methods needed for log fetching.
/// Enables unit testing without a real EVM provider.
#[async_trait]
pub(crate) trait LogProvider: Send + Sync {
    async fn fetch_logs(&self, filter: &Filter) -> Result<Vec<Log>, anyhow::Error>;
    async fn fetch_block_number(&self) -> Result<u64, anyhow::Error>;
    async fn fetch_block_timestamp(&self, block_number: u64) -> Result<u64, anyhow::Error>;
}

#[async_trait]
impl<P: Provider + Send + Sync> LogProvider for P {
    async fn fetch_logs(&self, filter: &Filter) -> Result<Vec<Log>, anyhow::Error> {
        self.get_logs(filter).await.map_err(|e| anyhow!("{}", e))
    }
    async fn fetch_block_number(&self) -> Result<u64, anyhow::Error> {
        self.get_block_number().await.map_err(|e| anyhow!("{}", e))
    }
    async fn fetch_block_timestamp(&self, block_number: u64) -> Result<u64, anyhow::Error> {
        self.get_block_by_number(block_number.into())
            .await
            .map_err(|error| anyhow!("failed to fetch block {block_number}: {error}"))?
            .map(|block| block.header.timestamp)
            .ok_or_else(|| anyhow!("provider returned no block for height {block_number}"))
    }
}

pub(crate) async fn process_log<L: LogProvider>(
    provider: &L,
    log: Log,
    chain_id: u64,
    next: &EvmEventProcessor,
    timestamp_tracker: &mut TimestampTracker,
) -> Result<CorrelationId, anyhow::Error> {
    let timestamp = timestamp_tracker
        .get(provider, log.block_number, log.block_timestamp)
        .await?;
    let evt = InterfoldEvmEvent::Log(EvmLog::new(log, chain_id, timestamp));
    let id = evt.get_id();
    debug!("Sending event({})", id);
    next.do_send(evt);
    Ok(id)
}

/// Handle a log delivered by the subscription stream.
///
/// With a positive confirmation depth the subscription is only a wake-up signal. Publishing the
/// raw notification here would make the historical confirmation gate ineffective, so the periodic
/// canonical backfill owns delivery instead. With zero confirmations this preserves the existing
/// low-latency behavior.
pub(crate) async fn process_live_log<L: LogProvider>(
    provider: &L,
    log: Log,
    chain_id: u64,
    next: &EvmEventProcessor,
    timestamp_tracker: &mut TimestampTracker,
    last_block: &mut u64,
    confirmations: u64,
) -> Result<Option<CorrelationId>, anyhow::Error> {
    if confirmations > 0 {
        debug!(
            chain_id,
            block_number = log.block_number,
            confirmations,
            "Deferring live log to confirmed canonical backfill"
        );
        return Ok(None);
    }

    let block_number = log.block_number;
    let id = process_log(provider, log, chain_id, next, timestamp_tracker).await?;
    if let Some(block_number) = block_number {
        *last_block = (*last_block).max(block_number);
    }
    Ok(Some(id))
}

/// Fetch logs in chunks from `from_block` to `to_block` with retry logic per chunk.
/// Returns the CorrelationId of the last processed event, if any.
pub(crate) async fn fetch_logs_chunked<L: LogProvider>(
    provider: &L,
    filter: &Filter,
    from_block: u64,
    to_block: u64,
    chain_id: u64,
    next: &EvmEventProcessor,
    timestamp_tracker: &mut TimestampTracker,
) -> Result<Option<CorrelationId>, anyhow::Error> {
    if to_block < from_block {
        return Ok(None);
    }

    let total_blocks = to_block - from_block + 1;
    let total_chunks = total_blocks.div_ceil(GET_LOGS_CHUNK_SIZE);

    info!(
        chain_id,
        from_block, to_block, total_chunks, "Fetching logs in chunks"
    );

    let mut cursor = from_block;
    let mut last_id: Option<CorrelationId> = None;
    let mut chunk_idx = 0u64;

    while cursor <= to_block {
        let chunk_end = (cursor + GET_LOGS_CHUNK_SIZE - 1).min(to_block);
        chunk_idx += 1;

        let chunk_filter = filter.clone().from_block(cursor).to_block(chunk_end);

        let mut success = false;
        for attempt in 1..=GET_LOGS_MAX_RETRIES {
            match provider.fetch_logs(&chunk_filter).await {
                Ok(logs) => {
                    info!(
                        chain_id,
                        chunk = chunk_idx,
                        total_chunks,
                        from = cursor,
                        to = chunk_end,
                        events = logs.len(),
                        "Fetched log chunk"
                    );
                    for log in logs {
                        last_id = Some(
                            process_log(provider, log, chain_id, next, timestamp_tracker).await?,
                        );
                    }
                    success = true;
                    break;
                }
                Err(e) => {
                    warn!(
                        chain_id, chunk = chunk_idx,
                        from = cursor, to = chunk_end,
                        attempt, max_retries = GET_LOGS_MAX_RETRIES,
                        error = %e, "Failed to fetch log chunk, retrying"
                    );
                    if attempt < GET_LOGS_MAX_RETRIES {
                        tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempt))).await;
                    }
                }
            }
        }

        if !success {
            return Err(anyhow!(
                "Failed to fetch logs for chain {} blocks {}..={} after {} retries",
                chain_id,
                cursor,
                chunk_end,
                GET_LOGS_MAX_RETRIES
            ));
        }

        cursor = chunk_end + 1;
    }

    info!(chain_id, chunks_fetched = chunk_idx, "Log fetch complete");
    Ok(last_id)
}

/// Fetch any blocks between `last_block` and the chain head to fill gaps.
/// Handles blocks missed during reconnection or due to Geth's eth_subscribe
/// silently ignoring the fromBlock parameter.
pub(crate) async fn backfill_to_head<L: LogProvider>(
    provider: &L,
    filter: &Filter,
    chain_id: u64,
    next: &EvmEventProcessor,
    timestamp_tracker: &mut TimestampTracker,
    last_block: &mut u64,
    confirmations: u64,
) -> Result<(), anyhow::Error> {
    let raw_head = provider
        .fetch_block_number()
        .await
        .map_err(|e| anyhow!("Failed to get block number for gap backfill: {}", e))?;
    // Clamp to the confirmed head so we never ingest logs that a reorg of depth
    // `confirmations` could still orphan. `confirmations == 0` is a no-op.
    let current_head = crate::domain::reorg::confirmed_head(raw_head, confirmations);

    let gap_start = *last_block + 1;
    if gap_start > current_head {
        return Ok(());
    }

    info!(
        chain_id,
        from = gap_start,
        to = current_head,
        blocks = current_head - gap_start + 1,
        "Backfilling missed blocks"
    );

    let mut cursor = gap_start;
    while cursor <= current_head {
        let chunk_end = (cursor + GET_LOGS_CHUNK_SIZE - 1).min(current_head);

        fetch_logs_chunked(
            provider,
            filter,
            cursor,
            chunk_end,
            chain_id,
            next,
            timestamp_tracker,
        )
        .await?;

        *last_block = chunk_end;
        cursor = chunk_end + 1;
    }

    Ok(())
}

/// Cache utility to keep track of timestamps
pub(crate) struct TimestampTracker {
    current: Option<(u64, u64)>, // (block_number, timestamp)
}

impl TimestampTracker {
    pub fn new() -> Self {
        Self { current: None }
    }

    pub async fn get<L: LogProvider>(
        &mut self,
        provider: &L,
        block_number: Option<u64>,
        log_timestamp: Option<u64>,
    ) -> Result<u64, anyhow::Error> {
        let bn = block_number.context("provider log is missing its block number")?;

        if let Some(timestamp) = log_timestamp {
            self.current = Some((bn, timestamp));
            return Ok(timestamp);
        }

        if let Some((cached_bn, ts)) = self.current {
            if bn == cached_bn {
                return Ok(ts);
            }
        }

        let mut last_error = None;
        for attempt in 1..=BLOCK_TIMESTAMP_MAX_ATTEMPTS {
            match provider.fetch_block_timestamp(bn).await {
                Ok(timestamp) => {
                    self.current = Some((bn, timestamp));
                    return Ok(timestamp);
                }
                Err(error) => {
                    warn!(
                        block_number = bn,
                        attempt,
                        max_attempts = BLOCK_TIMESTAMP_MAX_ATTEMPTS,
                        error = %error,
                        "Could not resolve log block timestamp"
                    );
                    last_error = Some(error);
                    if attempt < BLOCK_TIMESTAMP_MAX_ATTEMPTS {
                        let multiplier = 1_u32 << (attempt - 1);
                        tokio::time::sleep(BLOCK_TIMESTAMP_RETRY_BASE * multiplier).await;
                    }
                }
            }
        }

        Err(last_error.expect("timestamp retry loop always runs at least once"))
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
