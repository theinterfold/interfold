// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::log_window::{
    is_range_limit_error, LogWindow, MAX_WINDOW_SHRINKS, MIN_LOG_WINDOW,
};
use crate::messages::{EvmEventProcessor, EvmLog, InterfoldEvmEvent};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use anyhow::{anyhow, Context as _};
use async_trait::async_trait;
use e3_events::CorrelationId;
use tracing::{debug, info, warn};

const GET_LOGS_MAX_RETRIES: u32 = 3;

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

/// Fetch one chunk, narrowing `window` and retrying until the provider serves it.
///
/// Returns the chunk's logs and the last block it covers, which is where the caller resumes from.
/// The covered end is returned rather than recomputed, because a narrowing inside this call moves
/// the end of the range: a caller that recomputed it from the window afterwards would advance past
/// blocks that were never fetched.
///
/// Attempts and narrowings are budgeted separately. A narrowing is not a failed request to be
/// backed off; it is a corrected request that must be reissued at once. One shared budget would let
/// a provider with a tight cap exhaust the attempts before the window reached its limit, and the
/// sync would fail on a provider it could have used.
pub(crate) async fn fetch_chunk_adapting<L: LogProvider>(
    provider: &L,
    filter: &Filter,
    cursor: u64,
    to_block: u64,
    chain_id: u64,
    window: &mut LogWindow,
) -> Result<(Vec<Log>, u64), anyhow::Error> {
    let mut attempt = 1u32;
    let mut shrinks = 0u32;

    loop {
        // Recomputed on every pass: a narrowing between passes must move the end of the range,
        // and the start must not move, or the blocks between the old and new end are skipped.
        let end = window.end_for(cursor, to_block);
        let chunk_filter = filter.clone().from_block(cursor).to_block(end);

        match provider.fetch_logs(&chunk_filter).await {
            Ok(logs) => return Ok((logs, end)),
            Err(e) => {
                let message = format!("{e:#}");

                if is_range_limit_error(&message) {
                    // `shrink` reports `false` at the floor. A provider that refuses a single
                    // block is not applying a range cap, so the error is reported rather than
                    // answered with a narrower range that cannot exist.
                    if shrinks >= MAX_WINDOW_SHRINKS || !window.shrink() {
                        return Err(anyhow!(
                            "Provider rejected the block range for chain {} blocks {}..={} at \
                             the smallest window of {} block(s) after {} narrowing(s): {}",
                            chain_id,
                            cursor,
                            end,
                            MIN_LOG_WINDOW,
                            shrinks,
                            message
                        ));
                    }
                    shrinks += 1;

                    warn!(
                        chain_id,
                        from = cursor,
                        rejected_to = end,
                        window = window.width(),
                        shrinks,
                        error = %message,
                        "Provider rejected the block range, narrowing the window and retrying"
                    );

                    if window.is_narrow() {
                        warn!(
                            chain_id,
                            window = window.width(),
                            "The provider caps eth_getLogs to a narrow range. The first sync \
                             needs many requests and is slow. Use an endpoint with a wider \
                             range limit to sync faster."
                        );
                    }
                    continue;
                }

                warn!(
                    chain_id,
                    from = cursor, to = end,
                    attempt, max_retries = GET_LOGS_MAX_RETRIES,
                    error = %message, "Failed to fetch log chunk, retrying"
                );

                if attempt >= GET_LOGS_MAX_RETRIES {
                    // Name the window in the failure. A provider that caps the range with
                    // wording this crate does not recognize fails here rather than in the
                    // narrowing branch, and the generic text alone sent operators looking for
                    // a rate limit. The width makes the alternative reading visible, and the
                    // message is the provider's own words for a maintainer to match on.
                    return Err(anyhow!(
                        "Failed to fetch logs for chain {} blocks {}..={} ({} block window) \
                         after {} retries. If the provider caps the eth_getLogs range, this \
                         message is its wording for that cap and the window did not narrow: {}",
                        chain_id,
                        cursor,
                        end,
                        window.width(),
                        GET_LOGS_MAX_RETRIES,
                        message
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempt))).await;
                attempt += 1;
            }
        }
    }
}

/// Read every log a filter matches over `from_block..=to_block`, adapting to the provider's cap.
///
/// The same adaptation the event pager uses, for the reads that run before it. Startup replays its
/// own history — the randomness-provider set, and anything else needed before effects are enabled —
/// and those reads happen first, so a fixed window there fails on exactly the providers the pager
/// was taught to tolerate, and it fails before the pager is ever reached. That is the shape of the
/// reported bug: a ciphernode that would not start against an endpoint the sync could have used.
///
/// Returns the logs in chain order.
pub(crate) async fn fetch_logs_adapting<L: LogProvider>(
    provider: &L,
    filter: &Filter,
    from_block: u64,
    to_block: u64,
    chain_id: u64,
) -> Result<Vec<Log>, anyhow::Error> {
    if to_block < from_block {
        return Ok(Vec::new());
    }

    let mut window = LogWindow::new();
    let mut cursor = from_block;
    let mut logs = Vec::new();

    while cursor <= to_block {
        let (mut chunk, end) =
            fetch_chunk_adapting(provider, filter, cursor, to_block, chain_id, &mut window).await?;
        logs.append(&mut chunk);

        if end >= to_block {
            break;
        }
        cursor = end + 1;
    }

    Ok(logs)
}

/// Fetch logs in chunks from `from_block` to `to_block` with retry logic per chunk.
/// Returns the CorrelationId of the last processed event, if any.
///
/// `window` carries the block range across chunks and across calls. Hosted providers cap the
/// `eth_getLogs` range and do not publish that cap over the wire, so the range is narrowed when a
/// provider rejects it and the narrowed range is then kept. A caller that made a fresh window for
/// every call would rediscover the same cap and pay one failed request for each chunk.
pub(crate) async fn fetch_logs_chunked<L: LogProvider>(
    provider: &L,
    filter: &Filter,
    from_block: u64,
    to_block: u64,
    chain_id: u64,
    next: &EvmEventProcessor,
    timestamp_tracker: &mut TimestampTracker,
    window: &mut LogWindow,
) -> Result<Option<CorrelationId>, anyhow::Error> {
    if to_block < from_block {
        return Ok(None);
    }

    // An estimate, not a count: a later narrowing increases the real number of chunks.
    let total_chunks = window.estimated_chunks(from_block, to_block);

    info!(
        chain_id,
        from_block,
        to_block,
        total_chunks,
        window = window.width(),
        "Fetching logs in chunks"
    );

    let mut cursor = from_block;
    let mut last_id: Option<CorrelationId> = None;
    let mut chunk_idx = 0u64;

    while cursor <= to_block {
        chunk_idx += 1;

        let (logs, chunk_end) =
            fetch_chunk_adapting(provider, filter, cursor, to_block, chain_id, window).await?;

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
            last_id = Some(process_log(provider, log, chain_id, next, timestamp_tracker).await?);
        }

        cursor = chunk_end + 1;
    }

    info!(
        chain_id,
        chunks_fetched = chunk_idx,
        window = window.width(),
        "Log fetch complete"
    );
    Ok(last_id)
}

/// Fetch any blocks between `last_block` and the chain head to fill gaps.
/// Handles blocks missed during reconnection or due to Geth's eth_subscribe
/// silently ignoring the fromBlock parameter.
///
/// `last_block` advances after each completed range, so a failure part-way keeps the progress that
/// was already made and the next call resumes above it.
pub(crate) async fn backfill_to_head<L: LogProvider>(
    provider: &L,
    filter: &Filter,
    chain_id: u64,
    next: &EvmEventProcessor,
    timestamp_tracker: &mut TimestampTracker,
    last_block: &mut u64,
    confirmations: u64,
    window: &mut LogWindow,
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
        // Read with the width that applies now. `fetch_logs_chunked` may narrow the window inside
        // this range; it still covers the whole range before it returns, so the cursor advances by
        // exactly what was read.
        let chunk_end = window.end_for(cursor, current_head);

        fetch_logs_chunked(
            provider,
            filter,
            cursor,
            chunk_end,
            chain_id,
            next,
            timestamp_tracker,
            window,
        )
        .await?;

        *last_block = chunk_end;
        cursor = chunk_end + 1;
    }

    Ok(())
}

/// Resolves the block timestamp for a log, and remembers the last block it resolved.
///
/// A log usually carries its own `blockTimestamp`, so the common path needs no request at all. The
/// cache exists for providers that omit the field: several logs normally share one block, and
/// without it each of those logs would repeat the same `eth_getBlockByNumber`.
pub(crate) struct TimestampTracker {
    current: Option<(u64, u64)>, // (block_number, timestamp)
}

impl TimestampTracker {
    pub fn new() -> Self {
        Self { current: None }
    }

    /// Timestamp for the block holding a log.
    ///
    /// `log_timestamp` is the log's own `blockTimestamp`. It is preferred over a request because it
    /// is the same value the node would answer with, already delivered: resolving it again once
    /// for each log-bearing block made the timestamp lookups outnumber the `eth_getLogs` calls of
    /// the sync they belong to, and each one was a further chance to be rate limited.
    ///
    /// The field is optional in the JSON-RPC response, so a provider that omits it still falls back
    /// to `eth_getBlockByNumber`.
    pub async fn get<L: LogProvider>(
        &mut self,
        provider: &L,
        block_number: Option<u64>,
        log_timestamp: Option<u64>,
    ) -> Result<u64, anyhow::Error> {
        let bn = block_number.context("provider log is missing its block number")?;

        // Cached before returning, so a later log from this block that omits the field is answered
        // from the cache rather than from a request.
        if let Some(ts) = log_timestamp {
            self.current = Some((bn, ts));
            return Ok(ts);
        }

        if let Some((cached_bn, ts)) = self.current {
            if bn == cached_bn {
                return Ok(ts);
            }
        }

        let ts = provider.fetch_block_timestamp(bn).await?;

        self.current = Some((bn, ts));
        Ok(ts)
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
