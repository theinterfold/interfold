// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::log_window::{is_range_limit_error, LogWindow, MIN_LOG_WINDOW};
use alloy::primitives::B256;
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use anyhow::anyhow;
use async_trait::async_trait;
use tracing::warn;

const GET_LOGS_MAX_RETRIES: u32 = 3;
/// Trait abstracting provider methods needed for log fetching.
/// Enables unit testing without a real EVM provider.
#[async_trait]
pub(crate) trait LogProvider: Send + Sync {
    async fn fetch_logs(&self, filter: &Filter) -> Result<Vec<Log>, anyhow::Error>;
    async fn fetch_block_number(&self) -> Result<u64, anyhow::Error>;
    /// Hash of the block at `block_number`, or `None` when the provider has no block there yet.
    async fn fetch_block_hash(&self, block_number: u64) -> Result<Option<B256>, anyhow::Error>;
}

#[async_trait]
impl<P: Provider + Send + Sync> LogProvider for P {
    async fn fetch_logs(&self, filter: &Filter) -> Result<Vec<Log>, anyhow::Error> {
        self.get_logs(filter).await.map_err(|e| anyhow!("{}", e))
    }
    async fn fetch_block_number(&self) -> Result<u64, anyhow::Error> {
        self.get_block_number().await.map_err(|e| anyhow!("{}", e))
    }
    async fn fetch_block_hash(&self, block_number: u64) -> Result<Option<B256>, anyhow::Error> {
        Ok(self
            .get_block_by_number(block_number.into())
            .await
            .map_err(|error| anyhow!("failed to fetch block {block_number}: {error}"))?
            .map(|block| block.header.hash))
    }
}

/// Fetch one chunk, narrowing `window` and retrying until the provider serves it.
///
/// Returns the chunk's logs in chain order and the last block it covers, which is where the caller
/// resumes from.
/// The covered end is returned rather than recomputed, because a narrowing inside this call moves
/// the end of the range: a caller that recomputed it from the window afterwards would advance past
/// blocks that were never fetched.
///
/// Attempts and narrowings are counted separately. A narrowing is not a failed request to be
/// backed off; it is a corrected request that must be reissued at once. One shared budget would let
/// a provider with a tight cap exhaust the attempts before the window reached its limit, and the
/// sync would fail on a provider it could have used. Narrowing has no budget of its own: the
/// one-block floor bounds it, whatever range the chain configures.
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
            Ok(mut logs) => {
                // `eth_getLogs` does not guarantee the log order, and event consumers depend on
                // chain order.
                logs.sort_by_key(|log| (log.block_number, log.log_index));
                return Ok((logs, end));
            }
            Err(e) => {
                let message = format!("{e:#}");

                if is_range_limit_error(&message) {
                    // `shrink` reports `false` at the floor. A provider that refuses a single
                    // block is not applying a range cap, so the error is reported rather than
                    // answered with a narrower range that cannot exist.
                    if !window.shrink() {
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
/// `max_log_window` is the chain's widest `eth_getLogs` range (`rpc_log_range_blocks`).
///
/// Returns the logs in chain order.
pub(crate) async fn fetch_logs_adapting<L: LogProvider>(
    provider: &L,
    filter: &Filter,
    from_block: u64,
    to_block: u64,
    chain_id: u64,
    max_log_window: u64,
) -> Result<Vec<Log>, anyhow::Error> {
    if to_block < from_block {
        return Ok(Vec::new());
    }

    let mut window = LogWindow::with_max(max_log_window);
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
