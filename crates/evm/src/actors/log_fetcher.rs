// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::messages::{EvmEventProcessor, EvmLog, InterfoldEvmEvent};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use anyhow::anyhow;
use async_trait::async_trait;
use e3_events::CorrelationId;
use tracing::{debug, error, info, warn};

const GET_LOGS_CHUNK_SIZE: u64 = 10_000;
const GET_LOGS_MAX_RETRIES: u32 = 3;

/// Trait abstracting provider methods needed for log fetching.
/// Enables unit testing without a real EVM provider.
#[async_trait]
pub(crate) trait LogProvider: Send + Sync {
    async fn fetch_logs(&self, filter: &Filter) -> Result<Vec<Log>, anyhow::Error>;
    async fn fetch_block_number(&self) -> Result<u64, anyhow::Error>;
    async fn fetch_block_timestamp(&self, block_number: u64) -> Option<u64>;
}

#[async_trait]
impl<P: Provider + Send + Sync> LogProvider for P {
    async fn fetch_logs(&self, filter: &Filter) -> Result<Vec<Log>, anyhow::Error> {
        self.get_logs(filter).await.map_err(|e| anyhow!("{}", e))
    }
    async fn fetch_block_number(&self) -> Result<u64, anyhow::Error> {
        self.get_block_number().await.map_err(|e| anyhow!("{}", e))
    }
    async fn fetch_block_timestamp(&self, block_number: u64) -> Option<u64> {
        self.get_block_by_number(block_number.into())
            .await
            .ok()
            .flatten()
            .map(|b| b.header.timestamp)
    }
}

pub(crate) async fn process_log<L: LogProvider>(
    provider: &L,
    log: Log,
    chain_id: u64,
    next: &EvmEventProcessor,
    timestamp_tracker: &mut TimestampTracker,
) -> CorrelationId {
    let timestamp = timestamp_tracker.get(provider, log.block_number).await;
    let evt = InterfoldEvmEvent::Log(EvmLog::new(log, chain_id, timestamp));
    let id = evt.get_id();
    debug!("Sending event({})", id);
    next.do_send(evt);
    id
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
                            process_log(provider, log, chain_id, next, timestamp_tracker).await,
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

    pub async fn get<L: LogProvider>(&mut self, provider: &L, block_number: Option<u64>) -> u64 {
        let Some(bn) = block_number else {
            error!("BLOCK NUMBER NOT FOUND ON LOG!");
            return 0;
        };

        if let Some((cached_bn, ts)) = self.current {
            if bn == cached_bn {
                return ts;
            }
        }

        let ts = provider.fetch_block_timestamp(bn).await.unwrap_or(0);

        self.current = Some((bn, ts));
        ts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::prelude::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;

    #[derive(Clone)]
    struct MockLogProvider {
        inner: Arc<Mutex<MockState>>,
    }

    struct MockState {
        block_number: u64,
        log_responses: VecDeque<Result<Vec<Log>, String>>,
        get_logs_calls: u32,
    }

    impl MockLogProvider {
        fn new(block_number: u64) -> Self {
            Self {
                inner: Arc::new(Mutex::new(MockState {
                    block_number,
                    log_responses: VecDeque::new(),
                    get_logs_calls: 0,
                })),
            }
        }

        fn push_logs(&self, logs: Vec<Log>) {
            self.inner.lock().unwrap().log_responses.push_back(Ok(logs));
        }

        fn push_error(&self, msg: &str) {
            self.inner
                .lock()
                .unwrap()
                .log_responses
                .push_back(Err(msg.to_string()));
        }

        fn get_logs_call_count(&self) -> u32 {
            self.inner.lock().unwrap().get_logs_calls
        }
    }

    #[async_trait]
    impl LogProvider for MockLogProvider {
        async fn fetch_logs(&self, _filter: &Filter) -> Result<Vec<Log>, anyhow::Error> {
            let mut state = self.inner.lock().unwrap();
            state.get_logs_calls += 1;
            match state.log_responses.pop_front() {
                Some(Ok(logs)) => Ok(logs),
                Some(Err(msg)) => Err(anyhow!("{}", msg)),
                None => Ok(vec![]),
            }
        }

        async fn fetch_block_number(&self) -> Result<u64, anyhow::Error> {
            Ok(self.inner.lock().unwrap().block_number)
        }

        async fn fetch_block_timestamp(&self, _block_number: u64) -> Option<u64> {
            Some(0)
        }
    }

    struct TestCollector {
        tx: mpsc::UnboundedSender<InterfoldEvmEvent>,
    }

    impl Actor for TestCollector {
        type Context = Context<Self>;
    }

    impl Handler<InterfoldEvmEvent> for TestCollector {
        type Result = ();
        fn handle(&mut self, msg: InterfoldEvmEvent, _: &mut Self::Context) {
            let _ = self.tx.send(msg);
        }
    }

    fn make_test_log(block_number: u64) -> Log {
        Log {
            block_number: Some(block_number),
            ..Default::default()
        }
    }

    fn setup_collector() -> (
        EvmEventProcessor,
        mpsc::UnboundedReceiver<InterfoldEvmEvent>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        let addr = TestCollector { tx }.start();
        (addr.recipient(), rx)
    }

    #[actix::test]
    async fn test_fetch_logs_empty_range() {
        let mock = MockLogProvider::new(100);
        let (next, _rx) = setup_collector();
        let mut ts = TimestampTracker::new();
        let filter = Filter::new();

        let result = fetch_logs_chunked(&mock, &filter, 200, 100, 1, &next, &mut ts).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(mock.get_logs_call_count(), 0);
    }

    #[actix::test]
    async fn test_fetch_logs_single_chunk() {
        let mock = MockLogProvider::new(5000);
        mock.push_logs(vec![
            make_test_log(100),
            make_test_log(200),
            make_test_log(300),
        ]);
        let (next, mut rx) = setup_collector();
        let mut ts = TimestampTracker::new();
        let filter = Filter::new();

        let result = fetch_logs_chunked(&mock, &filter, 0, 5000, 1, &next, &mut ts).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
        assert_eq!(mock.get_logs_call_count(), 1);

        // Allow actix message delivery
        tokio::task::yield_now().await;
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[actix::test]
    async fn test_fetch_logs_multiple_chunks() {
        // 25k blocks → 3 chunks: [0..9999], [10000..19999], [20000..24999]
        let mock = MockLogProvider::new(25000);
        mock.push_logs(vec![make_test_log(5000)]);
        mock.push_logs(vec![make_test_log(15000)]);
        mock.push_logs(vec![make_test_log(22000)]);
        let (next, _rx) = setup_collector();
        let mut ts = TimestampTracker::new();
        let filter = Filter::new();

        let result = fetch_logs_chunked(&mock, &filter, 0, 24999, 1, &next, &mut ts).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
        assert_eq!(mock.get_logs_call_count(), 3);
    }

    #[actix::test]
    async fn test_fetch_logs_retry_then_success() {
        tokio::time::pause(); // Skip retry delays

        let mock = MockLogProvider::new(5000);
        mock.push_error("temporary RPC error");
        mock.push_logs(vec![make_test_log(100)]);
        let (next, _rx) = setup_collector();
        let mut ts = TimestampTracker::new();
        let filter = Filter::new();

        let result = fetch_logs_chunked(&mock, &filter, 0, 5000, 1, &next, &mut ts).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
        assert_eq!(mock.get_logs_call_count(), 2);
    }

    #[actix::test]
    async fn test_fetch_logs_all_retries_exhausted() {
        tokio::time::pause();

        let mock = MockLogProvider::new(5000);
        for _ in 0..GET_LOGS_MAX_RETRIES {
            mock.push_error("persistent RPC error");
        }
        let (next, _rx) = setup_collector();
        let mut ts = TimestampTracker::new();
        let filter = Filter::new();

        let result = fetch_logs_chunked(&mock, &filter, 0, 5000, 1, &next, &mut ts).await;

        let err = result.expect_err("expected error after all retries exhausted");
        assert!(
            err.to_string().contains("Failed to fetch logs"),
            "unexpected error: {err}"
        );
        assert_eq!(mock.get_logs_call_count(), GET_LOGS_MAX_RETRIES);
    }

    #[actix::test]
    async fn test_backfill_no_gap() {
        let mock = MockLogProvider::new(100);
        let (next, _rx) = setup_collector();
        let mut ts = TimestampTracker::new();
        let filter = Filter::new();
        let mut last_block = 100u64;

        let result = backfill_to_head(&mock, &filter, 1, &next, &mut ts, &mut last_block, 0).await;

        assert!(result.is_ok());
        assert_eq!(last_block, 100);
        assert_eq!(mock.get_logs_call_count(), 0);
    }

    #[actix::test]
    async fn test_backfill_with_gap() {
        let mock = MockLogProvider::new(200);
        mock.push_logs(vec![make_test_log(150), make_test_log(180)]);
        let (next, mut rx) = setup_collector();
        let mut ts = TimestampTracker::new();
        let filter = Filter::new();
        let mut last_block = 100u64;

        let result = backfill_to_head(&mock, &filter, 1, &next, &mut ts, &mut last_block, 0).await;

        assert!(result.is_ok());
        assert_eq!(last_block, 200);
        assert_eq!(mock.get_logs_call_count(), 1);

        tokio::task::yield_now().await;
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[actix::test]
    async fn test_backfill_partial_failure_preserves_progress() {
        tokio::time::pause();

        // Head at 25000, last_block at 100
        // Gap: blocks 101..=25000 → 3 chunks:
        //   chunk 1: [101, 10100]
        //   chunk 2: [10101, 20100]
        //   chunk 3: [20101, 25000]
        let mock = MockLogProvider::new(25000);
        // Chunk 1 succeeds
        mock.push_logs(vec![make_test_log(500)]);
        // Chunk 2 succeeds
        mock.push_logs(vec![make_test_log(15000)]);
        // Chunk 3: all retries fail
        for _ in 0..GET_LOGS_MAX_RETRIES {
            mock.push_error("RPC error");
        }

        let (next, _rx) = setup_collector();
        let mut ts = TimestampTracker::new();
        let filter = Filter::new();
        let mut last_block = 100u64;

        let result = backfill_to_head(&mock, &filter, 1, &next, &mut ts, &mut last_block, 0).await;

        // Should fail because chunk 3 exhausted retries
        assert!(result.is_err());
        // But last_block must have advanced past the two successful chunks
        assert_eq!(last_block, 20100);

        // On retry: gap_start = 20101, head still 25000 → single chunk succeeds
        mock.push_logs(vec![make_test_log(22000)]);

        let result = backfill_to_head(&mock, &filter, 1, &next, &mut ts, &mut last_block, 0).await;
        assert!(result.is_ok());
        assert_eq!(last_block, 25000);
    }

    #[actix::test]
    async fn test_backfill_clamps_to_confirmed_head() {
        // Head at 200, but require 12 confirmations => only ingest up to 188.
        let mock = MockLogProvider::new(200);
        mock.push_logs(vec![make_test_log(150)]);
        let (next, _rx) = setup_collector();
        let mut ts = TimestampTracker::new();
        let filter = Filter::new();
        let mut last_block = 100u64;

        let result = backfill_to_head(&mock, &filter, 1, &next, &mut ts, &mut last_block, 12).await;

        assert!(result.is_ok());
        // Advanced only to the confirmed head, not the raw head of 200.
        assert_eq!(last_block, 188);
    }
}
