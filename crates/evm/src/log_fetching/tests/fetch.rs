// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[actix::test]
async fn test_fetch_logs_empty_range() {
    let mock = MockLogProvider::new(100);
    let (next, _rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();
    let filter = Filter::new();

    let result = fetch_logs_chunked(&mock, &filter, 200, 100, 1, &next, &mut ts, &mut window).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    assert_eq!(mock.get_logs_call_count(), 0);
}

#[actix::test]
async fn timestamp_failure_is_not_cached_as_zero() {
    let mock = MockLogProvider::new(100);
    mock.push_timestamp_error("RPC unavailable");
    mock.push_timestamp(1234);
    let mut tracker = TimestampTracker::new();

    let error = tracker.get(&mock, Some(100), None).await.unwrap_err();
    assert!(error.to_string().contains("RPC unavailable"));
    assert_eq!(tracker.get(&mock, Some(100), None).await.unwrap(), 1234);
    assert_eq!(tracker.get(&mock, Some(100), None).await.unwrap(), 1234);
    assert_eq!(mock.timestamp_call_count(), 2);
}

#[actix::test]
async fn missing_log_block_number_is_rejected_without_rpc_fallback() {
    let mock = MockLogProvider::new(100);
    let mut tracker = TimestampTracker::new();

    let error = tracker.get(&mock, None, None).await.unwrap_err();
    assert!(error.to_string().contains("missing its block number"));
    assert_eq!(mock.timestamp_call_count(), 0);
}

#[actix::test]
async fn timestamp_rpc_failure_prevents_log_dispatch() {
    let mock = MockLogProvider::new(100);
    mock.push_logs(vec![make_test_log(100)]);
    mock.push_timestamp_error("timestamp RPC unavailable");
    let (next, mut receiver) = setup_collector();
    let mut tracker = TimestampTracker::new();
    let mut window = LogWindow::new();

    let error = fetch_logs_chunked(
        &mock,
        &Filter::new(),
        100,
        100,
        1,
        &next,
        &mut tracker,
        &mut window,
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains("timestamp RPC unavailable"));
    tokio::task::yield_now().await;
    assert!(receiver.try_recv().is_err());
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
    let mut window = LogWindow::new();
    let filter = Filter::new();

    let result = fetch_logs_chunked(&mock, &filter, 0, 5000, 1, &next, &mut ts, &mut window).await;

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
    let mut window = LogWindow::new();
    let filter = Filter::new();

    let result = fetch_logs_chunked(&mock, &filter, 0, 24999, 1, &next, &mut ts, &mut window).await;

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
    let mut window = LogWindow::new();
    let filter = Filter::new();

    let result = fetch_logs_chunked(&mock, &filter, 0, 5000, 1, &next, &mut ts, &mut window).await;

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
    let mut window = LogWindow::new();
    let filter = Filter::new();

    let result = fetch_logs_chunked(&mock, &filter, 0, 5000, 1, &next, &mut ts, &mut window).await;

    let err = result.expect_err("expected error after all retries exhausted");
    assert!(
        err.to_string().contains("Failed to fetch logs"),
        "unexpected error: {err}"
    );
    assert_eq!(mock.get_logs_call_count(), GET_LOGS_MAX_RETRIES);
}

#[actix::test]
async fn a_rejected_range_is_retried_narrower_and_covers_every_block() {
    // The provider refuses anything wider than 2,500 blocks. The first two attempts are rejected,
    // the third succeeds, and the range 0..=9999 must still be read in full.
    let mock = MockLogProvider::new(9_999);
    mock.push_error("error code -32062: range too large");
    mock.push_error("error code -32062: range too large");
    mock.push_logs(vec![make_test_log(100)]); // 0..=2499
    mock.push_logs(vec![make_test_log(3_000)]); // 2500..=4999
    mock.push_logs(vec![make_test_log(6_000)]); // 5000..=7499
    mock.push_logs(vec![make_test_log(8_000)]); // 7500..=9999
    let (next, mut rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();
    let filter = Filter::new();

    let result = fetch_logs_chunked(&mock, &filter, 0, 9_999, 1, &next, &mut ts, &mut window).await;

    assert!(result.is_ok(), "adaptive retry should succeed: {result:?}");
    // Two rejections then four accepted chunks.
    assert_eq!(mock.get_logs_call_count(), 6);
    assert_eq!(window.width(), 2_500);

    // Every block in the range was covered: all four logs arrived, none skipped.
    tokio::task::yield_now().await;
    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    assert_eq!(count, 4, "a narrowed window must not skip blocks");
}

#[actix::test]
async fn a_narrowed_window_is_kept_for_later_chunks() {
    // After one rejection the window must stay narrow. A window that grew back would be rejected
    // again on the next chunk and pay one wasted request per chunk.
    let mock = MockLogProvider::new(20_000);
    mock.push_error("query returned more than 10000 results");
    for _ in 0..4 {
        mock.push_logs(vec![]);
    }
    let (next, _rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();

    fetch_logs_chunked(
        &mock,
        &Filter::new(),
        0,
        19_999,
        1,
        &next,
        &mut ts,
        &mut window,
    )
    .await
    .expect("should succeed at the narrowed width");

    assert_eq!(window.width(), 5_000);
    // One rejection plus exactly four 5k chunks — no repeated rediscovery.
    assert_eq!(mock.get_logs_call_count(), 5);
}

#[actix::test]
async fn a_range_error_does_not_consume_the_retry_budget() {
    tokio::time::pause();

    // Eight rejections is more than GET_LOGS_MAX_RETRIES. They are narrowings, not failed attempts,
    // so the chunk must still succeed once the window reaches the provider's limit.
    let mock = MockLogProvider::new(100);
    for _ in 0..8 {
        mock.push_error("range too large");
    }
    mock.push_logs(vec![make_test_log(10)]);
    let (next, _rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();

    let result = fetch_logs_chunked(
        &mock,
        &Filter::new(),
        0,
        100,
        1,
        &next,
        &mut ts,
        &mut window,
    )
    .await;

    assert!(
        result.is_ok(),
        "range errors must not exhaust the retry budget: {result:?}"
    );
    assert_eq!(window.width(), 39);
}

#[actix::test]
async fn a_provider_that_rejects_every_range_fails_with_an_actionable_error() {
    tokio::time::pause();

    // Rejecting even a single block is not a range cap. The node must stop rather than narrow
    // forever.
    let mock = MockLogProvider::new(100);
    for _ in 0..40 {
        mock.push_error("range too large");
    }
    let (next, _rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();

    let error = fetch_logs_chunked(
        &mock,
        &Filter::new(),
        0,
        100,
        1,
        &next,
        &mut ts,
        &mut window,
    )
    .await
    .expect_err("a provider refusing one block must fail");

    let message = error.to_string();
    assert!(
        message.contains("smallest window"),
        "error should name the exhausted window: {message}"
    );
    assert_eq!(window.width(), MIN_LOG_WINDOW);
}

#[actix::test]
async fn a_rate_limit_error_is_retried_without_narrowing_the_window() {
    tokio::time::pause();

    // A 429 is answered with backoff, not a narrower range: fewer blocks per call would not raise
    // the rate limit and would multiply the number of calls.
    let mock = MockLogProvider::new(5_000);
    mock.push_error("429 Too Many Requests");
    mock.push_logs(vec![make_test_log(100)]);
    let (next, _rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();

    let result = fetch_logs_chunked(
        &mock,
        &Filter::new(),
        0,
        5_000,
        1,
        &next,
        &mut ts,
        &mut window,
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(
        window.width(),
        MAX_LOG_WINDOW,
        "a rate limit must not narrow the window"
    );
}

#[actix::test]
async fn a_log_carrying_its_timestamp_costs_no_extra_request() {
    // The provider already delivered the timestamp with the log, so resolving it must not send
    // eth_getBlockByNumber. This is the common case on a real endpoint.
    let mock = MockLogProvider::new(100);
    let mut tracker = TimestampTracker::new();

    let ts = tracker
        .get(&mock, Some(100), Some(1_700_000_000))
        .await
        .expect("a log timestamp needs no request");

    assert_eq!(ts, 1_700_000_000);
    assert_eq!(
        mock.timestamp_call_count(),
        0,
        "the log's own timestamp must not trigger a request"
    );
}

#[actix::test]
async fn a_whole_chunk_of_timestamped_logs_sends_no_timestamp_requests() {
    // Each log sits in its own block. Before the log's own timestamp was used, this chunk cost one
    // eth_getBlockByNumber per block — more requests than the eth_getLogs calls of the sync.
    let mock = MockLogProvider::new(5_000);
    mock.push_logs(vec![
        make_timestamped_log(10, 1_700_000_010),
        make_timestamped_log(20, 1_700_000_020),
        make_timestamped_log(30, 1_700_000_030),
        make_timestamped_log(40, 1_700_000_040),
    ]);
    let (next, mut rx) = setup_collector();
    let mut ts = TimestampTracker::new();
    let mut window = LogWindow::new();

    fetch_logs_chunked(
        &mock,
        &Filter::new(),
        0,
        5_000,
        1,
        &next,
        &mut ts,
        &mut window,
    )
    .await
    .expect("chunk should succeed");

    assert_eq!(
        mock.timestamp_call_count(),
        0,
        "four distinct blocks must cost zero timestamp requests"
    );

    tokio::task::yield_now().await;
    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    assert_eq!(count, 4, "every log must still be delivered");
}

#[actix::test]
async fn a_provider_that_omits_the_timestamp_still_falls_back_to_the_block() {
    // block_timestamp is optional in the JSON-RPC response. When absent the tracker must still
    // resolve the value rather than invent one.
    let mock = MockLogProvider::new(100);
    mock.push_timestamp(1_700_000_500);
    let mut tracker = TimestampTracker::new();

    let ts = tracker
        .get(&mock, Some(77), None)
        .await
        .expect("fallback should resolve");

    assert_eq!(ts, 1_700_000_500);
    assert_eq!(mock.timestamp_call_count(), 1);
}

#[actix::test]
async fn a_timestamp_from_a_log_is_reused_by_a_later_log_that_omits_it() {
    // Mixed responses within one block: the first log carries the timestamp, a second from the
    // same block does not. The cached value must answer the second rather than a request.
    let mock = MockLogProvider::new(100);
    let mut tracker = TimestampTracker::new();

    let first = tracker
        .get(&mock, Some(50), Some(1_700_000_050))
        .await
        .unwrap();
    let second = tracker.get(&mock, Some(50), None).await.unwrap();

    assert_eq!(first, second);
    assert_eq!(
        mock.timestamp_call_count(),
        0,
        "the cached log timestamp must serve the second log"
    );
}

/// A provider that caps `eth_getLogs` below the old fixed window must not defeat the shared read.
///
/// This is the reported failure. `fetch_randomness_providers` asked for 10,000 blocks at a time and
/// propagated the resulting error, so a ciphernode would not start against any endpoint whose cap
/// was lower — even though the event pager beside it, which narrows the window until the provider
/// accepts it, would have coped. 1RPC caps at 50 blocks and words the refusal without the article
/// the classifier used to require, so the narrowing never happened either.
#[actix::test]
async fn a_capped_provider_does_not_defeat_the_shared_read() {
    // 1RPC's wording, captured verbatim.
    let provider = CappedLogProvider::new(500, 50, "eth_getLogs is limited to 0 - 50 blocks range")
        .with_log(120)
        .with_log(300)
        .with_log(499);

    let logs = fetch_logs_adapting(&provider, &Filter::new(), 100, 500, 1)
        .await
        .expect("a provider that caps the range must not fail the read");

    let mut blocks: Vec<u64> = logs.iter().filter_map(|log| log.block_number).collect();
    blocks.sort_unstable();
    assert_eq!(
        blocks,
        vec![120, 300, 499],
        "every event in the range must be read"
    );

    assert!(
        provider.refused() > 0,
        "the window must have narrowed against the cap"
    );

    let served = provider.served();
    assert_eq!(served[0].0, 100, "the scan starts at from_block");
    assert_eq!(served.last().unwrap().1, 500, "the scan reaches to_block");

    // Contiguous and non-overlapping across the whole range: a gap drops an event and an overlap
    // re-reads one, and neither is visible from the returned logs alone.
    for pair in served.windows(2) {
        assert_eq!(
            pair[1].0,
            pair[0].1 + 1,
            "served ranges must tile the scan: {served:?}"
        );
    }

    // Every served request is within the cap, so none of them was one the provider had to refuse.
    for (from, to) in &served {
        let width = to - from + 1;
        assert!(
            width <= 50,
            "served range {from}..={to} is {width} blocks, over the provider's cap"
        );
    }
}
