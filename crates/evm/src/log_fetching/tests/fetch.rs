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
    let filter = Filter::new();

    let result = fetch_logs_chunked(&mock, &filter, 200, 100, 1, &next, &mut ts).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    assert_eq!(mock.get_logs_call_count(), 0);
}

#[actix::test]
async fn timestamp_lookup_retries_transient_provider_lag() {
    tokio::time::pause();

    let mock = MockLogProvider::new(100);
    mock.push_timestamp_error("provider returned no block for height 100");
    mock.push_timestamp(1234);
    let mut tracker = TimestampTracker::new();

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
async fn log_timestamp_avoids_cross_provider_block_lookup() {
    let mock = MockLogProvider::new(100);
    let mut tracker = TimestampTracker::new();

    assert_eq!(
        tracker.get(&mock, Some(100), Some(1234)).await.unwrap(),
        1234
    );
    assert_eq!(mock.timestamp_call_count(), 0);
}

#[actix::test]
async fn timestamp_rpc_failure_prevents_log_dispatch() {
    tokio::time::pause();

    let mock = MockLogProvider::new(100);
    mock.push_logs(vec![make_test_log(100)]);
    for _ in 0..BLOCK_TIMESTAMP_MAX_ATTEMPTS {
        mock.push_timestamp_error("timestamp RPC unavailable");
    }
    let (next, mut receiver) = setup_collector();
    let mut tracker = TimestampTracker::new();

    let error = fetch_logs_chunked(&mock, &Filter::new(), 100, 100, 1, &next, &mut tracker)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("timestamp RPC unavailable"));
    assert_eq!(mock.timestamp_call_count(), BLOCK_TIMESTAMP_MAX_ATTEMPTS);
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
