// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::direct_requester::DirectRequesterTester;
use crate::events::{NetCommand, PeerTarget};
use crate::net_interface_handle::{NetEventChannel, NetEventSubscriber};
use tokio::sync::mpsc;

#[test]
fn sync_fetch_budget_rejects_each_resource_limit_without_mutating_state() {
    let mut budget = SyncFetchBudget::new(1, 2, 3);
    budget.record_page(2, 3).unwrap();

    let page_error = budget.record_page(0, 0).unwrap_err();
    assert!(page_error.to_string().contains("page limit"));
    assert_eq!((budget.pages, budget.events, budget.bytes), (1, 2, 3));

    let mut event_budget = SyncFetchBudget::new(2, 1, 3);
    let event_error = event_budget.record_page(2, 0).unwrap_err();
    assert!(event_error.to_string().contains("event limit"));
    assert_eq!(
        (event_budget.pages, event_budget.events, event_budget.bytes),
        (0, 0, 0)
    );

    let mut byte_budget = SyncFetchBudget::new(2, 2, 1);
    let byte_error = byte_budget.record_page(0, 2).unwrap_err();
    assert!(byte_error.to_string().contains("byte limit"));
    assert_eq!(
        (byte_budget.pages, byte_budget.events, byte_budget.bytes),
        (0, 0, 0)
    );
}

#[tokio::test]
async fn test_non_advancing_cursor_is_rejected() {
    let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
    let net_events_tx = NetEventChannel::new(16);
    let _net_events_rx = net_events_tx.subscribe();
    let net_events = NetEventSubscriber::from(&net_events_tx);

    let requester = DirectRequester::builder(net_cmds_tx, net_events).build();
    let batch = EventBatch {
        events: vec![b"event1".to_vec()],
        next: BatchCursor::Next(0),
        aggregate_id: AggregateId::new(1),
        observed_from: None,
    };
    let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
        .expect_request(FetchEventsSince::new(AggregateId::new(1), 0, 1))
        .respond_with(batch)
        .spawn();

    let error = fetch_all_batched_events_with_budget::<Vec<u8>>(
        requester,
        PeerTarget::Random,
        AggregateId::new(1),
        0,
        1,
        &mut SyncFetchBudget::production(),
        None,
    )
    .await
    .unwrap_err();

    handle.await.unwrap();
    assert!(error.to_string().contains("non-advancing cursor"));
}

#[tokio::test]
async fn test_three_batches_with_cursor_continuity() {
    let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
    let net_events_tx = NetEventChannel::new(16);
    let _net_events_rx = net_events_tx.subscribe();
    let net_events = NetEventSubscriber::from(&net_events_tx);

    let requester = DirectRequester::builder(net_cmds_tx, net_events).build();

    let batch1 = EventBatch {
        events: vec![b"a".to_vec(), b"b".to_vec()],
        next: BatchCursor::Next(200),
        aggregate_id: AggregateId::new(1),
        observed_from: None,
    };
    let batch2 = EventBatch {
        events: vec![b"c".to_vec(), b"d".to_vec()],
        next: BatchCursor::Next(400),
        aggregate_id: AggregateId::new(1),
        observed_from: None,
    };
    let batch3 = EventBatch {
        events: vec![b"e".to_vec()],
        next: BatchCursor::Done,
        aggregate_id: AggregateId::new(1),
        observed_from: None,
    };

    let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
        .expect_request(FetchEventsSince::new(AggregateId::new(1), 0, 2))
        .respond_with(batch1)
        .expect_request(FetchEventsSince::new(AggregateId::new(1), 200, 2))
        .respond_with(batch2)
        .expect_request(FetchEventsSince::new(AggregateId::new(1), 400, 2))
        .respond_with(batch3)
        .spawn();

    let events: Vec<Vec<u8>> = fetch_all_batched_events_with_budget(
        requester,
        PeerTarget::Random,
        AggregateId::new(1),
        0,
        2,
        &mut SyncFetchBudget::production(),
        None,
    )
    .await
    .unwrap()
    .events;

    handle.await.unwrap();

    let expected = vec![
        b"a".to_vec(),
        b"b".to_vec(),
        b"c".to_vec(),
        b"d".to_vec(),
        b"e".to_vec(),
    ];
    assert_eq!(events.len(), expected.len());
    assert_eq!(events, expected);
}

#[tokio::test]
async fn a_responder_that_resets_between_pages_fails_as_a_source() {
    let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
    let net_events_tx = NetEventChannel::new(16);
    let _net_events_rx = net_events_tx.subscribe();
    let net_events = NetEventSubscriber::from(&net_events_tx);

    let requester = DirectRequester::builder(net_cmds_tx, net_events).build();
    // The first page vouches from 5. The responder then resets and answers the next cursor
    // from an empty log while it starts up.
    let first = EventBatch {
        events: vec![b"a".to_vec()],
        next: BatchCursor::Next(200),
        aggregate_id: AggregateId::new(1),
        observed_from: Some(5),
    };
    let after_reset = EventBatch::<Vec<u8>> {
        events: vec![],
        next: BatchCursor::Done,
        aggregate_id: AggregateId::new(1),
        observed_from: None,
    };
    let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
        .expect_request(FetchEventsSince::new(AggregateId::new(1), 0, 1))
        .respond_with(first)
        .expect_request(FetchEventsSince::new(AggregateId::new(1), 200, 1))
        .respond_with(after_reset)
        .spawn();

    let error = fetch_all_batched_events_with_budget::<Vec<u8>>(
        requester,
        PeerTarget::Random,
        AggregateId::new(1),
        0,
        1,
        &mut SyncFetchBudget::production(),
        None,
    )
    .await
    .unwrap_err();

    handle.await.unwrap();
    assert!(error
        .to_string()
        .contains("changed its live-history time from Some(5) to None"));
}

/// A responder that ends its own startup during the fetch keeps its log: its pages still form one
/// history, and the source keeps the time of its first page, so it vouches for nothing.
#[tokio::test]
async fn a_responder_that_ends_its_startup_between_pages_stays_a_source() {
    let (net_cmds_tx, net_cmds_rx) = mpsc::channel::<NetCommand>(16);
    let net_events_tx = NetEventChannel::new(16);
    let _net_events_rx = net_events_tx.subscribe();
    let net_events = NetEventSubscriber::from(&net_events_tx);

    let requester = DirectRequester::builder(net_cmds_tx, net_events).build();
    let starting = EventBatch {
        events: vec![b"a".to_vec()],
        next: BatchCursor::Next(200),
        aggregate_id: AggregateId::new(1),
        observed_from: None,
    };
    let started = EventBatch {
        events: vec![b"b".to_vec()],
        next: BatchCursor::Done,
        aggregate_id: AggregateId::new(1),
        observed_from: Some(7),
    };
    let handle = DirectRequesterTester::new(net_cmds_rx, net_events_tx)
        .expect_request(FetchEventsSince::new(AggregateId::new(1), 0, 1))
        .respond_with(starting)
        .expect_request(FetchEventsSince::new(AggregateId::new(1), 200, 1))
        .respond_with(started)
        .spawn();

    let fetched = fetch_all_batched_events_with_budget::<Vec<u8>>(
        requester,
        PeerTarget::Random,
        AggregateId::new(1),
        0,
        1,
        &mut SyncFetchBudget::production(),
        None,
    )
    .await
    .unwrap();

    handle.await.unwrap();
    assert_eq!(fetched.events, vec![b"a".to_vec(), b"b".to_vec()]);
    assert_eq!(fetched.observed_from, None);
}
