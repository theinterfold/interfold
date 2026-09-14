// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_events::{
    AggregateId, E3id, EventConstructorWithTimestamp, EventSource, KeyshareCreated, TestEvent,
};
use e3_utils::ArcBytes;

#[test]
fn no_peers_publishes_immediately_and_is_idempotent() {
    let mut r = NetReadiness::new();
    assert_eq!(r.on_all_peers_dialed(0, 0), ReadinessDecision::PublishReady);
    assert_eq!(r.on_all_peers_dialed(0, 0), ReadinessDecision::Idle);
}

#[test]
fn connected_peers_publish_ready() {
    let mut r = NetReadiness::new();
    assert_eq!(r.on_all_peers_dialed(2, 3), ReadinessDecision::PublishReady);
}

#[test]
fn all_dials_failed_waits_then_publishes_on_connect() {
    let mut r = NetReadiness::new();
    assert_eq!(
        r.on_all_peers_dialed(0, 3),
        ReadinessDecision::WaitForConnection
    );
    assert_eq!(r.on_peer_connected(), ReadinessDecision::PublishReady);
    assert_eq!(r.on_peer_connected(), ReadinessDecision::Idle);
}

#[test]
fn timeout_publishes_when_no_connection_arrived() {
    let mut r = NetReadiness::new();
    assert_eq!(
        r.on_all_peers_dialed(0, 3),
        ReadinessDecision::WaitForConnection
    );
    assert_eq!(r.on_connect_timeout(), ReadinessDecision::PublishReady);
    assert_eq!(r.on_connect_timeout(), ReadinessDecision::Idle);
}

#[test]
fn peer_connected_before_dial_does_not_publish() {
    let mut r = NetReadiness::new();
    assert_eq!(r.on_peer_connected(), ReadinessDecision::Idle);
    // Once dialing finishes with the connection already present, publish.
    assert_eq!(r.on_all_peers_dialed(0, 3), ReadinessDecision::PublishReady);
}

fn net_event(ts: u128) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        KeyshareCreated {
            pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
            e3_id: E3id::new(ts.to_string(), 1),
            node: "node-1".to_string(),
            party_id: 1,
            signed_pk_generation_proof: None,
            roster_hash: [0; 32],
        }
        .into(),
        None,
        ts,
        None,
        EventSource::Net,
    )
    .into_sequenced(ts as u64)
}

fn net_non_forwardable_event(ts: u128) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        TestEvent::new("remote-control", ts as u64).into(),
        None,
        ts,
        None,
        EventSource::Net,
    )
    .into_sequenced(ts as u64)
}

fn local_event(ts: u128) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        TestEvent::new("y", ts as u64).into(),
        None,
        ts,
        None,
        EventSource::Local,
    )
    .into_sequenced(ts as u64)
}

#[test]
fn build_sync_batch_rejects_zero_limit() {
    let fetch = FetchEventsSince::new(AggregateId::new(1), 0, 0);
    assert!(matches!(
        build_sync_batch(vec![], &fetch),
        SyncBatchOutcome::BadRequest(_)
    ));
}

#[test]
fn build_sync_batch_filters_local_non_forwardable_and_marks_done() {
    let fetch = FetchEventsSince::new(AggregateId::new(1), 0, 10);
    let outcome = build_sync_batch(
        vec![net_event(5), net_non_forwardable_event(6), local_event(7)],
        &fetch,
    );
    let SyncBatchOutcome::Batch(batch) = outcome else {
        panic!("expected batch");
    };
    // Only the allowlisted protocol event survives. Remote source does not make an internal
    // TestEvent forwardable.
    assert_eq!(batch.events.len(), 1);
    assert!(matches!(batch.next, BatchCursor::Done));
}

#[test]
fn build_sync_batch_limit_one_advances_past_inclusive_cursor() {
    let fetch = FetchEventsSince::new(AggregateId::new(1), 0, 1);
    let outcome = build_sync_batch(vec![net_event(5), net_event(9)], &fetch);
    let SyncBatchOutcome::Batch(batch) = outcome else {
        panic!("expected batch");
    };
    assert_eq!(batch.events.len(), 1);
    assert!(matches!(batch.next, BatchCursor::Next(6)));
}

#[test]
fn build_sync_batch_caps_malicious_huge_limit() {
    let fetch = FetchEventsSince::new(AggregateId::new(1), 0, usize::MAX);
    let events = (1..=MAX_SYNC_BATCH_SIZE + 1)
        .map(|ts| net_event(ts as u128))
        .collect();
    let SyncBatchOutcome::Batch(batch) = build_sync_batch(events, &fetch) else {
        panic!("expected batch");
    };

    assert_eq!(batch.events.len(), MAX_SYNC_BATCH_SIZE);
    assert!(matches!(
        batch.next,
        BatchCursor::Next(next) if next == MAX_SYNC_BATCH_SIZE as u128 + 1
    ));
    assert_eq!(sync_scan_limit(fetch.limit()), MAX_SYNC_SCAN_EVENTS);
}

#[test]
fn build_sync_batch_advances_past_full_filtered_scan() {
    let fetch = FetchEventsSince::new(AggregateId::new(1), 0, 1);
    let events = (1..=sync_scan_limit(fetch.limit()))
        .map(|ts| local_event(ts as u128))
        .collect();
    let SyncBatchOutcome::Batch(batch) = build_sync_batch(events, &fetch) else {
        panic!("expected batch");
    };

    assert!(batch.events.is_empty());
    assert!(matches!(
        batch.next,
        BatchCursor::Next(next) if next == sync_scan_limit(fetch.limit()) as u128 + 1
    ));
}

#[test]
fn build_sync_batch_stops_at_max_timestamp() {
    let fetch = FetchEventsSince::new(AggregateId::new(1), u128::MAX, 1);
    let SyncBatchOutcome::Batch(batch) = build_sync_batch(vec![net_event(u128::MAX)], &fetch)
    else {
        panic!("expected batch");
    };

    assert_eq!(batch.events.len(), 1);
    assert!(matches!(batch.next, BatchCursor::Done));
}
