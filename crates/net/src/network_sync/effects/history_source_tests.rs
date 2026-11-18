// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::direct_requester::DirectRequesterTester;
use crate::events::{NetCommand, PeerTarget};
use crate::net_interface_handle::{NetEventChannel, NetEventSubscriber};
use e3_events::{E3id, EventConstructorWithTimestamp, InterfoldEventData, KeyshareCreated};
use e3_utils::ArcBytes;
use tokio::sync::mpsc;

/// The keyshare `pubkey`, as a peer that received it at `ts` stores it.
fn keyshare(pubkey: &[u8], ts: u128) -> InterfoldEvent<Unsequenced> {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        KeyshareCreated {
            pubkey: ArcBytes::from_bytes(pubkey),
            e3_id: E3id::new("1", 1),
            node: "node-1".to_string(),
            party_id: 1,
            signed_pk_generation_proof: None,
        }
        .into(),
        None,
        ts,
        None,
        EventSource::Net,
    )
}

/// `payload`'s event under the context of `label`, as two payloads with one ID would arrive.
fn under_the_id_of(
    payload: &[u8],
    label: &InterfoldEvent<Unsequenced>,
) -> InterfoldEvent<Unsequenced> {
    #[derive(serde::Serialize)]
    struct Raw<'a> {
        payload: &'a InterfoldEventData,
        ctx: &'a e3_events::EventContext<Unsequenced>,
    }
    let (data, _) = keyshare(payload, 5).into_components();
    let (_, ctx) = label.clone().into_components();
    let bytes = bincode::serialize(&Raw {
        payload: &data,
        ctx: &ctx,
    })
    .unwrap();
    InterfoldEvent::from_bytes(&bytes).unwrap()
}

fn range() -> HistoryRange {
    HistoryRange {
        aggregate_id: AggregateId::new(1),
        since: 0,
        stored: Default::default(),
        latest_ts: Arc::new(|| Ok(u128::MAX)),
    }
}

fn page(
    events: Vec<InterfoldEvent<Unsequenced>>,
    next: BatchCursor,
) -> EventBatch<InterfoldEvent<Unsequenced>> {
    EventBatch {
        events,
        next,
        aggregate_id: AggregateId::new(1),
        observed_from: None,
    }
}

/// Serve `pages` for requests from the given cursors, and fetch them as one source.
async fn fetch_pages(
    pages: Vec<(u128, EventBatch<InterfoldEvent<Unsequenced>>)>,
) -> Result<(Vec<InterfoldEvent<Unsequenced>>, Option<u128>)> {
    let (commands, commands_rx) = mpsc::channel::<NetCommand>(16);
    let events = NetEventChannel::new(16);
    let _keep_open = events.subscribe();
    let requester = DirectRequester::builder(commands, NetEventSubscriber::from(&events))
        .build()
        .to(PeerTarget::Random);
    let mut tester = DirectRequesterTester::new(commands_rx, events);
    for (cursor, batch) in pages {
        tester = tester
            .expect_request(FetchEventsSince::new(
                AggregateId::new(1),
                cursor,
                MAX_SYNC_BATCH_SIZE,
            ))
            .respond_with(batch);
    }
    let handle = tester.spawn();
    let range = range();
    let policy = NetworkPolicy::local_unrestricted();
    let held = MergedEvents::default();
    let mut source = SourceHistory::new(&range, &held, &policy, MAX_KEPT_HISTORY);
    let fetched = fetch_source(
        &requester,
        &mut source,
        &mut FetchDeadline::production(),
        None,
    )
    .await;
    handle.await.unwrap();
    let observed_from = fetched?;
    Ok((source.finish()?.events.into_events(), observed_from))
}

#[tokio::test]
async fn pages_follow_the_responders_cursor() {
    let (events, _) = fetch_pages(vec![
        (
            0,
            page(
                vec![keyshare(&[1], 10), keyshare(&[2], 20)],
                BatchCursor::Next(200),
            ),
        ),
        (200, page(vec![keyshare(&[3], 210)], BatchCursor::Next(400))),
        (400, page(vec![keyshare(&[4], 410)], BatchCursor::Done)),
    ])
    .await
    .unwrap();

    let times: Vec<_> = events.iter().map(|event| event.ts()).collect();
    assert_eq!(times, vec![10, 20, 210, 410]);
}

#[tokio::test]
async fn a_non_advancing_cursor_fails_the_source() {
    let error = fetch_pages(vec![(
        0,
        page(vec![keyshare(&[1], 10)], BatchCursor::Next(0)),
    )])
    .await
    .unwrap_err();

    assert!(error.to_string().contains("non-advancing cursor"));
}

#[tokio::test]
async fn a_responder_that_resets_between_pages_fails_as_a_source() {
    // The first page vouches from 5. The responder then resets and answers the next cursor from
    // an empty log while it starts up.
    let mut first = page(vec![keyshare(&[1], 10)], BatchCursor::Next(200));
    first.observed_from = Some(5);
    let error = fetch_pages(vec![(0, first), (200, page(vec![], BatchCursor::Done))])
        .await
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("changed its live-history time from Some(5) to None"));
}

/// A responder that ends its own startup during the fetch keeps its log: its pages still form one
/// history, and the source keeps the time of its first page, so it vouches for nothing.
#[tokio::test]
async fn a_responder_that_ends_its_startup_between_pages_stays_a_source() {
    let mut started = page(vec![keyshare(&[2], 210)], BatchCursor::Done);
    started.observed_from = Some(7);
    let (events, observed_from) = fetch_pages(vec![
        (0, page(vec![keyshare(&[1], 10)], BatchCursor::Next(200))),
        (200, started),
    ])
    .await
    .unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(observed_from, None);
}

/// A peer that stored an event several times serves every copy. The source keeps the earliest,
/// and only kept events count against the limit.
#[test]
fn copies_count_once_against_the_kept_history() {
    let range = range();
    let policy = NetworkPolicy::local_unrestricted();
    let one = HistorySize::of(&keyshare(&[1], 10)).unwrap();
    let held = MergedEvents::default();
    let mut source = SourceHistory::new(&range, &held, &policy, one);
    for ts in [10, 20, 30] {
        source.add(keyshare(&[1], ts)).unwrap();
    }
    let error = source.add(keyshare(&[2], 40)).unwrap_err();
    assert!(error.to_string().contains("kept-history limit"), "{error}");

    let mut source = SourceHistory::new(&range, &held, &policy, one);
    for ts in [10, 20, 30] {
        source.add(keyshare(&[1], ts)).unwrap();
    }
    let kept = source.finish().unwrap().events;
    assert_eq!(kept.size(), one);
    assert_eq!(kept.into_events()[0].ts(), 10);
}

#[test]
fn copies_of_one_event_merge_to_the_earliest_and_different_payloads_fail() {
    let mut merged = MergedEvents::default();
    merged.merge(keyshare(&[1], 20)).unwrap();
    merged.merge(keyshare(&[1], 10)).unwrap();
    // The later copy's timestamp is free again.
    merged.merge(keyshare(&[2], 20)).unwrap();
    let conflicting = under_the_id_of(&[3], &keyshare(&[1], 30));
    assert!(merged.merge(conflicting).is_err());

    let times: Vec<_> = merged
        .into_events()
        .iter()
        .map(|event| event.ts())
        .collect();
    assert_eq!(times, vec![10, 20]);
}

/// A source that conflicts with the history adds none of its events.
#[test]
fn a_conflicting_source_leaves_the_history_unchanged() {
    let mut history = MergedEvents::default();
    history.merge(keyshare(&[1], 10)).unwrap();
    history.merge(keyshare(&[2], 20)).unwrap();
    let mut source = MergedEvents::default();
    source.merge(keyshare(&[3], 5)).unwrap();
    source.merge(keyshare(&[4], 20)).unwrap();

    assert!(history.extend(source.into()).is_err());

    let times: Vec<_> = history
        .into_events()
        .iter()
        .map(|event| event.ts())
        .collect();
    assert_eq!(times, vec![10, 20]);
}

/// The event store holds one event at a timestamp, so two events must not share one.
#[test]
fn different_events_at_one_timestamp_fail() {
    let mut merged = MergedEvents::default();
    merged.merge(keyshare(&[1], 10)).unwrap();
    assert!(merged.merge(keyshare(&[2], 10)).is_err());
}

/// A later source can bring an earlier copy of an event that the history holds. Its timestamp is
/// free again before a later event of the source takes it, whatever order the merge sees.
#[test]
fn a_source_replaces_a_later_copy_before_its_next_event_takes_that_time() {
    let mut history = MergedEvents::default();
    history.merge(keyshare(&[1], 10)).unwrap();
    let mut source = MergedEvents::default();
    source.merge(keyshare(&[1], 5)).unwrap();
    source.merge(keyshare(&[2], 10)).unwrap();

    history.extend(source.into()).unwrap();

    let times: Vec<_> = history
        .into_events()
        .iter()
        .map(|event| event.ts())
        .collect();
    assert_eq!(times, vec![5, 10]);
}

/// A source keeps only what the earlier sources lack, so the second source of a history fits in
/// the room that the first one left.
#[test]
fn a_source_keeps_only_events_that_the_history_lacks() {
    let range = range();
    let policy = NetworkPolicy::local_unrestricted();
    let mut held = MergedEvents::default();
    held.merge(keyshare(&[1], 10)).unwrap();
    let mut source = SourceHistory::new(&range, &held, &policy, HistorySize::default());

    source.add(keyshare(&[1], 11)).unwrap();
    assert!(source.add(keyshare(&[2], 12)).is_err());
}

/// Each peer stamps an event with the time that it reached the peer. A later source's earlier copy
/// of an event that the history holds moves the event to that time and costs no room.
#[test]
fn an_earlier_copy_of_a_held_event_moves_it_and_costs_no_room() {
    let range = range();
    let policy = NetworkPolicy::local_unrestricted();
    let mut history = MergedEvents::default();
    history.merge(keyshare(&[1], 20)).unwrap();
    history.merge(keyshare(&[2], 30)).unwrap();
    let mut source = SourceHistory::new(&range, &history, &policy, HistorySize::default());
    source.add(keyshare(&[1], 10)).unwrap();
    source.add(keyshare(&[1], 15)).unwrap();
    source.add(keyshare(&[2], 31)).unwrap();
    let additions = source.finish().unwrap();

    history.extend(additions).unwrap();

    assert_eq!(history.size().events, 2);
    let times: Vec<_> = history
        .into_events()
        .iter()
        .map(|event| event.ts())
        .collect();
    assert_eq!(times, vec![10, 30]);
}

/// An earlier time that would take another event's timestamp conflicts like an earlier copy does,
/// and changes nothing.
#[test]
fn an_earlier_time_at_another_events_timestamp_changes_nothing() {
    let range = range();
    let policy = NetworkPolicy::local_unrestricted();
    let mut history = MergedEvents::default();
    history.merge(keyshare(&[1], 10)).unwrap();
    history.merge(keyshare(&[2], 20)).unwrap();
    let mut source = SourceHistory::new(&range, &history, &policy, HistorySize::default());
    source.add(keyshare(&[2], 10)).unwrap();
    let additions = source.finish().unwrap();

    assert!(history.extend(additions).is_err());

    let times: Vec<_> = history
        .into_events()
        .iter()
        .map(|event| event.ts())
        .collect();
    assert_eq!(times, vec![10, 20]);
}
