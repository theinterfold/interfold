// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_events::{prelude::*, EventSource, InterfoldEvent, Unsequenced};

use crate::domain::{
    event_translation::EventTranslationService,
    net_event_batch::{BatchCursor, EventBatch, FetchEventsSince},
};

/// What the owning actor should do after a readiness signal.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadinessDecision {
    /// Nothing to do.
    Idle,
    /// Publish `NetReady` now.
    PublishReady,
    /// All dials failed; wait for a connection and schedule the fallback timeout.
    WaitForConnection,
}

/// Pure state machine deciding when the node is "network ready".
///
/// `NetReady` is published exactly once, when either all configured peers have been dialed and at
/// least one connection exists (or there are no peers), or — as a fallback — when a connection is
/// established / the wait times out. Holds no actix/bus state.
#[derive(Default)]
pub struct NetReadiness {
    all_peers_dialed: bool,
    has_connections: bool,
    net_ready_published: bool,
}

impl NetReadiness {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the `AllPeersDialed` signal has been observed yet.
    pub fn all_peers_dialed(&self) -> bool {
        self.all_peers_dialed
    }

    fn try_publish(&mut self) -> ReadinessDecision {
        if !self.net_ready_published {
            self.net_ready_published = true;
            ReadinessDecision::PublishReady
        } else {
            ReadinessDecision::Idle
        }
    }

    /// All configured peers have been dialed (`connected` of `total` succeeded).
    pub fn on_all_peers_dialed(&mut self, connected: usize, total: usize) -> ReadinessDecision {
        self.all_peers_dialed = true;
        if connected > 0 {
            self.has_connections = true;
        }
        if total == 0 || self.has_connections {
            self.try_publish()
        } else {
            ReadinessDecision::WaitForConnection
        }
    }

    /// A peer connection was established.
    pub fn on_peer_connected(&mut self) -> ReadinessDecision {
        if !self.has_connections {
            self.has_connections = true;
            if self.all_peers_dialed {
                return self.try_publish();
            }
        }
        ReadinessDecision::Idle
    }

    /// The fallback wait timer elapsed without a connection.
    pub fn on_connect_timeout(&mut self) -> ReadinessDecision {
        self.try_publish()
    }
}

/// Outcome of building a response to an incoming historical-sync request.
pub enum SyncBatchOutcome {
    /// The request was malformed and should be rejected.
    BadRequest(String),
    /// The batch to return to the requesting peer.
    Batch(EventBatch<InterfoldEvent<Unsequenced>>),
}

/// Build a sync response batch from the events returned by the event store.
///
/// Only includes events that are safe to forward over the network: events received via gossip
/// (`Net`) and locally-produced events that are themselves gossip-forwardable. The cursor advances
/// to the timestamp of the last returned event when the limit is reached.
pub fn build_sync_batch(
    all_events: Vec<InterfoldEvent>,
    fetch: &FetchEventsSince,
) -> SyncBatchOutcome {
    let limit = fetch.limit();
    if limit == 0 {
        return SyncBatchOutcome::BadRequest("limit must be greater than 0".to_string());
    }
    let aggregate_id = fetch.aggregate_id();

    // Include Net events (received via gossip) and Local events that are gossip-forwardable.
    // Without the Local check, a node's own gossip events would be excluded from sync responses,
    // causing syncing peers to miss them.
    let events: Vec<InterfoldEvent<Unsequenced>> = all_events
        .into_iter()
        .filter(|e| {
            e.source() == EventSource::Net
                || (e.source() == EventSource::Local
                    && EventTranslationService::is_forwardable_event(e))
        })
        .take(limit)
        .map(|ev| ev.clone_unsequenced())
        .collect();

    let next = if events.len() == limit {
        let last_event_ts = events.last().map(|e| e.ts()).unwrap_or(0);
        BatchCursor::Next(last_event_ts)
    } else {
        BatchCursor::Done
    };

    SyncBatchOutcome::Batch(EventBatch {
        events,
        next,
        aggregate_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{AggregateId, EventConstructorWithTimestamp, TestEvent};

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
            TestEvent::new("x", ts as u64).into(),
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
        let outcome = build_sync_batch(vec![net_event(5), local_event(6)], &fetch);
        let SyncBatchOutcome::Batch(batch) = outcome else {
            panic!("expected batch");
        };
        // Only the Net event survives; the Local TestEvent is not forwardable.
        assert_eq!(batch.events.len(), 1);
        assert!(matches!(batch.next, BatchCursor::Done));
    }

    #[test]
    fn build_sync_batch_advances_cursor_when_limit_reached() {
        let fetch = FetchEventsSince::new(AggregateId::new(1), 0, 1);
        let outcome = build_sync_batch(vec![net_event(5), net_event(9)], &fetch);
        let SyncBatchOutcome::Batch(batch) = outcome else {
            panic!("expected batch");
        };
        assert_eq!(batch.events.len(), 1);
        assert!(matches!(batch.next, BatchCursor::Next(5)));
    }
}
