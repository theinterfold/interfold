// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_events::{prelude::*, InterfoldEvent, Unsequenced};

use crate::domain::{
    event_translation::EventTranslationService,
    net_event_batch::{BatchCursor, EventBatch, FetchEventsSince},
};

/// Maximum number of forwardable events a remote peer may request in one sync response.
pub(crate) const MAX_SYNC_BATCH_SIZE: usize = 100;

/// A sync page may contain non-forwardable local events which are filtered after storage. Scan a
/// small, bounded multiple of the response size so those events cannot prematurely terminate sync,
/// while preventing a request from materializing the complete remaining history.
const SYNC_SCAN_MULTIPLIER: usize = 4;
pub(crate) const MAX_SYNC_SCAN_EVENTS: usize = MAX_SYNC_BATCH_SIZE * SYNC_SCAN_MULTIPLIER;

pub(crate) fn effective_sync_limit(requested: usize) -> usize {
    requested.min(MAX_SYNC_BATCH_SIZE)
}

pub(crate) fn sync_scan_limit(requested: usize) -> usize {
    (effective_sync_limit(requested) * SYNC_SCAN_MULTIPLIER).min(MAX_SYNC_SCAN_EVENTS)
}

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

    /// Whether a peer connection has been established at any point.
    ///
    /// `NetReady` is published by the connect-timeout fallback even when this is
    /// still false, so historical peer sync must consult it before it attempts
    /// fetches that cannot succeed.
    pub fn has_connections(&self) -> bool {
        self.has_connections
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
/// (`Net`) and locally-produced events that are themselves gossip-forwardable. The cursor is an
/// inclusive storage cursor, so it advances to one timestamp after the last returned or scanned
/// event. Both response work and storage scanning are capped independently of the peer's input.
pub fn build_sync_batch(
    all_events: Vec<InterfoldEvent>,
    fetch: &FetchEventsSince,
) -> SyncBatchOutcome {
    if fetch.limit() == 0 {
        return SyncBatchOutcome::BadRequest("limit must be greater than 0".to_string());
    }
    let limit = effective_sync_limit(fetch.limit());
    let scan_limit = sync_scan_limit(fetch.limit());
    let aggregate_id = fetch.aggregate_id();

    // A remote-origin event is not trusted merely because it was persisted after gossip. Apply
    // the same protocol allowlist to both local and relayed events so a peer cannot use historical
    // sync to amplify an internal control event that an older or malicious node accepted.
    let scan_was_full = all_events.len() >= scan_limit;
    let mut events = Vec::with_capacity(limit);
    let mut last_scanned_ts = None;
    for event in all_events.into_iter().take(scan_limit) {
        last_scanned_ts = Some(event.ts());
        if EventTranslationService::is_forwardable_event(&event) {
            events.push(event.clone_unsequenced());
            if events.len() == limit {
                break;
            }
        }
    }

    // Timestamp queries are inclusive. Advancing to exactly the last timestamp would repeat that
    // event and, for limit=1, loop forever. When a bounded scan contains only filtered events,
    // advance past the last scanned event so a later forwardable event remains reachable.
    let cursor_base = if events.len() == limit {
        events.last().map(|event| event.ts())
    } else if scan_was_full {
        last_scanned_ts
    } else {
        None
    };
    let next = cursor_base
        .and_then(|timestamp| timestamp.checked_add(1))
        .map(BatchCursor::Next)
        .unwrap_or(BatchCursor::Done);

    SyncBatchOutcome::Batch(EventBatch {
        events,
        next,
        aggregate_id,
    })
}

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
