// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_events::{prelude::*, HistoryProgress, InterfoldEvent, Unsequenced};

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
    /// This node cannot serve the request; the peer receives an error.
    Failed(String),
    /// The batch to return to the requesting peer.
    Batch(EventBatch<InterfoldEvent<Unsequenced>>),
}

/// Encoded bytes of the events in one sync response. The rest of the 10 MiB direct-message limit
/// holds the batch and envelope fields.
pub(crate) const MAX_SYNC_RESPONSE_EVENT_BYTES: usize =
    crate::domain::wire::MAX_DIRECT_MESSAGE_BYTES - 4 * 1024;

/// Build a sync response batch from one timestamp-ordered storage page.
///
/// Only includes events that are safe to forward over the network: events received via gossip
/// (`Net`) and locally-produced events that are themselves gossip-forwardable. Storage reads in
/// timestamp order and reports how far it scanned, so the cursor moves one timestamp past the last
/// record that this response consumed: returned, filtered, or skipped by storage. The response
/// stops at the forwardable-event limit or at the encoded-size limit, and the cursor then names the
/// first record it did not consume. `Done` means that storage holds nothing after the consumed
/// records. Both response work and storage scanning are capped independently of the peer's input.
pub fn build_sync_batch(
    page: Vec<InterfoldEvent>,
    progress: HistoryProgress,
    fetch: &FetchEventsSince,
) -> SyncBatchOutcome {
    if fetch.limit() == 0 {
        return SyncBatchOutcome::BadRequest("limit must be greater than 0".to_string());
    }
    let limit = effective_sync_limit(fetch.limit());
    let aggregate_id = fetch.aggregate_id();

    // A remote-origin event is not trusted merely because it was persisted after gossip. Apply
    // the same protocol allowlist to both local and relayed events so a peer cannot use historical
    // sync to amplify an internal control event that an older or malicious node accepted.
    let total = page.len();
    let mut events = Vec::with_capacity(limit.min(total));
    let mut event_bytes = 0usize;
    let mut consumed = 0usize;
    let mut consumed_ts = None;
    for event in page {
        if EventTranslationService::is_forwardable_event(&event) {
            let event = event.clone_unsequenced();
            let size = bincode::serialized_size(&event)
                .ok()
                .and_then(|size| usize::try_from(size).ok())
                .unwrap_or(usize::MAX);
            if event_bytes.saturating_add(size) > MAX_SYNC_RESPONSE_EVENT_BYTES {
                if events.is_empty() {
                    return SyncBatchOutcome::Failed(format!(
                        "historical event at timestamp {} exceeds the sync message limit",
                        event.ts()
                    ));
                }
                break;
            }
            event_bytes = event_bytes.saturating_add(size);
            consumed += 1;
            consumed_ts = Some(event.ts());
            events.push(event);
            if events.len() == limit {
                break;
            }
        } else {
            consumed += 1;
            consumed_ts = Some(event.ts());
        }
    }

    // A reply that consumed the whole page ends where storage stopped: storage can have skipped
    // records that the reply never saw, such as quarantined ones.
    let next = if consumed == total {
        if progress.exhausted {
            BatchCursor::Done
        } else {
            match consumed_ts.max(progress.last_scanned_ts) {
                Some(timestamp) => match timestamp.checked_add(1) {
                    Some(next) => BatchCursor::Next(next),
                    None => {
                        return SyncBatchOutcome::Failed(
                            "historical-sync cursor overflowed".to_string(),
                        )
                    }
                },
                None => {
                    return SyncBatchOutcome::Failed(
                        "historical-sync storage page made no progress".to_string(),
                    )
                }
            }
        }
    } else {
        // The reply stopped at its limit before the end of the page. The next request starts at
        // the first record that it did not consume.
        match consumed_ts.and_then(|timestamp| timestamp.checked_add(1)) {
            Some(next) => BatchCursor::Next(next),
            None => {
                return SyncBatchOutcome::Failed("historical-sync cursor overflowed".to_string())
            }
        }
    };

    SyncBatchOutcome::Batch(EventBatch {
        events,
        next,
        aggregate_id,
    })
}

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
