// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure reordering service that holds a `HistoricalSyncComplete` marker back
//! until the event it references has been observed.

use crate::messages::{HistoricalSyncComplete, InterfoldEvmEvent};
use bloom::{BloomFilter, ASMS};
use e3_events::CorrelationId;
use tracing::debug;

/// Buffers a `HistoricalSyncComplete` that references a not-yet-seen event and
/// releases it once that event flows through. All other events are forwarded
/// immediately while their ids are tracked in a bloom filter.
pub(crate) struct HistoricalOrderFixer {
    pending_sync_complete: Option<InterfoldEvmEvent>,
    seen_ids: BloomFilter,
}

impl HistoricalOrderFixer {
    pub(crate) fn new() -> Self {
        Self {
            pending_sync_complete: None,
            seen_ids: BloomFilter::with_rate(0.001, 10_000_000),
        }
    }

    /// Process a single incoming event, returning the (possibly empty) ordered
    /// list of events that should be forwarded downstream as a result.
    pub(crate) fn process(&mut self, msg: InterfoldEvmEvent) -> Vec<InterfoldEvmEvent> {
        let id = msg.get_id();
        debug!("Receiving InterfoldEvmEvent event({})", id);
        let mut out = Vec::new();
        match msg {
            none_hist @ InterfoldEvmEvent::HistoricalSyncComplete(HistoricalSyncComplete {
                prev_event: None,
                ..
            }) => {
                debug!(
                    "Historical order event({}) has no previous event. Forwarding...",
                    id
                );
                out.push(none_hist);
            }
            hist @ InterfoldEvmEvent::HistoricalSyncComplete(HistoricalSyncComplete {
                prev_event: Some(_),
                ..
            }) => {
                debug!(
                    "Historical order event({}) has a previous event. Buffering...",
                    id
                );
                self.pending_sync_complete = Some(hist);
            }
            InterfoldEvmEvent::Processed(id) => self.track_id(id),
            other => {
                debug!("Forwarding event({})", other.get_id());
                self.track_id(other.get_id());
                out.push(other);
            }
        }
        if let Some(pending) = self.take_ready_pending() {
            out.push(pending);
        }
        out
    }

    fn take_ready_pending(&mut self) -> Option<InterfoldEvmEvent> {
        if let Some(InterfoldEvmEvent::HistoricalSyncComplete(HistoricalSyncComplete {
            prev_event: Some(ref id),
            ..
        })) = self.pending_sync_complete
        {
            if self.seen_ids.contains(id) {
                debug!("Forwarding historical send complete event");
                return self.pending_sync_complete.take();
            }
        }
        None
    }

    fn track_id(&mut self, id: CorrelationId) {
        self.seen_ids.insert(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::EvmLog;
    use alloy_primitives::Address;

    #[test]
    fn test_forwards_sync_complete_without_prev_event_immediately() {
        let mut fixer = HistoricalOrderFixer::new();
        let sync = InterfoldEvmEvent::HistoricalSyncComplete(HistoricalSyncComplete::new(1, None));
        let out = fixer.process(sync.clone());
        assert_eq!(out, vec![sync]);
    }

    #[test]
    fn test_holds_sync_complete_until_referenced_event_seen() {
        let mut fixer = HistoricalOrderFixer::new();

        let log_1 = InterfoldEvmEvent::Log(EvmLog::test_log(Address::ZERO, 1, 1));
        let log_2 = InterfoldEvmEvent::Log(EvmLog::test_log(Address::ZERO, 2, 2));
        let log_3 = InterfoldEvmEvent::Log(EvmLog::test_log(Address::ZERO, 3, 3));

        let sync = InterfoldEvmEvent::HistoricalSyncComplete(HistoricalSyncComplete::new(
            1,
            Some(log_3.get_id()),
        ));

        // log_1 forwarded immediately
        assert_eq!(fixer.process(log_1.clone()), vec![log_1]);
        // sync references log_3 (not yet seen) -> buffered, nothing emitted
        assert!(fixer.process(sync.clone()).is_empty());
        // log_2 forwarded immediately, still no release
        assert_eq!(fixer.process(log_2.clone()), vec![log_2]);
        // log_3 forwarded AND the buffered sync released right after it
        assert_eq!(fixer.process(log_3.clone()), vec![log_3, sync]);
    }

    #[test]
    fn test_processed_events_track_ids_without_forwarding() {
        let mut fixer = HistoricalOrderFixer::new();
        let log = InterfoldEvmEvent::Log(EvmLog::test_log(Address::ZERO, 9, 9));
        let id = log.get_id();

        let sync =
            InterfoldEvmEvent::HistoricalSyncComplete(HistoricalSyncComplete::new(1, Some(id)));
        // Buffer the sync first
        assert!(fixer.process(sync.clone()).is_empty());
        // A Processed marker for the referenced id releases the sync but is not forwarded
        assert_eq!(fixer.process(InterfoldEvmEvent::Processed(id)), vec![sync]);
    }
}
