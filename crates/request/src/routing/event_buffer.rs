// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_events::{E3id, InterfoldEvent};
use std::collections::{HashMap, HashSet};

#[path = "event_size.rs"]
mod event_size;
pub(crate) use event_size::event_bytes;

// Sized for N=19, H=14 and four concurrent E3s. See the capacity derivation in
// agent/flow-trace/03_E3_REQUEST_AND_COMMITTEE.md.
#[derive(Clone, Copy)]
pub(crate) struct EventBufferLimits {
    pub per_e3_items: usize,
    pub per_e3_bytes: usize,
    pub global_items: usize,
    pub global_bytes: usize,
}

impl Default for EventBufferLimits {
    fn default() -> Self {
        Self {
            per_e3_items: 4_096,
            per_e3_bytes: 1024 * 1024 * 1024,
            global_items: 16_384,
            global_bytes: 3 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Default)]
struct BufferedEvents {
    events: Vec<InterfoldEvent>,
    bytes: usize,
}

#[derive(Clone, Copy, Default)]
struct Usage {
    items: usize,
    bytes: usize,
}

impl Usage {
    fn fits(&self, bytes: usize, max_items: usize, max_bytes: usize) -> bool {
        self.items < max_items && bytes <= max_bytes.saturating_sub(self.bytes)
    }

    fn release(&mut self, items: usize, bytes: usize) {
        self.items -= items;
        self.bytes -= bytes;
    }
}

/// Defers events for missing recipients, within per-E3 and shared memory budgets.
/// Overflow disables deferral for that recipient until E3 teardown or restart.
pub struct EventBuffer {
    buffer: HashMap<(E3id, String), BufferedEvents>,
    failed: HashSet<(E3id, String)>,
    per_e3: HashMap<E3id, Usage>,
    total: Usage,
    limits: EventBufferLimits,
}

impl Default for EventBuffer {
    fn default() -> Self {
        Self::with_limits(EventBufferLimits::default())
    }
}

impl EventBuffer {
    pub(crate) fn with_limits(limits: EventBufferLimits) -> Self {
        Self {
            buffer: HashMap::new(),
            failed: HashSet::new(),
            per_e3: HashMap::new(),
            total: Usage::default(),
            limits,
        }
    }

    pub fn add(&mut self, e3_id: &E3id, recipient: &str, mut event: InterfoldEvent) {
        let key = (e3_id.clone(), recipient.to_owned());
        if self.failed.contains(&key) {
            return;
        }

        // Charge shared allocations again for each recipient. No serialized copy is allocated.
        let bytes = event_bytes(&event);
        let usage = self.per_e3.get(e3_id).copied().unwrap_or_default();
        if !bytes.is_some_and(|bytes| {
            usage.fits(bytes, self.limits.per_e3_items, self.limits.per_e3_bytes)
                && self
                    .total
                    .fits(bytes, self.limits.global_items, self.limits.global_bytes)
        }) {
            tracing::error!(
                %e3_id,
                recipient,
                event_bytes = ?bytes,
                e3_items = usage.items,
                e3_bytes = usage.bytes,
                global_items = self.total.items,
                global_bytes = self.total.bytes,
                "Deferred delivery failed: request buffer limit exceeded; dropping the recipient backlog"
            );
            self.take(e3_id, recipient);
            self.failed.insert(key);
            return;
        }

        let bytes = bytes.expect("buffer admission checked the event size");
        event.compact_shared_collections();
        let pending = self.buffer.entry(key).or_default();
        pending.events.push(event);
        pending.bytes += bytes;
        let usage = self.per_e3.entry(e3_id.clone()).or_default();
        usage.items += 1;
        usage.bytes += bytes;
        self.total.items += 1;
        self.total.bytes += bytes;
    }

    pub fn take(&mut self, e3_id: &E3id, recipient: &str) -> Vec<InterfoldEvent> {
        let Some(pending) = self.buffer.remove(&(e3_id.clone(), recipient.to_owned())) else {
            return Vec::new();
        };
        self.total.release(pending.events.len(), pending.bytes);
        if let Some(usage) = self.per_e3.get_mut(e3_id) {
            usage.release(pending.events.len(), pending.bytes);
            if usage.items == 0 {
                self.per_e3.remove(e3_id);
            }
        }
        pending.events
    }

    /// Release the terminal request's reservations and deferred-delivery failure records.
    pub fn remove_e3(&mut self, e3_id: &E3id) {
        self.buffer.retain(|(id, _), _| id != e3_id);
        self.failed.retain(|(id, _)| id != e3_id);
        if let Some(usage) = self.per_e3.remove(e3_id) {
            self.total.release(usage.items, usage.bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{E3id, InterfoldEvent, Sequenced};

    fn event(label: &str) -> InterfoldEvent {
        InterfoldEvent::<Sequenced>::test_event(label)
            .e3_id(E3id::new("1", 1))
            .seq(1)
            .build()
    }

    #[test]
    fn take_returns_empty_for_unknown_key() {
        let mut buffer = EventBuffer::default();
        assert!(buffer.take(&E3id::new("1", 1), "missing").is_empty());
    }

    #[test]
    fn add_then_take_drains_buffer() {
        let mut buffer = EventBuffer::default();
        let e3_id = E3id::new("1", 1);
        buffer.add(&e3_id, "k", event("a"));
        buffer.add(&e3_id, "k", event("b"));

        let drained = buffer.take(&e3_id, "k");
        assert_eq!(drained.len(), 2);
        // A second take should yield nothing since the buffer was drained.
        assert!(buffer.take(&e3_id, "k").is_empty());
    }

    #[test]
    fn keys_are_isolated() {
        let mut buffer = EventBuffer::default();
        let e3_id = E3id::new("1", 1);
        buffer.add(&e3_id, "a", event("x"));
        buffer.add(&e3_id, "b", event("y"));

        assert_eq!(buffer.take(&e3_id, "a").len(), 1);
        assert_eq!(buffer.take(&e3_id, "b").len(), 1);
    }

    #[test]
    fn terminal_cleanup_removes_only_the_completed_e3() {
        let mut buffer = EventBuffer::default();
        let completed = E3id::new("1", 1);
        let active = E3id::new("2", 1);
        buffer.add(&completed, "missing-a", event("old-a"));
        buffer.add(&completed, "missing-b", event("old-b"));
        buffer.add(&active, "missing-a", event("active"));

        buffer.remove_e3(&completed);

        assert!(buffer.take(&completed, "missing-a").is_empty());
        assert!(buffer.take(&completed, "missing-b").is_empty());
        assert_eq!(buffer.take(&active, "missing-a").len(), 1);
    }
}
