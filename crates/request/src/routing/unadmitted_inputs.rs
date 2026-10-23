// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Peer events that arrive before the chain admits their E3.
//!
//! A peer event can only contribute to a request that the node admitted from chain state. When the
//! node's chain reader lags, peers' first DKG messages for a new E3 can arrive before the node sees
//! the request. The router holds them here, in memory, and delivers them when the chain event that
//! creates the E3's context arrives. Startup does not need this: the network event buffer holds
//! gossip until the historical chain events are applied.

use std::collections::VecDeque;

use e3_events::{E3id, Event, InterfoldEvent};

use super::event_buffer::event_bytes;

/// Bounds for the held peer events.
///
/// A DKG of 19 parties sends about 160 such events before the last party starts (six readiness
/// updates, one key share and one fold proof from each party). A decryption sends 19 shares of
/// about 0.2 MB each. The totals match the network event buffer that holds gossip during startup.
#[derive(Clone, Copy)]
pub(crate) struct UnadmittedLimits {
    pub per_e3_items: usize,
    pub per_e3_bytes: usize,
    pub total_items: usize,
    pub total_bytes: usize,
}

impl Default for UnadmittedLimits {
    fn default() -> Self {
        Self {
            per_e3_items: 512,
            per_e3_bytes: 128 * 1024 * 1024,
            total_items: 1_024,
            total_bytes: 256 * 1024 * 1024,
        }
    }
}

struct Held {
    e3_id: E3id,
    event: InterfoldEvent,
    bytes: usize,
}

/// Peer events of E3s without a context, in arrival order. When a bound is full, the oldest held
/// event goes first: the oldest of the same E3 for the per-E3 bound, the oldest of all for the
/// total.
pub struct UnadmittedInputs {
    held: VecDeque<Held>,
    bytes: usize,
    limits: UnadmittedLimits,
}

impl Default for UnadmittedInputs {
    fn default() -> Self {
        Self::with_limits(UnadmittedLimits::default())
    }
}

impl UnadmittedInputs {
    pub(crate) fn with_limits(limits: UnadmittedLimits) -> Self {
        Self {
            held: VecDeque::new(),
            bytes: 0,
            limits,
        }
    }

    /// Hold a peer event until the chain admits its E3.
    pub fn hold(&mut self, e3_id: E3id, mut event: InterfoldEvent) {
        let Some(bytes) = event_bytes(&event).filter(|bytes| *bytes <= self.limits.per_e3_bytes)
        else {
            tracing::warn!(
                %e3_id,
                event_type = %event.event_type(),
                "Dropped a peer event for an E3 that the chain has not admitted: it is larger \
                 than the hold budget"
            );
            return;
        };

        let mut evicted = 0;
        while self.e3_usage(&e3_id).is_some_and(|(items, held_bytes)| {
            items >= self.limits.per_e3_items || held_bytes + bytes > self.limits.per_e3_bytes
        }) {
            let index = self
                .held
                .iter()
                .position(|held| held.e3_id == e3_id)
                .expect("a nonempty E3 usage has a held event");
            self.remove_at(index);
            evicted += 1;
        }
        while !self.held.is_empty()
            && (self.held.len() >= self.limits.total_items
                || self.bytes + bytes > self.limits.total_bytes)
        {
            self.remove_at(0);
            evicted += 1;
        }
        if evicted > 0 {
            tracing::warn!(
                %e3_id,
                evicted,
                "Dropped the oldest held peer events of E3s that the chain has not admitted"
            );
        }

        event.compact_shared_collections();
        self.bytes += bytes;
        self.held.push_back(Held {
            e3_id,
            event,
            bytes,
        });
    }

    /// Take the held events of an E3, in arrival order.
    pub fn take(&mut self, e3_id: &E3id) -> Vec<InterfoldEvent> {
        let mut taken = Vec::new();
        let mut kept = VecDeque::with_capacity(self.held.len());
        for held in self.held.drain(..) {
            if &held.e3_id == e3_id {
                self.bytes -= held.bytes;
                taken.push(held.event);
            } else {
                kept.push_back(held);
            }
        }
        self.held = kept;
        taken
    }

    /// Drop the held events of an E3 that ended.
    pub fn remove_e3(&mut self, e3_id: &E3id) {
        self.take(e3_id);
    }

    fn e3_usage(&self, e3_id: &E3id) -> Option<(usize, usize)> {
        let (items, bytes) = self
            .held
            .iter()
            .filter(|held| &held.e3_id == e3_id)
            .fold((0, 0), |(items, bytes), held| {
                (items + 1, bytes + held.bytes)
            });
        (items > 0).then_some((items, bytes))
    }

    fn remove_at(&mut self, index: usize) {
        if let Some(held) = self.held.remove(index) {
            self.bytes -= held.bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{prelude::*, Sequenced};

    fn event(e3_id: &E3id, seq: u64) -> InterfoldEvent {
        InterfoldEvent::<Sequenced>::test_event("peer")
            .e3_id(e3_id.clone())
            .seq(seq)
            .build()
    }

    fn seqs(events: Vec<InterfoldEvent>) -> Vec<u64> {
        events.iter().map(|event| event.seq()).collect()
    }

    #[test]
    fn held_events_are_taken_per_e3_in_arrival_order() {
        let (first, second) = (E3id::new("1", 1), E3id::new("2", 1));
        let mut inputs = UnadmittedInputs::default();
        inputs.hold(first.clone(), event(&first, 1));
        inputs.hold(second.clone(), event(&second, 2));
        inputs.hold(first.clone(), event(&first, 3));

        assert_eq!(seqs(inputs.take(&first)), vec![1, 3]);
        assert!(inputs.take(&first).is_empty());
        assert_eq!(seqs(inputs.take(&second)), vec![2]);
        assert_eq!(inputs.bytes, 0);
    }

    #[test]
    fn a_full_bound_drops_the_oldest_held_event() {
        let (first, second) = (E3id::new("1", 1), E3id::new("2", 1));
        let mut inputs = UnadmittedInputs::with_limits(UnadmittedLimits {
            per_e3_items: 2,
            per_e3_bytes: usize::MAX,
            total_items: 3,
            total_bytes: usize::MAX,
        });
        inputs.hold(first.clone(), event(&first, 1));
        inputs.hold(first.clone(), event(&first, 2));
        // The per-E3 bound drops the oldest event of the same E3.
        inputs.hold(first.clone(), event(&first, 3));
        inputs.hold(second.clone(), event(&second, 4));
        // The total bound drops the oldest event of all.
        inputs.hold(second.clone(), event(&second, 5));

        assert_eq!(seqs(inputs.take(&first)), vec![3]);
        assert_eq!(seqs(inputs.take(&second)), vec![4, 5]);
    }

    #[test]
    fn the_byte_bounds_drop_the_oldest_held_event_and_teardown_releases_bytes() {
        let (first, second) = (E3id::new("1", 1), E3id::new("2", 1));
        let size = event_bytes(&event(&first, 1)).unwrap();
        let mut inputs = UnadmittedInputs::with_limits(UnadmittedLimits {
            per_e3_items: usize::MAX,
            per_e3_bytes: 2 * size,
            total_items: usize::MAX,
            total_bytes: 3 * size,
        });
        inputs.hold(first.clone(), event(&first, 1));
        inputs.hold(first.clone(), event(&first, 2));
        // The per-E3 byte bound drops the oldest event of the same E3.
        inputs.hold(first.clone(), event(&first, 3));
        inputs.hold(second.clone(), event(&second, 4));
        // The total byte bound drops the oldest event of all.
        inputs.hold(second.clone(), event(&second, 5));
        assert_eq!(inputs.bytes, 3 * size);

        // Teardown of one E3 releases its bytes and keeps the other E3's events.
        inputs.remove_e3(&second);
        assert_eq!(inputs.bytes, size);
        assert_eq!(seqs(inputs.take(&first)), vec![3]);
        assert_eq!(inputs.bytes, 0);
    }

    #[test]
    fn an_event_larger_than_the_budget_is_not_held() {
        let e3_id = E3id::new("1", 1);
        let mut inputs = UnadmittedInputs::with_limits(UnadmittedLimits {
            per_e3_items: 4,
            per_e3_bytes: 1,
            total_items: 4,
            total_bytes: 1,
        });
        inputs.hold(e3_id.clone(), event(&e3_id, 1));

        assert!(inputs.take(&e3_id).is_empty());
    }
}
