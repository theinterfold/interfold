// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_events::InterfoldEvent;
use std::collections::HashMap;

/// Buffers events for downstream instances to handle out-of-order event delivery.
/// Events are stored in a HashMap keyed by string identifiers until they are ready
/// to be processed.
#[derive(Default)]
pub struct EventBuffer {
    buffer: HashMap<String, Vec<InterfoldEvent>>,
}

impl EventBuffer {
    pub fn add(&mut self, key: &str, event: InterfoldEvent) {
        self.buffer.entry(key.to_string()).or_default().push(event)
    }

    pub fn take(&mut self, key: &str) -> Vec<InterfoldEvent> {
        self.buffer
            .get_mut(key)
            .map(std::mem::take)
            .unwrap_or_default()
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
        assert!(buffer.take("missing").is_empty());
    }

    #[test]
    fn add_then_take_drains_buffer() {
        let mut buffer = EventBuffer::default();
        buffer.add("k", event("a"));
        buffer.add("k", event("b"));

        let drained = buffer.take("k");
        assert_eq!(drained.len(), 2);
        // A second take should yield nothing since the buffer was drained.
        assert!(buffer.take("k").is_empty());
    }

    #[test]
    fn keys_are_isolated() {
        let mut buffer = EventBuffer::default();
        buffer.add("a", event("x"));
        buffer.add("b", event("y"));

        assert_eq!(buffer.take("a").len(), 1);
        assert_eq!(buffer.take("b").len(), 1);
    }
}
