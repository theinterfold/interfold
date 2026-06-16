// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_events::{EventLog, InterfoldEvent, Unsequenced};

pub struct InMemEventLog {
    log: Vec<InterfoldEvent<Unsequenced>>,
}

impl InMemEventLog {
    pub fn new() -> Self {
        Self { log: Vec::new() }
    }
}

impl Default for InMemEventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl EventLog for InMemEventLog {
    fn read_from(&self, from: u64) -> Box<dyn Iterator<Item = (u64, InterfoldEvent<Unsequenced>)>> {
        // Convert 1-indexed sequence to 0-indexed array position
        let start_idx = from.saturating_sub(1) as usize;

        let events: Vec<_> = self
            .log
            .iter()
            .skip(start_idx)
            .enumerate()
            .map(|(i, event)| (from + i as u64, event.clone()))
            .collect();
        Box::new(events.into_iter())
    }
    fn append(&mut self, event: &InterfoldEvent<Unsequenced>) -> Result<u64> {
        self.log.push(event.to_owned());
        Ok(self.log.len() as u64)
    }
    fn head(&self) -> u64 {
        self.log.len() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{EventConstructorWithTimestamp, EventSource, InterfoldEventData, TestEvent};

    fn event_from(data: impl Into<InterfoldEventData>) -> InterfoldEvent<Unsequenced> {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data.into(),
            None,
            123,
            None,
            EventSource::Local,
        )
    }

    #[test]
    fn test_append_and_read() {
        let mut log = InMemEventLog::new();

        let event1 = event_from(TestEvent::new("one", 1));
        let event2 = event_from(TestEvent::new("two", 2));

        let offset1 = log.append(&event1).unwrap();
        let offset2 = log.append(&event2).unwrap();

        assert_eq!(offset1, 1); // 1-indexed
        assert_eq!(offset2, 2);

        // Read back from the beginning
        let events: Vec<_> = log.read_from(1).collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, 1);
        assert_eq!(events[1].0, 2);
    }

    #[test]
    fn test_read_from_offset() {
        let mut log = InMemEventLog::new();

        let event1 = event_from(TestEvent::new("one", 1));
        let event2 = event_from(TestEvent::new("two", 2));
        let event3 = event_from(TestEvent::new("three", 3));

        log.append(&event1).unwrap();
        log.append(&event2).unwrap();
        log.append(&event3).unwrap();

        // Read from offset 2 (should get events 2 and 3)
        let events: Vec<_> = log.read_from(2).collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, 2);
        assert_eq!(events[1].0, 3);
    }

    #[test]
    fn test_read_empty_log() {
        let log = InMemEventLog::new();

        let events: Vec<_> = log.read_from(1).collect();
        assert!(events.is_empty());
    }

    #[test]
    fn test_read_past_end() {
        let mut log = InMemEventLog::new();

        let event = event_from(TestEvent::new("one", 1));
        log.append(&event).unwrap();

        // Read from offset beyond what exists
        let events: Vec<_> = log.read_from(100).collect();
        assert!(events.is_empty());
    }
}
