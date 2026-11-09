// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

/// Lets a message that can repeat through at most once per interval, so a flood of one event
/// writes one line and a count.
#[derive(Debug)]
pub struct Limited {
    every: Duration,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    last: Option<Instant>,
    held_back: u64,
}

impl Limited {
    pub fn new(every: Duration) -> Self {
        Self {
            every,
            state: Mutex::default(),
        }
    }

    /// When the message may go out now, how many were held back since the last one.
    pub fn pass(&self) -> Option<u64> {
        let mut state = self.state.lock().expect("no holder of the lock panics");
        let now = Instant::now();
        if state.last.is_some_and(|last| now < last + self.every) {
            state.held_back += 1;
            return None;
        }
        state.last = Some(now);
        Some(std::mem::take(&mut state.held_back))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeat_inside_the_interval_is_held_back_and_counted() {
        let limited = Limited::new(Duration::from_millis(40));
        assert_eq!(limited.pass(), Some(0));
        assert_eq!(limited.pass(), None);
        assert_eq!(limited.pass(), None);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(limited.pass(), Some(2));
    }
}
