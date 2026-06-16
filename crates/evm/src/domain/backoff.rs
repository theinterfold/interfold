// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure exponential-backoff helper used by the EVM read interface reconnect loop.

use std::time::Duration;

pub(crate) struct Backoff {
    delay_secs: u64,
    max_delay_secs: u64,
}

impl Backoff {
    pub(crate) fn new(max_delay_secs: u64) -> Self {
        Self {
            delay_secs: 1,
            max_delay_secs,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.delay_secs = 1;
    }

    pub(crate) fn next_delay(&mut self) -> Duration {
        let delay = Duration::from_secs(self.delay_secs);
        self.delay_secs = (self.delay_secs * 2).min(self.max_delay_secs);
        delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doubles_until_capped() {
        let mut b = Backoff::new(8);
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(2));
        assert_eq!(b.next_delay(), Duration::from_secs(4));
        assert_eq!(b.next_delay(), Duration::from_secs(8));
        // Capped at max_delay_secs
        assert_eq!(b.next_delay(), Duration::from_secs(8));
    }

    #[test]
    fn test_reset_returns_to_one_second() {
        let mut b = Backoff::new(60);
        b.next_delay();
        b.next_delay();
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }
}
