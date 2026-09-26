// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Exponential delays for repeated network announcements and retries.

use std::time::Duration;

/// Returns `base * 2^(attempt - 1)` capped at `cap`, plus up to 10 % random jitter so that nodes
/// do not repeat in step. `attempt` counts from 1.
pub(crate) fn backoff_delay(base: Duration, attempt: u32, cap: Duration) -> Duration {
    let exponent = attempt.saturating_sub(1).min(20);
    let delay = base.saturating_mul(1u32 << exponent).min(cap);
    delay + delay.mul_f64(rand::random::<f64>() * 0.1)
}

#[cfg(test)]
mod tests {
    use super::backoff_delay;
    use std::time::Duration;

    fn assert_within(delay: Duration, expected: Duration) {
        assert!(
            delay >= expected && delay <= expected.mul_f64(1.1),
            "{delay:?} is outside {expected:?}..=110%"
        );
    }

    #[test]
    fn doubles_from_the_base_and_stops_at_the_cap() {
        let base = Duration::from_secs(30);
        let cap = Duration::from_secs(300);
        assert_within(backoff_delay(base, 0, cap), base);
        assert_within(backoff_delay(base, 1, cap), base);
        assert_within(backoff_delay(base, 2, cap), Duration::from_secs(60));
        assert_within(backoff_delay(base, 4, cap), Duration::from_secs(240));
        assert_within(backoff_delay(base, 5, cap), cap);
        assert_within(backoff_delay(base, u32::MAX, cap), cap);
    }
}
