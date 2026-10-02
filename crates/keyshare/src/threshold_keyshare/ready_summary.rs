// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Rate limit for the INFO summary of the authenticated DKG Ready set.

use std::time::{Duration, Instant};

/// Shortest time between two Ready-set summaries of one E3.
pub(crate) const READY_SUMMARY_INTERVAL: Duration = Duration::from_secs(30);

/// Decides which changes of the authenticated Ready set get an INFO summary. The first change and
/// the first change that gives enough Ready parties for a roster always get one. Other changes get
/// one at most once per `READY_SUMMARY_INTERVAL`, and that summary counts the changes left out.
#[derive(Debug, Default)]
pub(crate) struct ReadySummaryGate {
    last_summary: Option<Instant>,
    threshold_reached: bool,
    suppressed: usize,
}

impl ReadySummaryGate {
    /// Records one change of the Ready set. Returns the number of earlier changes without a summary
    /// when this change gets one, and `None` when it does not.
    pub(crate) fn admit(&mut self, now: Instant, threshold_reached: bool) -> Option<usize> {
        let first_threshold = threshold_reached && !self.threshold_reached;
        self.threshold_reached |= threshold_reached;
        let interval_passed = self
            .last_summary
            .is_none_or(|last| now.saturating_duration_since(last) >= READY_SUMMARY_INTERVAL);
        if !first_threshold && !interval_passed {
            self.suppressed += 1;
            return None;
        }
        self.last_summary = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_inside_the_interval_are_counted_in_the_next_summary() {
        let start = Instant::now();
        let mut gate = ReadySummaryGate::default();

        assert_eq!(gate.admit(start, false), Some(0));
        assert_eq!(gate.admit(start + Duration::from_secs(1), false), None);
        assert_eq!(gate.admit(start + Duration::from_secs(2), false), None);
        assert_eq!(gate.admit(start + READY_SUMMARY_INTERVAL, false), Some(2));
        assert_eq!(
            gate.admit(
                start + READY_SUMMARY_INTERVAL + Duration::from_secs(1),
                false
            ),
            None
        );
    }

    #[test]
    fn reaching_the_threshold_gets_one_summary_inside_the_interval() {
        let start = Instant::now();
        let mut gate = ReadySummaryGate::default();
        gate.admit(start, false);
        gate.admit(start + Duration::from_secs(1), false);

        assert_eq!(gate.admit(start + Duration::from_secs(2), true), Some(1));
        assert_eq!(gate.admit(start + Duration::from_secs(3), true), None);
    }
}
