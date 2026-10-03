// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Rate limit for the INFO summary of the authenticated DKG Ready set.

use std::time::{Duration, Instant};

/// Shortest time between two Ready-set summaries of one E3.
pub(crate) const READY_SUMMARY_INTERVAL: Duration = Duration::from_secs(30);

/// Decides which changes of the authenticated Ready set get an INFO summary. A change that adds a
/// Ready party always gets one, so the last summary lists every Ready party and shows when enough
/// parties are Ready for a roster; that is at most one line per committee member. A change that
/// only extends the dealer list of a party that is already Ready gets one at most once per
/// `READY_SUMMARY_INTERVAL`, and the next summary counts the changes left out.
#[derive(Debug, Default)]
pub(crate) struct ReadySummaryGate {
    last_summary: Option<Instant>,
    suppressed: usize,
}

impl ReadySummaryGate {
    /// Records one change of the Ready set: `new_party` when it adds a Ready party. Returns the
    /// number of earlier changes without a summary when this change gets one, and `None` when it
    /// does not.
    pub(crate) fn admit(&mut self, now: Instant, new_party: bool) -> Option<usize> {
        let interval_passed = self
            .last_summary
            .is_none_or(|last| now.saturating_duration_since(last) >= READY_SUMMARY_INTERVAL);
        if !new_party && !interval_passed {
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
    fn every_new_ready_party_gets_a_summary() {
        let start = Instant::now();
        let mut gate = ReadySummaryGate::default();
        let at = |seconds| start + Duration::from_secs(seconds);

        assert_eq!(gate.admit(start, true), Some(0));
        assert_eq!(gate.admit(at(1), true), Some(0));
        assert_eq!(gate.admit(at(2), true), Some(0));
    }

    #[test]
    fn dealer_growth_inside_the_interval_is_counted_in_the_next_summary() {
        let start = Instant::now();
        let mut gate = ReadySummaryGate::default();
        let at = |seconds| start + Duration::from_secs(seconds);

        assert_eq!(gate.admit(start, true), Some(0));
        assert_eq!(gate.admit(at(1), false), None);
        assert_eq!(gate.admit(at(2), false), None);
        assert_eq!(gate.admit(at(3), true), Some(2));
        assert_eq!(
            gate.admit(
                at(3) + READY_SUMMARY_INTERVAL - Duration::from_secs(1),
                false
            ),
            None
        );
        assert_eq!(gate.admit(at(3) + READY_SUMMARY_INTERVAL, false), Some(1));
    }
}
