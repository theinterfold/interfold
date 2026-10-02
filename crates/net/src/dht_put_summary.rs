// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Counts finished DHT uploads, so the network interface reports them in one INFO line per
/// interval and not in one line per upload.
#[derive(Debug, Default)]
pub(crate) struct DhtPutSummary {
    stored: usize,
    failed: usize,
}

impl DhtPutSummary {
    pub(crate) fn record(&mut self, stored: bool) {
        if stored {
            self.stored = self.stored.saturating_add(1);
        } else {
            self.failed = self.failed.saturating_add(1);
        }
    }

    /// Returns the stored and failed counts since the last call and resets them. Returns `None`
    /// when no upload finished, so a quiet interval writes no log line.
    pub(crate) fn take(&mut self) -> Option<(usize, usize)> {
        let counts = (self.stored, self.failed);
        *self = Self::default();
        (counts != (0, 0)).then_some(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::DhtPutSummary;

    #[test]
    fn reports_each_interval_once_and_stays_quiet_without_uploads() {
        let mut summary = DhtPutSummary::default();
        assert_eq!(summary.take(), None);

        summary.record(true);
        summary.record(true);
        summary.record(false);
        assert_eq!(summary.take(), Some((2, 1)));
        assert_eq!(summary.take(), None);
    }
}
