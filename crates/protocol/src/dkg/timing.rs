// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::UnixSecs;
use serde::{Deserialize, Serialize};

/// The DKG timing the request froze, read from the chain when the committee is finalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgTiming {
    /// The canonical DKG deadline.
    pub deadline: UnixSecs,
    /// The frozen DKG window, which ends at the deadline.
    pub window: u64,
    /// The block the committee was finalized in: nothing of its key is on chain before it.
    pub finalized_block: u64,
}

impl DkgTiming {
    /// Encryption keys that arrive after this do not count: 10% into the window.
    pub fn key_cutoff(&self) -> UnixSecs {
        self.at_basis_points(1_000)
    }

    /// After this a Ready report no longer waits for missing dealers: 75% into the window.
    pub fn share_checkpoint(&self) -> UnixSecs {
        self.at_basis_points(7_500)
    }

    fn at_basis_points(&self, basis_points: u64) -> UnixSecs {
        let start = self.deadline.saturating_sub(self.window);
        let offset = (self.window.saturating_mul(basis_points) / 10_000).max(1);
        start.saturating_add(offset).min(self.deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutoffs_are_a_share_of_the_window_at_least_a_second_in_and_never_past_the_deadline() {
        let timing = |deadline, window| DkgTiming {
            deadline,
            window,
            finalized_block: 0,
        };
        assert_eq!(timing(10_000, 1_000).key_cutoff(), 9_100);
        assert_eq!(timing(10_000, 1_000).share_checkpoint(), 9_750);
        assert_eq!(timing(10_000, 5).key_cutoff(), 9_996);
        assert_eq!(timing(10_000, 5).share_checkpoint(), 9_998);
        assert_eq!(timing(10_000, 20_000).key_cutoff(), 2_000);
        assert_eq!(timing(10_000, 1).key_cutoff(), 10_000);
    }
}
