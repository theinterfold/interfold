// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure decision logic for staggered, committee-attested slash submission.
//!
//! A node only submits a slash proposal when it is one of the top
//! `MAX_SLASH_SUBMITTERS` voters (ranked ascending by signer address). The
//! lowest-address voter submits immediately; higher-ranked fallback voters wait
//! `rank * SUBMITTER_DELAY_SECS` so on-chain `DuplicateEvidence` protection lets
//! at most one slash execute.

use std::time::Duration;

use alloy::primitives::Address;
use e3_events::AccusationOutcome;

/// Maximum number of voters eligible to attempt on-chain submission.
/// Rank 0 submits immediately, rank 1 after one delay interval, etc.
pub(crate) const MAX_SLASH_SUBMITTERS: usize = 3;

/// Delay between fallback submission attempts (seconds).
/// Rank N waits N * SUBMITTER_DELAY_SECS before submitting.
pub(crate) const SUBMITTER_DELAY_SECS: u64 = 30;

/// Determine this node's submission rank: its position in the voter set after
/// sorting ascending by address. `None` when this node is not among the voters.
pub(crate) fn submission_rank<I>(voters: I, my_addr: Address) -> Option<usize>
where
    I: IntoIterator<Item = Address>,
{
    let mut sorted: Vec<Address> = voters.into_iter().collect();
    sorted.sort();
    sorted.iter().position(|&v| v == my_addr)
}

/// Outcomes that warrant an on-chain slash proposal.
pub(crate) fn is_slashable_outcome(outcome: &AccusationOutcome) -> bool {
    matches!(
        outcome,
        AccusationOutcome::AccusedFaulted | AccusationOutcome::Equivocation
    )
}

/// Whether this node should attempt submission for the given quorum result.
pub(crate) fn should_submit_slash(
    chain_matches: bool,
    outcome: &AccusationOutcome,
    rank: Option<usize>,
) -> bool {
    chain_matches && is_slashable_outcome(outcome) && rank.is_some_and(|r| r < MAX_SLASH_SUBMITTERS)
}

/// How long a fallback submitter of the given rank should wait before attempting.
pub(crate) fn submission_delay(rank: usize) -> Duration {
    Duration::from_secs(rank as u64 * SUBMITTER_DELAY_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submission_rank_sorts_ascending() {
        let a = Address::repeat_byte(0x01);
        let b = Address::repeat_byte(0x02);
        let c = Address::repeat_byte(0x03);
        // Provided out of order; my_addr=b should be rank 1.
        assert_eq!(submission_rank([c, a, b], b), Some(1));
        assert_eq!(submission_rank([c, a, b], a), Some(0));
        assert_eq!(submission_rank([c, a, b], c), Some(2));
    }

    #[test]
    fn test_submission_rank_none_when_not_voter() {
        let a = Address::repeat_byte(0x01);
        let other = Address::repeat_byte(0x09);
        assert_eq!(submission_rank([a], other), None);
    }

    #[test]
    fn test_should_submit_slash_gating() {
        // Happy path: chain matches, slashable outcome, rank within bound.
        assert!(should_submit_slash(
            true,
            &AccusationOutcome::AccusedFaulted,
            Some(0)
        ));
        // Wrong chain.
        assert!(!should_submit_slash(
            false,
            &AccusationOutcome::AccusedFaulted,
            Some(0)
        ));
        // Non-slashable outcome.
        assert!(!should_submit_slash(
            true,
            &AccusationOutcome::Inconclusive,
            Some(0)
        ));
        // Rank exceeds MAX_SLASH_SUBMITTERS.
        assert!(!should_submit_slash(
            true,
            &AccusationOutcome::AccusedFaulted,
            Some(MAX_SLASH_SUBMITTERS)
        ));
        // Not a voter.
        assert!(!should_submit_slash(
            true,
            &AccusationOutcome::Equivocation,
            None
        ));
    }

    #[test]
    fn test_submission_delay_scales_with_rank() {
        assert_eq!(submission_delay(0), Duration::from_secs(0));
        assert_eq!(
            submission_delay(2),
            Duration::from_secs(2 * SUBMITTER_DELAY_SECS)
        );
    }
}
