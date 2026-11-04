// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::Address;
use anyhow::{anyhow, Result};
use std::{collections::HashSet, future::Future, pin::Pin, sync::Arc, time::Duration};

pub type EligibilityFuture = Pin<Box<dyn Future<Output = Result<HashSet<Address>>> + Send>>;

/// Reads which of `operators` `BondingRegistry.eligibilityAt` finds active at `timepoint` on
/// `chain_id`. Under a required identity policy, that includes a verified bond owner, so the owner
/// shortlist can rank only those operators.
pub type EligibilityReader = Arc<dyn Fn(u64, Vec<Address>, u64) -> EligibilityFuture + Send + Sync>;

/// The longest an eligibility read may take. A stalled RPC then ranks without the owner shortlist.
pub(crate) const ELIGIBILITY_READ_TIMEOUT: Duration = Duration::from_secs(20);

/// Seconds that a read leaves before the ticket deadline, for the ticket transaction: about a block,
/// plus clock skew.
pub(crate) const SUBMISSION_RESERVE_SECS: u64 = 20;

/// How long an eligibility read may take at `now` when tickets close at `deadline`: at most
/// [`ELIGIBILITY_READ_TIMEOUT`], and never into the submission reserve. None when no time is left.
pub(crate) fn read_limit(deadline: u64, now: u64) -> Option<Duration> {
    let left = deadline
        .checked_sub(now)?
        .checked_sub(SUBMISSION_RESERVE_SECS)?;
    (left > 0).then(|| ELIGIBILITY_READ_TIMEOUT.min(Duration::from_secs(left)))
}

/// `read`, failing after `limit`.
pub(crate) fn bounded(read: EligibilityFuture, limit: Duration) -> EligibilityFuture {
    Box::pin(async move {
        tokio::time::timeout(limit, read)
            .await
            .map_err(|_| anyhow!("the eligibility read took longer than {limit:?}"))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_ends_in_time_to_submit_the_ticket() {
        // Far from the deadline: the full limit.
        assert_eq!(read_limit(1_000, 100), Some(ELIGIBILITY_READ_TIMEOUT));
        // Close to it: only the time before the submission reserve.
        assert_eq!(read_limit(130, 100), Some(Duration::from_secs(10)));
        // Inside the reserve, or past the deadline: no read.
        assert_eq!(read_limit(120, 100), None);
        assert_eq!(read_limit(110, 100), None);
        assert_eq!(read_limit(90, 100), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_read_fails_at_the_limit() {
        let stalled = bounded(Box::pin(std::future::pending()), ELIGIBILITY_READ_TIMEOUT);
        let error = stalled.await.unwrap_err();
        assert!(error.to_string().contains("took longer than 20s"));

        let eligible = HashSet::from([Address::repeat_byte(1)]);
        let answered = eligible.clone();
        let read = bounded(
            Box::pin(async move { Ok(answered) }),
            ELIGIBILITY_READ_TIMEOUT,
        );
        assert_eq!(read.await.unwrap(), eligible);
    }
}
