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

/// How long an eligibility read may take. A stalled RPC then ranks without the owner shortlist, well
/// inside the shortest ticket submission window (60 seconds).
pub(crate) const ELIGIBILITY_READ_TIMEOUT: Duration = Duration::from_secs(20);

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
