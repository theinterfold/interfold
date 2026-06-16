// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure derivation of an HLC timestamp for an EVM log.

use e3_events::hlc::HlcTimestamp;

/// Derive a monotonic HLC timestamp for a log from its block timestamp, log
/// index (orders logs within a block) and chain id (acts as the HLC node id).
pub(crate) fn from_log_chain_id_to_ts(block_timestamp: u64, log_index: u64, chain_id: u64) -> u128 {
    let ts = block_timestamp.saturating_mul(1_000_000);

    // Use log_index as counter (orders logs within same block)
    let counter = log_index as u32;

    // Use transaction_index as node (or chain_id if you have it)
    let node = chain_id as u32;

    HlcTimestamp::new(ts, counter, node).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orders_logs_within_same_block_by_index() {
        let a = from_log_chain_id_to_ts(1_000, 0, 1);
        let b = from_log_chain_id_to_ts(1_000, 1, 1);
        assert!(b > a, "later log index must produce a greater timestamp");
    }

    #[test]
    fn test_later_block_dominates_log_index() {
        let earlier = from_log_chain_id_to_ts(1_000, 99, 1);
        let later = from_log_chain_id_to_ts(1_001, 0, 1);
        assert!(later > earlier, "later block must dominate the log index");
    }

    #[test]
    fn test_block_timestamp_does_not_overflow() {
        // saturating_mul must not panic at the upper bound.
        let _ = from_log_chain_id_to_ts(u64::MAX, 0, 1);
    }
}
