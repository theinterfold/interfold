// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure reorg-safety primitive for EVM ingestion.
//!
//! The local event log is append-only and has no truncation primitive, so once
//! a chain log is promoted to an `InterfoldEvent` and folded into state it cannot
//! be cleanly un-applied. The only sound defence against a chain reorg is
//! therefore *prevention*: do not ingest a log until it is buried under enough
//! confirmations that a reorg of that depth is infeasible.
//!
//! [`confirmed_head`] is that gate: it clamps how far the reader may advance. It
//! is clock-free and provider-free so it is fully unit-tested; the actors own the
//! wall clock and provider I/O and feed values in.

/// The highest block height that is safe to ingest given the current chain head
/// and the required confirmation depth. Returns `chain_head` when
/// `confirmations == 0` (no gating), and saturates at 0 for shallow chains.
///
/// A log at height `h` is safe once `h <= chain_head - confirmations`, i.e. once
/// at least `confirmations` blocks have been built on top of it.
pub fn confirmed_head(chain_head: u64, confirmations: u64) -> u64 {
    chain_head.saturating_sub(confirmations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmed_head_clamps_and_saturates() {
        assert_eq!(confirmed_head(100, 0), 100);
        assert_eq!(confirmed_head(100, 12), 88);
        assert_eq!(confirmed_head(5, 12), 0);
    }
}
