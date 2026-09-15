// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Adaptive `eth_getLogs` block window.
//!
//! Hosted providers cap the block range of a single `eth_getLogs` call, and the cap is not
//! discoverable: it is published in documentation, not over the wire. A fixed window therefore makes
//! the node work on some providers and fail on others, and the failure arrives as an opaque
//! provider-specific error during the first historical sync.
//!
//! This window starts at the widest range and halves it each time the provider rejects the range.
//! The node then finds the provider's limit by itself, so an operator does not have to select an
//! endpoint by its documented range cap.
//!
//! The discovered width is kept for the remainder of the sync. A range cap is a property of the
//! provider, not of the block range that was requested, so a window that grew back would find the
//! same cap again on the next call and pay one more failed request for each chunk.

/// Widest `eth_getLogs` range the node asks for. Providers that permit this range, or more, complete
/// a sync in the fewest calls.
pub(crate) const MAX_LOG_WINDOW: u64 = 10_000;

/// Narrowest range the window can reach. One block always satisfies a range cap, so the node keeps a
/// usable window against any provider.
pub(crate) const MIN_LOG_WINDOW: u64 = 1;

/// Window width at or below which a sync is slow enough that the operator should know. A provider
/// that caps the range this tightly needs hundreds of thousands of calls to read a long history.
pub(crate) const NARROW_LOG_WINDOW_WARN: u64 = 128;

/// Maximum halvings for one chunk. `MAX_LOG_WINDOW` reaches `MIN_LOG_WINDOW` in 14 halvings, so this
/// bound stops a provider that rejects every range from looping, and never stops a real adaptation.
pub(crate) const MAX_WINDOW_SHRINKS: u32 = 16;

/// Provider messages that report a rejected block range or an oversized result set.
///
/// Both conditions are corrected the same way — ask for fewer blocks — so they share one list. The
/// entries are matched against a lowercased message, and each is specific enough that an unrelated
/// error does not consume the shrink budget. A rate limit is deliberately absent: it is retried with
/// backoff, and narrowing the window would not help.
///
/// The wording is provider-specific and undocumented, so this list is evidence, not a
/// specification. Entries confirmed against a live endpoint carry the provider that produced them.
const RANGE_LIMIT_MARKERS: &[&str] = &[
    // JSON-RPC codes some providers use for a rejected range. Codes are matched as text because
    // the transport reports the code inside the error message.
    "-32062",
    // Observed: publicnode Sepolia, "error code -32701: exceed maximum block range: 50000".
    "-32701",
    "range too large",
    "range is too large",
    "range too wide",
    "range is too wide",
    "block range limit",
    "max block range",
    // Observed: publicnode, "exceed maximum block range: 50000".
    "exceed maximum block range",
    "exceeds max block range",
    "query returned more than",
    "too many results",
    "response size exceeded",
    "query timeout exceeded",
    "reduce the block range",
    "reduce your block range",
];

/// Phrases that report a rejected range only when the message also names a range.
///
/// `limited to a` alone is not sufficient, because providers use the same words for a request
/// quota, as in "limited to a maximum of 25 requests per second". A quota must keep the backoff
/// path: fewer blocks for each call does not raise it, and narrowing the window would send more
/// calls. The qualifier keeps the block-range wording, as in "eth_getLogs is limited to a 10,000
/// range".
const RANGE_QUALIFIED_MARKERS: &[&str] = &["limited to a"];

/// Word that must accompany a [`RANGE_QUALIFIED_MARKERS`] phrase before it reports a block range.
const RANGE_CONTEXT_MARKER: &str = "range";

/// Report whether `message` says the provider refused the block range or the result set size.
pub(crate) fn is_range_limit_error(message: &str) -> bool {
    let message = message.to_lowercase();
    if RANGE_LIMIT_MARKERS
        .iter()
        .any(|marker| message.contains(marker))
    {
        return true;
    }

    message.contains(RANGE_CONTEXT_MARKER)
        && RANGE_QUALIFIED_MARKERS
            .iter()
            .any(|marker| message.contains(marker))
}

/// Current `eth_getLogs` block window for one chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LogWindow {
    width: u64,
}

impl Default for LogWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl LogWindow {
    /// Start at the widest range and narrow it only when a provider rejects one.
    pub(crate) fn new() -> Self {
        Self {
            width: MAX_LOG_WINDOW,
        }
    }

    /// Build a window of an exact width, for tests.
    ///
    /// The width is clamped into `MIN_LOG_WINDOW..=MAX_LOG_WINDOW`, so a zero width cannot produce a
    /// range that never advances.
    #[cfg(test)]
    pub(crate) fn with_width(width: u64) -> Self {
        Self {
            width: width.clamp(MIN_LOG_WINDOW, MAX_LOG_WINDOW),
        }
    }

    /// The current window width in blocks.
    pub(crate) fn width(&self) -> u64 {
        self.width
    }

    /// The last block of the chunk that starts at `cursor`, bounded by `to_block`.
    ///
    /// Saturating arithmetic keeps a window near `u64::MAX` from wrapping to a range that ends below
    /// its own start.
    pub(crate) fn end_for(&self, cursor: u64, to_block: u64) -> u64 {
        cursor.saturating_add(self.width - 1).min(to_block)
    }

    /// Halve the window after a provider rejected the range.
    ///
    /// Returns `false` when the window is already at `MIN_LOG_WINDOW`: a provider that refuses a
    /// single block is not applying a range cap, and the caller must report the error instead of
    /// narrowing further.
    pub(crate) fn shrink(&mut self) -> bool {
        if self.width <= MIN_LOG_WINDOW {
            return false;
        }
        self.width = (self.width / 2).max(MIN_LOG_WINDOW);
        true
    }

    /// Report whether the window is narrow enough that the operator should be told.
    pub(crate) fn is_narrow(&self) -> bool {
        self.width <= NARROW_LOG_WINDOW_WARN
    }

    /// Estimated number of chunks for `from_block..=to_block` at the current width.
    ///
    /// The estimate is a lower bound: a later shrink increases the real count.
    pub(crate) fn estimated_chunks(&self, from_block: u64, to_block: u64) -> u64 {
        if to_block < from_block {
            return 0;
        }
        (to_block - from_block + 1).div_ceil(self.width)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_window_starts_at_the_widest_range() {
        assert_eq!(LogWindow::new().width(), MAX_LOG_WINDOW);
    }

    #[test]
    fn shrinking_halves_the_window() {
        let mut window = LogWindow::new();

        assert!(window.shrink());
        assert_eq!(window.width(), 5_000);
        assert!(window.shrink());
        assert_eq!(window.width(), 2_500);
    }

    #[test]
    fn shrinking_stops_at_the_floor_and_reports_it() {
        let mut window = LogWindow::with_width(2);

        assert!(window.shrink());
        assert_eq!(window.width(), MIN_LOG_WINDOW);
        // The floor is a usable window, so the caller must learn that narrowing is exhausted rather
        // than read a width that stopped changing.
        assert!(!window.shrink());
        assert_eq!(window.width(), MIN_LOG_WINDOW);
    }

    #[test]
    fn the_widest_window_reaches_the_floor_within_the_shrink_budget() {
        let mut window = LogWindow::new();
        let mut shrinks = 0u32;

        while window.shrink() {
            shrinks += 1;
            assert!(shrinks <= MAX_WINDOW_SHRINKS, "shrink budget is too small");
        }

        assert_eq!(window.width(), MIN_LOG_WINDOW);
        assert!(shrinks < MAX_WINDOW_SHRINKS);
    }

    #[test]
    fn a_zero_width_is_clamped_so_a_chunk_always_advances() {
        let window = LogWindow::with_width(0);

        assert_eq!(window.width(), MIN_LOG_WINDOW);
        // A zero width would produce end_for(100, 200) == 99 and a range that never advances.
        assert_eq!(window.end_for(100, 200), 100);
    }

    #[test]
    fn a_width_above_the_maximum_is_clamped() {
        assert_eq!(LogWindow::with_width(u64::MAX).width(), MAX_LOG_WINDOW);
    }

    #[test]
    fn the_chunk_end_is_bounded_by_the_requested_range() {
        let window = LogWindow::new();

        assert_eq!(window.end_for(0, 24_999), 9_999);
        assert_eq!(window.end_for(20_000, 24_999), 24_999);
    }

    #[test]
    fn the_chunk_end_does_not_wrap_near_the_maximum_block() {
        let window = LogWindow::new();

        // Saturating arithmetic must not produce an end below the cursor.
        assert_eq!(window.end_for(u64::MAX - 1, u64::MAX), u64::MAX);
    }

    #[test]
    fn narrow_windows_are_reported_for_the_operator() {
        assert!(!LogWindow::new().is_narrow());
        assert!(LogWindow::with_width(NARROW_LOG_WINDOW_WARN).is_narrow());
        assert!(LogWindow::with_width(10).is_narrow());
    }

    #[test]
    fn the_chunk_estimate_follows_the_current_width() {
        assert_eq!(LogWindow::new().estimated_chunks(0, 24_999), 3);
        assert_eq!(LogWindow::with_width(10).estimated_chunks(0, 99), 10);
        // An empty range needs no call.
        assert_eq!(LogWindow::new().estimated_chunks(200, 100), 0);
    }

    #[test]
    fn provider_range_errors_are_recognized() {
        for message in [
            "server returned an error response: error code -32062: range too large",
            "Log response size exceeded. You can make eth_getLogs requests with up to a 10K block range",
            "query returned more than 10000 results",
            "eth_getLogs is limited to a 10,000 range",
            "block range limit exceeded",
            "Query timeout exceeded. Consider reducing your block range",
            "Max block range is 1000",
        ] {
            assert!(is_range_limit_error(message), "not detected: {message}");
        }
    }

    #[test]
    fn unrelated_provider_errors_are_not_treated_as_range_errors() {
        for message in [
            "429 Too Many Requests",
            "error code -32005: rate limit exceeded",
            "connection reset by peer",
            "execution reverted",
            "insufficient funds for gas * price + value",
            "intrinsic gas too low",
        ] {
            assert!(
                !is_range_limit_error(message),
                "wrongly detected: {message}"
            );
        }
    }

    #[test]
    fn a_request_quota_that_borrows_range_wording_keeps_the_backoff_path() {
        // These say "limited to a" but describe a request quota. Narrowing the window would send
        // more calls for each block, which makes a quota failure worse. They must reach the
        // backoff path instead.
        //
        // The transport retry answers most quota errors before this point, but only for the error
        // codes it knows. An unrecognized code, and the "Max retries exceeded" error raised once
        // the transport gives up, both still arrive here carrying the provider's own words.
        for message in [
            "You are limited to a maximum of 25 requests per second",
            "Max retries exceeded: this key is limited to a maximum of 30 requests/second",
            "your plan is limited to a rate of 100 requests per second",
            "credits limited to 6000/sec",
        ] {
            assert!(
                !is_range_limit_error(message),
                "a request quota must not narrow the window: {message}"
            );
        }
    }

    #[test]
    fn range_wording_with_the_same_phrase_is_still_detected() {
        // The qualifier must not cost the block-range wording this phrase was added for.
        for message in [
            "eth_getLogs is limited to a 10,000 range",
            "eth_getLogs is limited to a 10K block range",
            "this endpoint is limited to a range of 1000 blocks",
        ] {
            assert!(is_range_limit_error(message), "not detected: {message}");
        }
    }

    #[test]
    fn live_provider_range_errors_are_recognized() {
        // Captured verbatim from live endpoints, not composed by hand. `-32701` with this wording
        // is what publicnode returns above its 50,000-block cap.
        for message in [
            "server returned an error response: error code -32701: exceed maximum block range: 50000",
        ] {
            assert!(is_range_limit_error(message), "not detected: {message}");
        }
    }

    #[test]
    fn a_plan_or_auth_refusal_is_not_a_range_error() {
        // Also captured live. These refuse the request for reasons a narrower window cannot fix,
        // so they must not consume the shrink budget.
        for message in [
            r#"HTTP error 400 with body: {"message":"chain is not available on free plan, please upgrade to paid plan","code":35}"#,
            r#"HTTP error 403 with body: {"error":{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"}}"#,
        ] {
            assert!(
                !is_range_limit_error(message),
                "wrongly detected as a range error: {message}"
            );
        }
    }

    #[test]
    fn range_error_detection_ignores_case() {
        assert!(is_range_limit_error("RANGE TOO LARGE"));
        assert!(is_range_limit_error(
            "Query Returned More Than 10000 Results"
        ));
    }
}
