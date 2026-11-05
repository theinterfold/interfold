// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Attempts of a chain read or transaction that fails with a retryable error.
pub const RPC_RETRY_ATTEMPTS: u32 = 3;
/// The first wait between attempts of a chain read or transaction, in milliseconds.
pub const RPC_RETRY_FIRST_DELAY_MS: u64 = 2000;

pub fn should_retry_error(
    error: &str,
    decoded_error: Option<&str>,
    retry_on_errors: &[&str],
) -> bool {
    if retry_on_errors.is_empty() {
        return true;
    }
    retry_on_errors.iter().any(|code| {
        error.contains(code) || decoded_error.is_some_and(|decoded| decoded.contains(code))
    })
}
