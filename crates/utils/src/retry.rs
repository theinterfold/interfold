// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use std::{future::Future, time::Duration};
use tokio::time::sleep;
use tracing::{error, warn};

#[derive(Debug)]
pub enum RetryError {
    Failure(anyhow::Error),
    Retry(anyhow::Error),
}

pub fn to_retry(e: impl Into<anyhow::Error>) -> RetryError {
    RetryError::Retry(e.into())
}

/// Attempts of a chain read or transaction that fails with a retryable error.
pub const RPC_RETRY_ATTEMPTS: u32 = 3;
/// The first wait between attempts of a chain read or transaction, in milliseconds.
pub const RPC_RETRY_FIRST_DELAY_MS: u64 = 2000;

/// The longest wait of `retry_with_backoff` between two attempts.
const RETRY_MAX_DELAY: Duration = Duration::from_secs(5 * 60);

/// Returns `base * 2^(attempt - 1)` capped at `cap`, plus up to 10 % random jitter so that nodes
/// do not repeat in step. `attempt` counts from 1.
pub fn backoff_delay(base: Duration, attempt: u32, cap: Duration) -> Duration {
    let exponent = attempt.saturating_sub(1).min(20);
    let delay = base.saturating_mul(1u32 << exponent).min(cap);
    delay + delay.mul_f64(rand::random::<f64>() * 0.1)
}

/// Retries an async operation with exponential backoff
///
/// # Arguments
/// * `operation` - Async function to retry
/// * `max_attempts` - Maximum number of retry attempts
/// * `initial_delay_ms` - Initial delay between retries in milliseconds. Each later delay doubles,
///   up to 5 minutes, plus up to 10 % jitter (`backoff_delay`).
///
/// # Returns
/// * `Result<()>` - Ok if the operation succeeded, Err if all retries failed
pub async fn retry_with_backoff<F, Fut, T>(
    operation: F,
    max_attempts: u32,
    initial_delay_ms: u64,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, RetryError>>,
{
    let mut current_attempt = 1;
    let initial_delay = Duration::from_millis(initial_delay_ms);

    loop {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(re) => match re {
                RetryError::Retry(e) => {
                    if current_attempt >= max_attempts {
                        error!("Operation failed after {} attempts: {}", max_attempts, e);
                        return Err(anyhow::anyhow!(
                            "Operation failed after {} attempts. Last error: {}",
                            max_attempts,
                            e
                        ));
                    }

                    let delay = backoff_delay(initial_delay, current_attempt, RETRY_MAX_DELAY);
                    warn!(
                        "Attempt {}/{} failed, retrying in {}ms: {}",
                        current_attempt,
                        max_attempts,
                        delay.as_millis(),
                        e
                    );

                    sleep(delay).await;
                    current_attempt += 1;
                }
                RetryError::Failure(e) => {
                    error!("Non-retryable failure: {}", e);
                    return Err(e);
                }
            },
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_within(delay: Duration, expected: Duration) {
        assert!(
            delay >= expected && delay <= expected.mul_f64(1.1),
            "{delay:?} is outside {expected:?}..=110%"
        );
    }

    #[test]
    fn doubles_from_the_base_and_stops_at_the_cap() {
        let base = Duration::from_secs(30);
        let cap = Duration::from_secs(300);
        assert_within(backoff_delay(base, 0, cap), base);
        assert_within(backoff_delay(base, 1, cap), base);
        assert_within(backoff_delay(base, 2, cap), Duration::from_secs(60));
        assert_within(backoff_delay(base, 4, cap), Duration::from_secs(240));
        assert_within(backoff_delay(base, 5, cap), cap);
        assert_within(backoff_delay(base, u32::MAX, cap), cap);
    }

    /// The waits between attempts double from the first one and stop at 5 minutes.
    #[tokio::test(start_paused = true)]
    async fn retry_waits_stop_at_the_cap() {
        let started = tokio::time::Instant::now();
        let result: Result<()> = retry_with_backoff(
            || async { Err(to_retry(anyhow::anyhow!("unavailable"))) },
            8,
            60_000,
        )
        .await;
        assert!(result.is_err());
        // 60 + 120 + 240 s, then four waits of 300 s.
        assert_within(
            started.elapsed(),
            Duration::from_secs(60 + 120 + 240 + 4 * 300),
        );
    }
}
