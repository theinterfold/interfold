// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_utils::{retry_with_backoff, RetryError};
use std::future::Future;
use tracing::info;

const RETRY_MAX_ATTEMPTS: u32 = 3;
const RETRY_INITIAL_DELAY_MS: u64 = 2000;

fn should_retry_error(error: &str, decoded_error: Option<&str>, retry_on_errors: &[&str]) -> bool {
    if retry_on_errors.is_empty() {
        return true;
    }
    retry_on_errors.iter().any(|code| {
        error.contains(code) || decoded_error.is_some_and(|decoded| decoded.contains(code))
    })
}

pub async fn call_with_retry<F, Fut, T>(
    operation_name: &str,
    retry_on_errors: &[&str],
    operation_fn: F,
) -> anyhow::Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    call_with_retry_and_decoder(operation_name, retry_on_errors, operation_fn, |_| None).await
}

/// Like `call_with_retry`, but accepts an error decoder function that can
/// translate raw error strings (containing hex revert data) into human-readable
/// error names. The decoded name is used both for logging and for matching
/// against `retry_on_errors`.
pub async fn call_with_retry_and_decoder<F, Fut, T, D>(
    operation_name: &str,
    retry_on_errors: &[&str],
    operation_fn: F,
    decode_error: D,
) -> anyhow::Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
    D: Fn(&str) -> Option<String>,
{
    let op_name = operation_name.to_string();
    let retry_codes: Vec<String> = retry_on_errors.iter().map(|s| s.to_string()).collect();

    retry_with_backoff(
        || {
            let op_name = op_name.clone();
            let retry_codes = retry_codes.clone();
            let fut = operation_fn();
            // Decode before entering the async block to avoid moving the closure
            let decode_fn = &decode_error;
            async move {
                match fut.await {
                    Ok(value) => Ok(value),
                    Err(e) => {
                        let error_str = format!("{e:#}");
                        let decoded = decode_fn(&error_str);
                        let display_error = decoded.as_deref().unwrap_or(&error_str);
                        let retry_refs: Vec<&str> =
                            retry_codes.iter().map(|s| s.as_str()).collect();
                        if should_retry_error(&error_str, decoded.as_deref(), &retry_refs) {
                            info!("{}: error, will retry: {}", op_name, display_error);
                            Err(RetryError::Retry(e))
                        } else {
                            info!("{}: error: {}", op_name, display_error);
                            Err(RetryError::Failure(e))
                        }
                    }
                }
            }
        },
        RETRY_MAX_ATTEMPTS,
        RETRY_INITIAL_DELAY_MS,
    )
    .await
}
