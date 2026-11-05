// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Transaction facts that EVM senders share: receipt status, nonce choice, broadcast refusal, and
//! RPC retry classification. Each sender keeps its own locks, attempts, and confirmation policy.

pub mod nonce;
mod receipt;
mod retry;

pub use receipt::{require_successful_receipt, RevertedTransaction};
pub use retry::{should_retry_error, RPC_RETRY_ATTEMPTS, RPC_RETRY_FIRST_DELAY_MS};
