// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::{primitives::B256, rpc::types::TransactionReceipt};
use std::{error::Error, fmt};

/// A transaction was mined but its receipt records an EVM execution failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertedTransaction {
    operation: String,
    transaction_hash: B256,
}

impl fmt::Display for RevertedTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} transaction {} reverted on chain",
            self.operation, self.transaction_hash
        )
    }
}

impl Error for RevertedTransaction {}

/// Reject a mined transaction whose consensus receipt reports execution failure.
pub fn require_successful_receipt(
    operation: &str,
    receipt: &TransactionReceipt,
) -> Result<(), RevertedTransaction> {
    require_successful_status(operation, receipt.transaction_hash, receipt.status())
}

fn require_successful_status(
    operation: &str,
    transaction_hash: B256,
    succeeded: bool,
) -> Result<(), RevertedTransaction> {
    if !succeeded {
        return Err(RevertedTransaction {
            operation: operation.to_owned(),
            transaction_hash,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_status_is_accepted() {
        assert!(require_successful_status("publish", B256::ZERO, true).is_ok());
    }

    #[test]
    fn failed_status_reports_operation_and_hash() {
        let hash = B256::with_last_byte(7);
        let error = require_successful_status("publish", hash, false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("publish"));
        assert!(message.contains(&hash.to_string()));
        assert!(message.contains("reverted"));
    }
}
