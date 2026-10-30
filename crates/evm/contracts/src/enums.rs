// SPDX-License-Identifier: LGPL-3.0-only

//! Typed views of contract discriminants, separate from raw wire tuples.

use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

sol! {
    #[derive(Debug, Serialize, Deserialize)]
    enum CommitteeSize {
        Minimum,
        Micro,
        Small,
    }

    #[derive(Debug, PartialEq)]
    enum E3Stage {
        None,
        Requested,
        CommitteeFinalized,
        KeyPublished,
        CiphertextReady,
        Complete,
        Failed
    }

    // _MAX_FAILURE_REASON is a Solidity bound, never an emitted failure reason.
    #[derive(Debug, PartialEq)]
    enum FailureReason {
        None,
        CommitteeFormationTimeout,
        InsufficientCommitteeMembers,
        DKGTimeout,
        DKGInvalidShares,
        NoInputsReceived,
        ComputeTimeout,
        ComputeProviderExpired,
        ComputeProviderFailed,
        RequesterCancelled,
        DecryptionTimeout,
        DecryptionInvalidShares,
        VerificationFailed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_view_preserves_existing_indexer_encoding() {
        for (index, value) in [
            CommitteeSize::Minimum,
            CommitteeSize::Micro,
            CommitteeSize::Small,
            CommitteeSize::__Invalid,
        ]
        .into_iter()
        .enumerate()
        {
            let encoded = bincode::serialize(&value).unwrap();
            assert_eq!(encoded, (index as u32).to_le_bytes());
            let restored: CommitteeSize = bincode::deserialize(&encoded).unwrap();
            assert_eq!(u8::from(restored), u8::from(value));
        }
    }
}
