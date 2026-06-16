// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Reason why an E3 failed
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailureReason {
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
    VerificationFailed,
}

impl FailureReason {
    /// Returns true when the failure was caused purely by a deadline expiring rather
    /// than by a node acting maliciously. Timeout failures have no associated
    /// accusation/slashing lifecycle, so their E3 context can be torn down immediately.
    pub fn is_timeout(&self) -> bool {
        matches!(
            self,
            Self::CommitteeFormationTimeout
                | Self::DKGTimeout
                | Self::ComputeTimeout
                | Self::DecryptionTimeout
        )
    }
}

/// E3 lifecycle stage
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum E3Stage {
    None,
    Requested,
    CommitteeFinalized,
    KeyPublished,
    CiphertextReady,
    Complete,
    Failed,
}

#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct E3Failed {
    pub e3_id: E3id,
    pub failed_at_stage: E3Stage,
    pub reason: FailureReason,
}

impl Display for E3Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "E3Failed {{ e3_id: {}, stage: {:?}, reason: {:?} }}",
            self.e3_id, self.failed_at_stage, self.reason
        )
    }
}
