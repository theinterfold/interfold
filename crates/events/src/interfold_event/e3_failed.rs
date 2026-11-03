// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// A contract enum value that this binary does not know.
///
/// The contract encodes its enums as `uint8`, so a value from a newer contract reaches the node
/// as a number. The conversions below refuse it instead of mapping it to a known variant, because
/// a wrong variant changes what the node does with the E3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown {name} value {value}; the contract is newer than this node")]
pub struct UnknownContractValue {
    pub name: &'static str,
    pub value: u8,
}

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
    /// The requester cancelled the E3 before completion.
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

    /// Returns true when the E3 can stop without an accusation or slash flow.
    pub fn ends_without_slashing(&self) -> bool {
        self.is_timeout()
            || matches!(
                self,
                Self::NoInputsReceived
                    | Self::ComputeProviderExpired
                    | Self::ComputeProviderFailed
                    | Self::RequesterCancelled
            )
    }
}

/// The contract's `FailureReason` enum, in declaration order. `_MAX_FAILURE_REASON` is a bound
/// that the contract never emits, so it has no variant.
impl TryFrom<u8> for FailureReason {
    type Error = UnknownContractValue;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::None,
            1 => Self::CommitteeFormationTimeout,
            2 => Self::InsufficientCommitteeMembers,
            3 => Self::DKGTimeout,
            4 => Self::DKGInvalidShares,
            5 => Self::NoInputsReceived,
            6 => Self::ComputeTimeout,
            7 => Self::ComputeProviderExpired,
            8 => Self::ComputeProviderFailed,
            9 => Self::RequesterCancelled,
            10 => Self::DecryptionTimeout,
            11 => Self::DecryptionInvalidShares,
            12 => Self::VerificationFailed,
            value => {
                return Err(UnknownContractValue {
                    name: "FailureReason",
                    value,
                })
            }
        })
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

impl E3Stage {
    /// Returns true when the E3 has completed or failed.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete | Self::Failed)
    }
}

/// The contract's `E3Stage` enum, in declaration order.
impl TryFrom<u8> for E3Stage {
    type Error = UnknownContractValue;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::None,
            1 => Self::Requested,
            2 => Self::CommitteeFinalized,
            3 => Self::KeyPublished,
            4 => Self::CiphertextReady,
            5 => Self::Complete,
            6 => Self::Failed,
            value => {
                return Err(UnknownContractValue {
                    name: "E3Stage",
                    value,
                })
            }
        })
    }
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
