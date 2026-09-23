// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Mirrors the contract's timestamp-bound admission policy, including the frozen pause rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    pub cooldown_enabled: bool,
    pub admissions_paused: bool,
    pub cooldown_duration: u64,
    pub pause_timepoint: u64,
    pub pause_cooldown_enabled: bool,
    pub pause_cooldown_duration: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdmissionChange {
    Policy(AdmissionPolicy),
    Started { operator: String },
}

/// Uses the timestamp emitted by BondingRegistry, not the local ingestion clock.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct AdmissionUpdated {
    pub chain_id: u64,
    pub timepoint: u64,
    pub change: AdmissionChange,
}

impl Display for AdmissionUpdated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AdmissionUpdated {{ chain: {}, timepoint: {}, change: {:?} }}",
            self.chain_id, self.timepoint, self.change
        )
    }
}
