// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use alloy::{primitives::B256, sol, sol_types::SolEvent};
use anyhow::{Context, Result};
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

// Keep this ABI for logs saved before admission events had a typed payload.
sol! {
    struct StoredAdmissionPolicy {
        bool cooldownEnabled;
        bool admissionsPaused;
        uint48 cooldownDuration;
        uint48 pauseTimepoint;
        bool pauseCooldownEnabled;
        uint48 pauseCooldownDuration;
    }
    event AdmissionPolicyUpdated(uint48 timepoint, StoredAdmissionPolicy policy);
    event AdmissionStarted(address indexed operator, uint48 timepoint);
}

impl AdmissionUpdated {
    /// Decode an admission log preserved by an older binary. The caller must verify its EVM source.
    pub fn from_observed_log(log: &crate::EvmLogObserved) -> Result<Option<Self>> {
        if log.contract != "BondingRegistry" {
            return Ok(None);
        }
        let Some(topic) = log.topics.first() else {
            return Ok(None);
        };
        let signature: B256 = topic
            .parse()
            .context("invalid stored EVM event signature")?;
        if signature != AdmissionPolicyUpdated::SIGNATURE_HASH
            && signature != AdmissionStarted::SIGNATURE_HASH
        {
            return Ok(None);
        }
        let topics = log
            .topics
            .iter()
            .map(|topic| topic.parse::<B256>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("invalid stored admission event topics")?;
        let (timepoint, change) = if signature == AdmissionPolicyUpdated::SIGNATURE_HASH {
            let event =
                AdmissionPolicyUpdated::decode_raw_log_validate(topics, &log.data.extract_bytes())
                    .context("invalid stored admission policy log")?;
            (
                event.timepoint.to(),
                AdmissionChange::Policy(AdmissionPolicy {
                    cooldown_enabled: event.policy.cooldownEnabled,
                    admissions_paused: event.policy.admissionsPaused,
                    cooldown_duration: event.policy.cooldownDuration.to(),
                    pause_timepoint: event.policy.pauseTimepoint.to(),
                    pause_cooldown_enabled: event.policy.pauseCooldownEnabled,
                    pause_cooldown_duration: event.policy.pauseCooldownDuration.to(),
                }),
            )
        } else {
            let event =
                AdmissionStarted::decode_raw_log_validate(topics, &log.data.extract_bytes())
                    .context("invalid stored admission start log")?;
            (
                event.timepoint.to(),
                AdmissionChange::Started {
                    operator: event.operator.to_string(),
                },
            )
        };
        Ok(Some(Self {
            chain_id: log.chain_id,
            timepoint,
            change,
        }))
    }
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
