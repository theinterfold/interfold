// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The bond-owner identity policy, decoded from raw BondingRegistry logs.
//!
//! The node keeps these logs as `EvmLogObserved` and decodes them where it needs them, so the policy
//! adds no variant to the durable event log.

use crate::EvmLogObserved;
use alloy::{primitives::B256, sol, sol_types::SolEvent};
use anyhow::{Context, Result};

sol! {
    event IdentityPolicyUpdated(uint48 timepoint, address registry, bool required);
}

/// One identity policy change, at the timestamp that BondingRegistry emitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityPolicyChange {
    pub chain_id: u64,
    pub timepoint: u64,
    pub required: bool,
}

impl IdentityPolicyChange {
    /// Decode an identity policy log. The caller must verify its EVM source.
    pub fn from_observed_log(log: &EvmLogObserved) -> Result<Option<Self>> {
        if log.contract != "BondingRegistry" {
            return Ok(None);
        }
        let Some(topic) = log.topics.first() else {
            return Ok(None);
        };
        let signature: B256 = topic
            .parse()
            .context("invalid stored EVM event signature")?;
        if signature != IdentityPolicyUpdated::SIGNATURE_HASH {
            return Ok(None);
        }
        let topics = log
            .topics
            .iter()
            .map(|topic| topic.parse::<B256>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("invalid stored identity policy topics")?;
        let event =
            IdentityPolicyUpdated::decode_raw_log_validate(topics, &log.data.extract_bytes())
                .context("invalid stored identity policy log")?;
        Ok(Some(Self {
            chain_id: log.chain_id,
            timepoint: event.timepoint.to(),
            required: event.required,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{keccak256, Address, U256},
        sol_types::SolValue,
    };

    fn log(contract: &str, signature: &str, data: Vec<u8>) -> EvmLogObserved {
        EvmLogObserved {
            contract: contract.into(),
            chain_id: 7,
            e3_id: None,
            event_name: "UnknownEvmLog".into(),
            signature: None,
            known: false,
            topics: vec![keccak256(signature).to_string()],
            data: e3_utils::ArcBytes::from_bytes(&data),
        }
    }

    #[test]
    fn decodes_a_policy_log_from_the_registry_only() {
        let data = (U256::from(42), Address::repeat_byte(9), true).abi_encode();
        let policy = log(
            "BondingRegistry",
            "IdentityPolicyUpdated(uint48,address,bool)",
            data.clone(),
        );
        assert_eq!(
            IdentityPolicyChange::from_observed_log(&policy).unwrap(),
            Some(IdentityPolicyChange {
                chain_id: 7,
                timepoint: 42,
                required: true,
            })
        );
        let elsewhere = log(
            "Interfold",
            "IdentityPolicyUpdated(uint48,address,bool)",
            data,
        );
        assert_eq!(
            IdentityPolicyChange::from_observed_log(&elsewhere).unwrap(),
            None
        );
        let other = log(
            "BondingRegistry",
            "AdmissionStarted(address,uint48)",
            Vec::new(),
        );
        assert_eq!(
            IdentityPolicyChange::from_observed_log(&other).unwrap(),
            None
        );
        let truncated = log(
            "BondingRegistry",
            "IdentityPolicyUpdated(uint48,address,bool)",
            vec![0; 31],
        );
        assert!(IdentityPolicyChange::from_observed_log(&truncated).is_err());
    }
}
