// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure translation of `BondingRegistry.sol` logs into `InterfoldEventData`.

use crate::contracts::IBondingRegistry;
use alloy::{
    primitives::{LogData, B256},
    sol_types::SolEvent,
};
use e3_events::{
    BondOwnerSet, CiphernodeBondUpdated, CiphernodeDeregistrationRequested, InterfoldEventData,
};
use tracing::{error, trace};

struct TicketBalanceUpdatedWithChainId(pub IBondingRegistry::TicketBalanceUpdated, pub u64);

impl From<TicketBalanceUpdatedWithChainId> for e3_events::TicketBalanceUpdated {
    fn from(value: TicketBalanceUpdatedWithChainId) -> Self {
        e3_events::TicketBalanceUpdated {
            operator: value.0.operator.to_string(),
            delta: value.0.delta,
            new_balance: value.0.newBalance,
            reason: value.0.reason,
            chain_id: value.1,
        }
    }
}

impl From<TicketBalanceUpdatedWithChainId> for InterfoldEventData {
    fn from(value: TicketBalanceUpdatedWithChainId) -> Self {
        let payload: e3_events::TicketBalanceUpdated = value.into();
        Self::from(payload)
    }
}

struct ConfigurationUpdatedWithChainId(pub IBondingRegistry::ConfigurationUpdated, pub u64);

impl From<ConfigurationUpdatedWithChainId> for e3_events::ConfigurationUpdated {
    fn from(value: ConfigurationUpdatedWithChainId) -> Self {
        let param_bytes = value.0.parameter.as_slice();
        let param_str = String::from_utf8(
            param_bytes
                .iter()
                .copied()
                .take_while(|&b| b != 0)
                .collect(),
        )
        .unwrap_or_else(|_| value.0.parameter.to_string());

        e3_events::ConfigurationUpdated {
            parameter: param_str,
            old_value: value.0.oldValue,
            new_value: value.0.newValue,
            chain_id: value.1,
        }
    }
}

impl From<ConfigurationUpdatedWithChainId> for InterfoldEventData {
    fn from(value: ConfigurationUpdatedWithChainId) -> Self {
        let payload: e3_events::ConfigurationUpdated = value.into();
        Self::from(payload)
    }
}

struct OperatorActivationChangedWithChainId(
    pub IBondingRegistry::OperatorActivationChanged,
    pub u64,
);

impl From<OperatorActivationChangedWithChainId> for e3_events::OperatorActivationChanged {
    fn from(value: OperatorActivationChangedWithChainId) -> Self {
        e3_events::OperatorActivationChanged {
            operator: value.0.operator.to_string(),
            active: value.0.active,
            chain_id: value.1,
        }
    }
}

impl From<OperatorActivationChangedWithChainId> for InterfoldEventData {
    fn from(value: OperatorActivationChangedWithChainId) -> Self {
        let payload: e3_events::OperatorActivationChanged = value.into();
        Self::from(payload)
    }
}

struct CiphernodeBondUpdatedWithChainId(pub IBondingRegistry::CiphernodeBondUpdated, pub u64);

impl From<CiphernodeBondUpdatedWithChainId> for CiphernodeBondUpdated {
    fn from(value: CiphernodeBondUpdatedWithChainId) -> Self {
        Self {
            operator: value.0.operator.to_string(),
            delta: value.0.delta,
            new_bond: value.0.newBond,
            reason: value.0.reason.into(),
            chain_id: value.1,
        }
    }
}

impl From<CiphernodeBondUpdatedWithChainId> for InterfoldEventData {
    fn from(value: CiphernodeBondUpdatedWithChainId) -> Self {
        CiphernodeBondUpdated::from(value).into()
    }
}

struct CiphernodeDeregistrationRequestedWithChainId(
    pub IBondingRegistry::CiphernodeDeregistrationRequested,
    pub u64,
);

impl From<CiphernodeDeregistrationRequestedWithChainId> for CiphernodeDeregistrationRequested {
    fn from(value: CiphernodeDeregistrationRequestedWithChainId) -> Self {
        Self {
            operator: value.0.operator.to_string(),
            unlock_at: value.0.unlockAt,
            chain_id: value.1,
        }
    }
}

impl From<CiphernodeDeregistrationRequestedWithChainId> for InterfoldEventData {
    fn from(value: CiphernodeDeregistrationRequestedWithChainId) -> Self {
        CiphernodeDeregistrationRequested::from(value).into()
    }
}

struct BondOwnerSetWithChainId(pub IBondingRegistry::BondOwnerSet, pub u64);

impl From<BondOwnerSetWithChainId> for BondOwnerSet {
    fn from(value: BondOwnerSetWithChainId) -> Self {
        Self {
            operator: value.0.operator.to_string(),
            bond_owner: value.0.bondOwner.to_string(),
            chain_id: value.1,
        }
    }
}

impl From<BondOwnerSetWithChainId> for InterfoldEventData {
    fn from(value: BondOwnerSetWithChainId) -> Self {
        BondOwnerSet::from(value).into()
    }
}

pub(crate) fn extractor(
    data: &LogData,
    topics: &[B256],
    chain_id: u64,
) -> Option<InterfoldEventData> {
    match topics.first() {
        Some(&IBondingRegistry::AdmissionPolicyUpdated::SIGNATURE_HASH) => {
            let event = IBondingRegistry::AdmissionPolicyUpdated::decode_log_data(data).ok()?;
            let policy = event.policy;
            Some(
                e3_events::AdmissionUpdated {
                    chain_id,
                    timepoint: event.timepoint.to(),
                    change: e3_events::AdmissionChange::Policy(e3_events::AdmissionPolicy {
                        cooldown_enabled: policy.cooldownEnabled,
                        admissions_paused: policy.admissionsPaused,
                        cooldown_duration: policy.cooldownDuration.to(),
                        pause_timepoint: policy.pauseTimepoint.to(),
                        pause_cooldown_enabled: policy.pauseCooldownEnabled,
                        pause_cooldown_duration: policy.pauseCooldownDuration.to(),
                    }),
                }
                .into(),
            )
        }
        Some(&IBondingRegistry::AdmissionStarted::SIGNATURE_HASH) => {
            let event = IBondingRegistry::AdmissionStarted::decode_log_data(data).ok()?;
            Some(
                e3_events::AdmissionUpdated {
                    chain_id,
                    timepoint: event.timepoint.to(),
                    change: e3_events::AdmissionChange::Started {
                        operator: event.operator.to_string(),
                    },
                }
                .into(),
            )
        }
        Some(&IBondingRegistry::TicketBalanceUpdated::SIGNATURE_HASH) => {
            let Ok(event) = IBondingRegistry::TicketBalanceUpdated::decode_log_data(data) else {
                error!("Error parsing event TicketBalanceUpdated after topic was matched!");
                return None;
            };
            Some(InterfoldEventData::from(TicketBalanceUpdatedWithChainId(
                event, chain_id,
            )))
        }
        Some(&IBondingRegistry::OperatorActivationChanged::SIGNATURE_HASH) => {
            let Ok(event) = IBondingRegistry::OperatorActivationChanged::decode_log_data(data)
            else {
                error!("Error parsing event OperatorActivationChanged after topic was matched!");
                return None;
            };
            Some(InterfoldEventData::from(
                OperatorActivationChangedWithChainId(event, chain_id),
            ))
        }
        Some(&IBondingRegistry::CiphernodeBondUpdated::SIGNATURE_HASH) => {
            let Ok(event) = IBondingRegistry::CiphernodeBondUpdated::decode_log_data(data) else {
                error!("Error parsing event CiphernodeBondUpdated after topic matched!");
                return None;
            };
            Some(CiphernodeBondUpdatedWithChainId(event, chain_id).into())
        }
        Some(&IBondingRegistry::CiphernodeDeregistrationRequested::SIGNATURE_HASH) => {
            let Ok(event) =
                IBondingRegistry::CiphernodeDeregistrationRequested::decode_log_data(data)
            else {
                error!("Error parsing CiphernodeDeregistrationRequested after topic matched!");
                return None;
            };
            Some(CiphernodeDeregistrationRequestedWithChainId(event, chain_id).into())
        }
        Some(&IBondingRegistry::ConfigurationUpdated::SIGNATURE_HASH) => {
            let Ok(event) = IBondingRegistry::ConfigurationUpdated::decode_log_data(data) else {
                error!("Error parsing event ConfigurationUpdated after topic was matched!");
                return None;
            };
            Some(InterfoldEventData::from(ConfigurationUpdatedWithChainId(
                event, chain_id,
            )))
        }
        Some(&IBondingRegistry::BondOwnerSet::SIGNATURE_HASH) => {
            let Ok(event) = IBondingRegistry::BondOwnerSet::decode_log_data(data) else {
                error!("Error parsing event BondOwnerSet after topic matched!");
                return None;
            };
            Some(BondOwnerSetWithChainId(event, chain_id).into())
        }
        _ => {
            trace!(
                topic=?topics.first(),
                "Preserving event without a typed BondingRegistry decoder"
            );
            Some(crate::domain::evm_log_observation::observe(
                "BondingRegistry",
                data,
                topics,
                chain_id,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;

    #[test]
    fn test_extractor_decodes_operator_activation_changed() {
        let event = IBondingRegistry::OperatorActivationChanged {
            operator: Address::repeat_byte(0x11),
            active: true,
        };
        let log_data = event.encode_log_data();
        let out = extractor(
            &log_data,
            &[IBondingRegistry::OperatorActivationChanged::SIGNATURE_HASH],
            55,
        );
        match out {
            Some(InterfoldEventData::OperatorActivationChanged(data)) => {
                assert!(data.active);
                assert_eq!(data.chain_id, 55);
            }
            other => panic!("expected OperatorActivationChanged, got {other:?}"),
        }
    }

    #[test]
    fn test_configuration_updated_trims_utf8_parameter() {
        // A 32-byte right-padded ascii parameter should decode to the trimmed string.
        let mut raw = [0u8; 32];
        raw[..5].copy_from_slice(b"price");
        let event = IBondingRegistry::ConfigurationUpdated {
            parameter: raw.into(),
            oldValue: alloy::primitives::U256::from(1u64),
            newValue: alloy::primitives::U256::from(2u64),
        };
        let converted: e3_events::ConfigurationUpdated =
            ConfigurationUpdatedWithChainId(event, 1).into();
        assert_eq!(converted.parameter, "price");
    }

    #[test]
    fn test_extractor_decodes_bond_owner_set() {
        let event = IBondingRegistry::BondOwnerSet {
            operator: Address::repeat_byte(0x11),
            bondOwner: Address::repeat_byte(0x22),
        };
        let log_data = event.encode_log_data();
        let out = extractor(
            &log_data,
            &[IBondingRegistry::BondOwnerSet::SIGNATURE_HASH],
            55,
        );
        match out {
            Some(InterfoldEventData::BondOwnerSet(data)) => {
                assert_eq!(data.operator, Address::repeat_byte(0x11).to_string());
                assert_eq!(data.bond_owner, Address::repeat_byte(0x22).to_string());
                assert_eq!(data.chain_id, 55);
            }
            other => panic!("expected BondOwnerSet, got {other:?}"),
        }
    }

    #[test]
    fn admission_events_preserve_chain_time_and_the_frozen_pause_policy() {
        let event = IBondingRegistry::AdmissionPolicyUpdated {
            timepoint: alloy::primitives::Uint::<48, 1>::from(100),
            policy: IBondingRegistry::AdmissionPolicy {
                cooldownEnabled: false,
                admissionsPaused: true,
                cooldownDuration: 0.try_into().unwrap(),
                pauseTimepoint: 90.try_into().unwrap(),
                pauseCooldownEnabled: true,
                pauseCooldownDuration: 259200.try_into().unwrap(),
            },
        };
        let out = extractor(
            &event.encode_log_data(),
            &[IBondingRegistry::AdmissionPolicyUpdated::SIGNATURE_HASH],
            1,
        )
        .unwrap();
        assert_eq!(
            out,
            e3_events::AdmissionUpdated {
                chain_id: 1,
                timepoint: 100,
                change: e3_events::AdmissionChange::Policy(e3_events::AdmissionPolicy {
                    cooldown_enabled: false,
                    admissions_paused: true,
                    cooldown_duration: 0,
                    pause_timepoint: 90,
                    pause_cooldown_enabled: true,
                    pause_cooldown_duration: 259200,
                }),
            }
            .into()
        );
        let started = IBondingRegistry::AdmissionStarted {
            operator: Address::repeat_byte(1),
            timepoint: 101.try_into().unwrap(),
        };
        let out = extractor(
            &started.encode_log_data(),
            &[IBondingRegistry::AdmissionStarted::SIGNATURE_HASH],
            2,
        )
        .unwrap();
        assert_eq!(
            out,
            e3_events::AdmissionUpdated {
                chain_id: 2,
                timepoint: 101,
                change: e3_events::AdmissionChange::Started {
                    operator: started.operator.to_string()
                }
            }
            .into()
        );
    }

    #[test]
    fn test_extractor_preserves_unknown_topic() {
        let log_data = LogData::default();
        assert!(matches!(
            extractor(&log_data, &[B256::ZERO], 1),
            Some(InterfoldEventData::EvmLogObserved(_))
        ));
    }
}
