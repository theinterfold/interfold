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
use e3_events::InterfoldEventData;
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

pub(crate) fn extractor(
    data: &LogData,
    topics: &[B256],
    chain_id: u64,
) -> Option<InterfoldEventData> {
    match topics.first() {
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
        Some(&IBondingRegistry::ConfigurationUpdated::SIGNATURE_HASH) => {
            let Ok(event) = IBondingRegistry::ConfigurationUpdated::decode_log_data(data) else {
                error!("Error parsing event ConfigurationUpdated after topic was matched!");
                return None;
            };
            Some(InterfoldEventData::from(ConfigurationUpdatedWithChainId(
                event, chain_id,
            )))
        }
        _ => {
            trace!(
                topic=?topics.first(),
                "Unknown event was received by BondingRegistry.sol parser but was ignored"
            );
            None
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
    fn test_extractor_ignores_unknown_topic() {
        let log_data = LogData::default();
        assert!(extractor(&log_data, &[B256::ZERO], 1).is_none());
    }
}
