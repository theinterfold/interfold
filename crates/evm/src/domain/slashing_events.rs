// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure translation of `SlashingManager.sol` logs into `InterfoldEventData`.

use crate::contracts::ISlashingManager;
use alloy::{
    primitives::{LogData, B256, U256},
    sol_types::SolEvent,
};
use e3_events::{E3id, InterfoldEventData};
use tracing::{error, info, trace};

/// Convert a U256 to u128, returning None if the value overflows.
fn safe_u256_to_u128(val: U256) -> Option<u128> {
    if val > U256::from(u128::MAX) {
        None
    } else {
        Some(val.to::<u128>())
    }
}

pub(crate) fn extractor(
    data: &LogData,
    topics: &[B256],
    chain_id: u64,
) -> Option<InterfoldEventData> {
    match topics.first() {
        Some(&ISlashingManager::SlashExecuted::SIGNATURE_HASH) => {
            let Ok(event) = ISlashingManager::SlashExecuted::decode_log_data(data) else {
                error!("Error parsing event SlashExecuted after topic was matched!");
                return None;
            };
            info!(
                "SlashExecuted event received: proposal_id={}, e3_id={}, operator={}, reason={:?}, ticket={}, license={}",
                event.proposalId, event.e3Id, event.operator, event.reason, event.ticketAmount, event.licenseAmount
            );
            Some(InterfoldEventData::from(e3_events::SlashExecuted {
                e3_id: E3id::new(event.e3Id.to_string(), chain_id),
                proposal_id: match safe_u256_to_u128(event.proposalId) {
                    Some(v) => v,
                    None => {
                        error!(
                            "SlashExecuted proposalId overflows u128: {}",
                            event.proposalId
                        );
                        return None;
                    }
                },
                operator: event.operator,
                reason: event.reason.into(),
                ticket_amount: match safe_u256_to_u128(event.ticketAmount) {
                    Some(v) => v,
                    None => {
                        error!(
                            "SlashExecuted ticketAmount overflows u128: {}",
                            event.ticketAmount
                        );
                        return None;
                    }
                },
                license_amount: match safe_u256_to_u128(event.licenseAmount) {
                    Some(v) => v,
                    None => {
                        error!(
                            "SlashExecuted licenseAmount overflows u128: {}",
                            event.licenseAmount
                        );
                        return None;
                    }
                },
            }))
        }
        _ => {
            trace!(
                topic=?topics.first(),
                "Preserving event without a typed SlashingManager decoder"
            );
            Some(crate::domain::evm_log_observation::observe(
                "SlashingManager",
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
    fn test_safe_u256_to_u128_within_range() {
        assert_eq!(safe_u256_to_u128(U256::from(123u64)), Some(123u128));
        assert_eq!(safe_u256_to_u128(U256::from(u128::MAX)), Some(u128::MAX));
    }

    #[test]
    fn test_safe_u256_to_u128_overflow() {
        let too_big = U256::from(u128::MAX) + U256::from(1u64);
        assert_eq!(safe_u256_to_u128(too_big), None);
    }

    #[test]
    fn test_extractor_preserves_unknown_topic() {
        let log_data = LogData::default();
        assert!(matches!(
            extractor(&log_data, &[B256::ZERO], 1),
            Some(InterfoldEventData::EvmLogObserved(_))
        ));
        assert!(matches!(
            extractor(&log_data, &[], 1),
            Some(InterfoldEventData::EvmLogObserved(_))
        ));
    }

    #[test]
    fn test_extractor_matches_current_slash_executed_signature() {
        let event = ISlashingManager::SlashExecuted {
            proposalId: U256::from(3),
            e3Id: U256::from(9),
            operator: Address::repeat_byte(0x44),
            reason: B256::repeat_byte(0x55),
            ticketAmount: U256::from(100),
            licenseAmount: U256::from(200),
            executed: true,
            lane: 1,
        };
        let log = event.encode_log_data();
        let out = extractor(&log, log.topics(), 31337);
        match out {
            Some(InterfoldEventData::SlashExecuted(event)) => {
                assert_eq!(event.e3_id, E3id::new("9", 31337));
                assert_eq!(event.ticket_amount, 100);
                assert_eq!(event.license_amount, 200);
            }
            other => panic!("expected SlashExecuted, got {other:?}"),
        }
    }
}
