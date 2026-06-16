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
                "Unknown event was received by SlashingManager.sol parser but was ignored"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_extractor_ignores_unknown_topic() {
        let log_data = LogData::default();
        assert!(extractor(&log_data, &[B256::ZERO], 1).is_none());
        assert!(extractor(&log_data, &[], 1).is_none());
    }
}
