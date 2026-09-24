// SPDX-License-Identifier: LGPL-3.0-only

use crate::hlc::HlcTimestamp;
use serde::{Deserialize, Serialize};

/// Source block time and log order, independent of the event bus clock.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ChainPosition {
    /// Block timestamp in seconds, matching the on-chain checkpoint clock.
    pub timepoint: u64,
    pub log_index: u32,
}

impl ChainPosition {
    pub const fn new(timepoint: u64, log_index: u32) -> Self {
        Self {
            timepoint,
            log_index,
        }
    }

    /// Decode the raw EVM log timestamp before the event bus merges its clock.
    pub fn from_log_timestamp(timestamp: u128) -> Self {
        let source = HlcTimestamp::from_u128(timestamp);
        Self::new(source.ts / 1_000_000, source.counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_time_is_in_seconds_and_preserves_log_order() {
        let timestamp = HlcTimestamp::new(42_000_000, 7, 1).to_u128();
        assert_eq!(
            ChainPosition::from_log_timestamp(timestamp),
            ChainPosition::new(42, 7)
        );
        assert!(ChainPosition::new(42, 7) < ChainPosition::new(42, 8));
        assert!(ChainPosition::new(42, 8) < ChainPosition::new(43, 0));
    }

    #[test]
    fn encoding_matches_the_existing_timepoint_and_log_index_pair() {
        let bytes = bincode::serialize(&(42_u64, 7_u32)).unwrap();
        let position = ChainPosition::new(42, 7);
        assert_eq!(bincode::serialize(&position).unwrap(), bytes);
        assert_eq!(
            bincode::deserialize::<ChainPosition>(&bytes).unwrap(),
            position
        );
    }

    #[test]
    fn positioned_event_keeps_its_existing_bincode_layout() {
        use crate::{ConfigurationUpdated, ConfigurationUpdatedAt};
        use alloy::primitives::U256;

        let configuration = ConfigurationUpdated {
            parameter: "ticketPrice".into(),
            old_value: U256::from(10),
            new_value: U256::from(20),
            chain_id: 1,
        };
        let flat = bincode::serialize(&(configuration.clone(), 42_u64, 7_u32)).unwrap();
        let event = ConfigurationUpdatedAt {
            configuration,
            position: ChainPosition::new(42, 7),
        };
        assert_eq!(bincode::serialize(&event).unwrap(), flat);
        assert_eq!(
            bincode::deserialize::<ConfigurationUpdatedAt>(&flat).unwrap(),
            event
        );
    }
}
