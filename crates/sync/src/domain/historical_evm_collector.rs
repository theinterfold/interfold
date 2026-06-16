// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_events::{EvmEventConfig, HistoricalEvmEventsReceived, InterfoldEvent, Unsequenced};
use std::collections::HashSet;

/// Outcome of recording one batch of historical EVM events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectOutcome {
    /// The batch was for an expected, not-yet-seen chain and was recorded.
    Recorded {
        chains_received: usize,
        chains_expected: usize,
    },
    /// The batch was for an unexpected or already-seen chain and was ignored.
    Skipped,
}

/// Pure accumulator tracking which chains have reported their historical EVM events.
///
/// The async recv/timeout loop lives in the actor; this struct owns the "have all expected
/// chains reported yet?" decision so it can be unit tested without a channel.
pub struct HistoricalEvmCollector {
    expected: HashSet<u64>,
    received: HashSet<u64>,
    results: Vec<InterfoldEvent<Unsequenced>>,
}

impl HistoricalEvmCollector {
    pub fn new(config: &EvmEventConfig) -> Self {
        Self {
            expected: config.chains(),
            received: HashSet::new(),
            results: Vec::new(),
        }
    }

    /// True once every expected chain has reported.
    pub fn is_complete(&self) -> bool {
        self.received.len() >= self.expected.len()
    }

    /// Record a received batch, appending its events when the chain is expected and unseen.
    pub fn record(&mut self, msg: &mut HistoricalEvmEventsReceived) -> CollectOutcome {
        if self.expected.contains(&msg.chain_id) && !self.received.contains(&msg.chain_id) {
            self.received.insert(msg.chain_id);
            self.results.append(&mut msg.events);
            CollectOutcome::Recorded {
                chains_received: self.received.len(),
                chains_expected: self.expected.len(),
            }
        } else {
            CollectOutcome::Skipped
        }
    }

    /// Chains still outstanding (expected but not yet received).
    pub fn remaining(&self) -> Vec<u64> {
        self.expected.difference(&self.received).copied().collect()
    }

    /// Consume the collector and return the accumulated events.
    pub fn into_events(self) -> Vec<InterfoldEvent<Unsequenced>> {
        self.results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{EvmEventConfig, EvmEventConfigChain};
    use std::collections::BTreeMap;

    fn config_for(chains: &[u64]) -> EvmEventConfig {
        let map: BTreeMap<u64, EvmEventConfigChain> = chains
            .iter()
            .map(|c| (*c, EvmEventConfigChain::new(0)))
            .collect();
        EvmEventConfig::from_config(map)
    }

    fn batch(chain_id: u64, count: usize) -> HistoricalEvmEventsReceived {
        let events = (0..count)
            .map(|i| {
                InterfoldEvent::<Unsequenced>::test_event("evt")
                    .ts(i as u128)
                    .build()
            })
            .collect();
        HistoricalEvmEventsReceived::new(events, chain_id)
    }

    #[test]
    fn records_expected_chains_and_completes() {
        let mut collector = HistoricalEvmCollector::new(&config_for(&[1, 2]));
        assert!(!collector.is_complete());

        let mut b1 = batch(1, 3);
        assert_eq!(
            collector.record(&mut b1),
            CollectOutcome::Recorded {
                chains_received: 1,
                chains_expected: 2,
            }
        );
        assert!(!collector.is_complete());
        assert_eq!(collector.remaining(), vec![2]);

        let mut b2 = batch(2, 2);
        assert_eq!(
            collector.record(&mut b2),
            CollectOutcome::Recorded {
                chains_received: 2,
                chains_expected: 2,
            }
        );
        assert!(collector.is_complete());
        assert!(collector.remaining().is_empty());
        assert_eq!(collector.into_events().len(), 5);
    }

    #[test]
    fn skips_unexpected_and_duplicate_chains() {
        let mut collector = HistoricalEvmCollector::new(&config_for(&[1]));

        // unexpected chain
        let mut unexpected = batch(99, 4);
        assert_eq!(collector.record(&mut unexpected), CollectOutcome::Skipped);
        assert!(!collector.is_complete());

        // first record of chain 1
        let mut first = batch(1, 2);
        assert!(matches!(
            collector.record(&mut first),
            CollectOutcome::Recorded { .. }
        ));

        // duplicate chain 1
        let mut dup = batch(1, 7);
        assert_eq!(collector.record(&mut dup), CollectOutcome::Skipped);

        assert!(collector.is_complete());
        assert_eq!(collector.into_events().len(), 2);
    }
}
