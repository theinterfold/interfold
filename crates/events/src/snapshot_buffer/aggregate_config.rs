// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use crate::AggregateId;
use std::{collections::HashMap, time::Duration};

/// Central configuration for aggregates in the WriteBuffer
#[derive(Debug, Clone)]
pub struct AggregateConfig {
    pub delays: HashMap<AggregateId, Duration>,
}

impl AggregateConfig {
    pub fn get_delay(&self, id: &AggregateId) -> Duration {
        self.delays
            .get(id)
            .cloned()
            .unwrap_or(Duration::from_micros(0))
    }
}

impl AggregateConfig {
    /// Create a new AggregateConfig with the specified delays
    pub fn new(mut delays: HashMap<AggregateId, Duration>) -> Self {
        // Always handle AggregatId of 0 with a delay of 0
        delays
            .entry(AggregateId::new(0))
            .or_insert_with(|| Duration::from_micros(0));
        Self { delays }
    }

    /// Get the indexed aggregate IDs, defaulting to [0] if no delays are configured
    pub fn indexed_ids(&self) -> Vec<usize> {
        self.delays.keys().map(|id| id.to_usize()).collect()
    }

    pub fn aggregates(&self) -> Vec<AggregateId> {
        self.delays.keys().cloned().collect()
    }
}
