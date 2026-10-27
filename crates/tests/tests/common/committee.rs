// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_events::{BusHandle, CiphernodeAdded, EventPublisher, InterfoldEventData};

/// Synthetic registration events, not peer authorization or chain finality.
#[derive(Clone, Debug)]
pub struct AddToCommittee {
    bus: BusHandle,
    count: usize,
    chain_id: u64,
}

impl AddToCommittee {
    pub fn new(bus: &BusHandle, chain_id: u64) -> Self {
        Self {
            bus: bus.clone(),
            chain_id,
            count: 0,
        }
    }

    pub async fn add(&mut self, address: &str) -> Result<InterfoldEventData> {
        let evt = CiphernodeAdded {
            chain_id: self.chain_id,
            address: address.to_owned(),
            index: self.count,
            num_nodes: self.count + 1,
        };
        self.count += 1;
        self.bus.publish_without_context(evt.clone())?;
        Ok(evt.into())
    }
}
