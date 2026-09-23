// SPDX-License-Identifier: LGPL-3.0-only

//! Request-time bond owners, derived from the existing chain events.

use crate::domain::node_registry::StateCheckpoint;
use alloy::primitives::Address;
use anyhow::{ensure, Result};
use e3_events::BondOwnerSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const BOND_OWNER_SCHEMA_VERSION: u32 = 1;

/// A separate snapshot leaves the existing node and recovery schemas unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BondOwnerState {
    pub schema_version: u32,
    /// An entry also records that startup backfilled this chain through its snapshot cursor.
    pub chains: HashMap<u64, HashMap<Address, Vec<StateCheckpoint<Address>>>>,
}

impl Default for BondOwnerState {
    fn default() -> Self {
        Self {
            schema_version: BOND_OWNER_SCHEMA_VERSION,
            chains: HashMap::new(),
        }
    }
}

impl BondOwnerState {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == BOND_OWNER_SCHEMA_VERSION,
            "unsupported bond-owner snapshot schema {}",
            self.schema_version
        );
        Ok(())
    }

    pub fn record(&mut self, event: &BondOwnerSet, timepoint: u64) -> Result<()> {
        let operator: Address = event.operator.parse()?;
        let owner: Address = event.bond_owner.parse()?;
        ensure!(!owner.is_zero(), "bond owner must not be zero");
        let history = self
            .chains
            .entry(event.chain_id)
            .or_default()
            .entry(operator)
            .or_default();
        if let Some(last) = history.last_mut() {
            ensure!(
                last.timepoint <= timepoint,
                "bond-owner history is out of order"
            );
            if last.timepoint == timepoint {
                last.value = owner;
                return Ok(());
            }
        }
        history.push(StateCheckpoint {
            timepoint,
            value: owner,
        });
        Ok(())
    }

    pub fn owner_at(&self, chain_id: u64, operator: Address, timepoint: u64) -> Option<Address> {
        let history = self.chains.get(&chain_id)?.get(&operator)?;
        let index = history.partition_point(|checkpoint| checkpoint.timepoint <= timepoint);
        index.checked_sub(1).map(|index| history[index].value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfers_preserve_request_owners_and_chain_isolation() {
        let node = Address::from([1; 20]);
        let first = Address::from([2; 20]);
        let second = Address::from([3; 20]);
        let mut state = BondOwnerState::default();
        let mut event = BondOwnerSet {
            operator: node.to_string(),
            bond_owner: first.to_string(),
            chain_id: 1,
        };
        state.record(&event, 10).unwrap();
        state.record(&event, 10).unwrap();
        event.bond_owner = second.to_string();
        state.record(&event, 20).unwrap();
        assert_eq!(state.owner_at(1, node, 9), None);
        assert_eq!(state.owner_at(1, node, 19), Some(first));
        assert_eq!(state.owner_at(1, node, 20), Some(second));
        assert_eq!(state.owner_at(2, node, 20), None);
        let restarted: BondOwnerState =
            bincode::deserialize(&bincode::serialize(&state).unwrap()).unwrap();
        restarted.validate().unwrap();
        assert_eq!(restarted.owner_at(1, node, 19), Some(first));
        assert_eq!(restarted.owner_at(1, node, 20), Some(second));
        assert!(state.record(&event, 15).is_err());
        state.schema_version += 1;
        assert!(state.validate().is_err());
    }

    #[test]
    fn version_one_fixture_remains_readable() {
        let bytes =
            alloy::hex::decode(include_str!("../../tests/fixtures/bond-owners-v1.hex").trim())
                .unwrap();
        let state: BondOwnerState = bincode::deserialize(&bytes).unwrap();
        state.validate().unwrap();
        assert!(state.chains.is_empty());
        assert_eq!(bincode::serialize(&state).unwrap(), bytes);
    }
}
