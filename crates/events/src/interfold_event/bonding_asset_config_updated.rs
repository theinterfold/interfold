// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use alloy::primitives::U256;
use serde::{Deserialize, Serialize};

/// The bonding registry set its ticket and ciphernode-bond assets, the ticket price and the
/// required bond. The same transaction then emits `EligibilityConfigurationVersionUpdated`.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct BondingAssetConfigUpdated {
    pub ticket_token: String,
    pub ciphernode_bond_token: String,
    pub ticket_price: U256,
    pub required_ciphernode_bond: U256,
    pub expected_ticket_decimals: u8,
    pub expected_ciphernode_bond_decimals: u8,
    pub configuration_version: u64,
    pub chain_id: u64,
}

/// A bonding-asset update with its source block timestamp in seconds and log order.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct BondingAssetConfigUpdatedAt {
    pub config: BondingAssetConfigUpdated,
    pub position: crate::ChainPosition,
}
