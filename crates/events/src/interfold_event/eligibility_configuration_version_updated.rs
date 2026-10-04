// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use alloy::primitives::U256;
use serde::{Deserialize, Serialize};

/// The bonding registry started a new eligibility configuration version. Every operator is
/// inactive on chain until it refreshes under the new version. Each eligibility invalidation emits
/// this event: a configuration or bonding-asset change, and the node-release cutover.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EligibilityConfigurationVersionUpdated {
    pub version: U256,
    pub chain_id: u64,
}

/// An eligibility version update with its source block timestamp in seconds and log order.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EligibilityConfigurationVersionUpdatedAt {
    pub update: EligibilityConfigurationVersionUpdated,
    pub position: crate::ChainPosition,
}
