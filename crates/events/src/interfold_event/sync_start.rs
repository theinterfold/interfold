// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::AggregateId;
use crate::{EvmEventConfig, EvmEventConfigChain};
use actix::{Message, Recipient};
use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{self, Display};

use super::InterfoldEvent;
use super::Unsequenced;

/// Dispatched by the Sync actor when initial data is read and the sync process needs to be started
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct HistoricalEvmSyncStart {
    /// The initial information for reading historical events from chains. This is generated from
    /// from persisted information
    pub evm_config: EvmEventConfig,

    #[serde(skip)]
    /// We include the sender here so that the evm can communicate directly with the sync actor
    pub sender: Option<Recipient<HistoricalEvmEventsReceived>>, // Must be Option to allow serde deserialize on
                                                                // InterfoldEvent as Default is required to be
                                                                // implemented this is fine as this event is never
                                                                // shared
}

impl HistoricalEvmSyncStart {
    pub fn new(
        sender: impl Into<Recipient<HistoricalEvmEventsReceived>>,
        evm_config: EvmEventConfig,
    ) -> Self {
        Self {
            sender: Some(sender.into()),
            evm_config,
        }
    }

    pub fn get_evm_config(&self, chain_id: u64) -> Result<EvmEventConfigChain> {
        Ok(self
            .evm_config
            .get(&chain_id)
            .context("No config found for chain")?
            .clone())
    }
}

impl Display for HistoricalEvmSyncStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Dispatched by the Sync actor when initial data is read and the sync process needs to be started
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct HistoricalNetSyncStart {
    pub since: BTreeMap<AggregateId, u128>,
}

impl HistoricalNetSyncStart {
    pub fn new(since: BTreeMap<AggregateId, u128>) -> Self {
        Self { since }
    }
}

impl Display for HistoricalNetSyncStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct HistoricalEvmEventsReceived {
    pub events: Vec<InterfoldEvent<Unsequenced>>,
    pub chain_id: u64,
}

impl HistoricalEvmEventsReceived {
    pub fn new(events: Vec<InterfoldEvent<Unsequenced>>, chain_id: u64) -> Self {
        Self { events, chain_id }
    }
}

impl Display for HistoricalEvmEventsReceived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct HistoricalNetSyncEventsReceived {
    pub events: Vec<InterfoldEvent<Unsequenced>>,
}

impl HistoricalNetSyncEventsReceived {
    pub fn new(events: Vec<InterfoldEvent<Unsequenced>>) -> Self {
        Self { events }
    }
}

impl Display for HistoricalNetSyncEventsReceived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
