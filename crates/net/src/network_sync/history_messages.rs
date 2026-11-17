// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::fmt::Debug;

use anyhow::{Context, Result};
use e3_events::AggregateId;

use crate::domain::wire::{decode_sync, encode_sync, SyncMessageKind};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum BatchCursor {
    Done,
    Next(u128),
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct EventBatch<E: Debug> {
    pub events: Vec<E>,
    pub next: BatchCursor,
    pub aggregate_id: AggregateId,
    /// Timestamp from which the responder stores this network's history live: the time when the
    /// gossip that it held during its own startup became durable. `None` while it still starts
    /// up. A responder vouches only for history at or after this time; earlier records come from
    /// its log and from its own peers.
    pub observed_from: Option<u128>,
}

impl<E: Debug> TryFrom<Vec<u8>> for EventBatch<E>
where
    E: serde::de::DeserializeOwned,
{
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        decode_sync(&value, SyncMessageKind::EventBatch).context("failed to deserialize EventBatch")
    }
}

impl<E: Debug> TryFrom<EventBatch<E>> for Vec<u8>
where
    E: serde::Serialize,
{
    type Error = anyhow::Error;

    fn try_from(value: EventBatch<E>) -> Result<Self> {
        encode_sync(SyncMessageKind::EventBatch, &value).context("failed to serialize EventBatch")
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct FetchEventsSince {
    aggregate_id: AggregateId,
    since: u128,
    limit: usize,
}

impl FetchEventsSince {
    pub fn new(aggregate_id: AggregateId, since: u128, limit: usize) -> Self {
        Self {
            aggregate_id,
            since,
            limit,
        }
    }

    pub fn aggregate_id(&self) -> AggregateId {
        self.aggregate_id
    }

    pub fn since(&self) -> u128 {
        self.since
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl TryFrom<FetchEventsSince> for Vec<u8> {
    type Error = anyhow::Error;

    fn try_from(value: FetchEventsSince) -> Result<Self> {
        encode_sync(SyncMessageKind::FetchEvents, &value)
            .context("failed to serialize FetchEventsSince")
    }
}

impl TryFrom<Vec<u8>> for FetchEventsSince {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        decode_sync(&value, SyncMessageKind::FetchEvents)
            .context("failed to deserialize FetchEventsSince")
    }
}
