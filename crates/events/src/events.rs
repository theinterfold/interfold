// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::collections::HashMap;

use actix::{Message, Recipient};

use crate::{AggregateId, CorrelationId, EventSource, InterfoldEvent, Sequenced, Unsequenced};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventStoreFilter {
    Source(EventSource),
}

/// Direct event received by the EventStore to store an event
#[derive(Message, Debug)]
#[rtype("()")]
pub struct StoreEventRequested {
    pub event: InterfoldEvent<Unsequenced>,
    pub sender: Recipient<StoreEventResponse>,
}

impl StoreEventRequested {
    pub fn new(
        event: InterfoldEvent<Unsequenced>,
        sender: impl Into<Recipient<StoreEventResponse>>,
    ) -> Self {
        Self {
            event,
            sender: sender.into(),
        }
    }
}

/// The response of a request to get all EventStore events by either sequence or timestamp
#[derive(Message, Debug)]
#[rtype("()")]
pub struct EventStoreQueryResponse {
    id: CorrelationId,
    events: Vec<InterfoldEvent<Sequenced>>,
}

impl EventStoreQueryResponse {
    pub fn new(id: CorrelationId, events: Vec<InterfoldEvent>) -> Self {
        Self { id, events }
    }

    pub fn into_events(self) -> Vec<InterfoldEvent> {
        self.events
    }

    pub fn id(&self) -> CorrelationId {
        self.id
    }
}

/// Direct event received by the Sequencer once an event has been stored
#[derive(Message, Debug)]
#[rtype("()")]
pub struct StoreEventResponse(pub InterfoldEvent<Sequenced>);

impl StoreEventResponse {
    pub fn into_event(self) -> InterfoldEvent<Sequenced> {
        self.0
    }
}

/// Trait for various EventStore query types
pub trait QueryKind {
    type Shape: Send;
}

/// Query by aggregated sequence
#[derive(Debug)]
pub struct SeqAgg;
impl QueryKind for SeqAgg {
    type Shape = HashMap<AggregateId, u64>;
}

/// Query by aggregated timestamp
#[derive(Debug)]
pub struct TsAgg;
impl QueryKind for TsAgg {
    type Shape = HashMap<AggregateId, u128>;
}

/// Query by timestamp
pub struct Ts;
impl QueryKind for Ts {
    type Shape = u128;
}

/// Query by seq
pub struct Seq;
impl QueryKind for Seq {
    type Shape = u64;
}

#[derive(Message, Debug)]
#[rtype("()")]
pub struct EventStoreQueryBy<Q: QueryKind> {
    correlation_id: CorrelationId,
    query: Q::Shape,
    sender: Recipient<EventStoreQueryResponse>,
    limit: Option<u64>,
    filter: Option<EventStoreFilter>,
}

impl EventStoreQueryBy<SeqAgg> {
    pub fn new(
        correlation_id: CorrelationId,
        query: HashMap<AggregateId, u64>,
        sender: impl Into<Recipient<EventStoreQueryResponse>>,
    ) -> Self {
        Self {
            correlation_id,
            query,
            sender: sender.into(),
            limit: None,
            filter: None,
        }
    }

    pub fn query(&self) -> &HashMap<AggregateId, u64> {
        &self.query
    }

    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    pub fn filter(&self) -> Option<&EventStoreFilter> {
        self.filter.as_ref()
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_filter(mut self, filter: EventStoreFilter) -> Self {
        self.filter = Some(filter);
        self
    }
}

impl EventStoreQueryBy<TsAgg> {
    pub fn new(
        correlation_id: CorrelationId,
        query: HashMap<AggregateId, u128>,
        sender: impl Into<Recipient<EventStoreQueryResponse>>,
    ) -> Self {
        Self {
            correlation_id,
            query,
            sender: sender.into(),
            limit: None,
            filter: None,
        }
    }

    pub fn query(&self) -> &HashMap<AggregateId, u128> {
        &self.query
    }

    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    pub fn filter(&self) -> Option<&EventStoreFilter> {
        self.filter.as_ref()
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_filter(mut self, filter: EventStoreFilter) -> Self {
        self.filter = Some(filter);
        self
    }
}

impl EventStoreQueryBy<Ts> {
    pub fn new(
        correlation_id: CorrelationId,
        query: u128,
        sender: impl Into<Recipient<EventStoreQueryResponse>>,
    ) -> Self {
        Self {
            correlation_id,
            query,
            sender: sender.into(),
            limit: None,
            filter: None,
        }
    }

    pub fn query(&self) -> u128 {
        self.query
    }

    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    pub fn filter(&self) -> Option<&EventStoreFilter> {
        self.filter.as_ref()
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_filter(mut self, filter: EventStoreFilter) -> Self {
        self.filter = Some(filter);
        self
    }
}

impl EventStoreQueryBy<Seq> {
    pub fn new(
        correlation_id: CorrelationId,
        query: u64,
        sender: impl Into<Recipient<EventStoreQueryResponse>>,
    ) -> Self {
        Self {
            correlation_id,
            query,
            sender: sender.into(),
            limit: None,
            filter: None,
        }
    }

    pub fn query(&self) -> u64 {
        self.query
    }

    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    pub fn filter(&self) -> Option<&EventStoreFilter> {
        self.filter.as_ref()
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_filter(mut self, filter: EventStoreFilter) -> Self {
        self.filter = Some(filter);
        self
    }
}

impl<Q: QueryKind> EventStoreQueryBy<Q> {
    pub fn id(&self) -> CorrelationId {
        self.correlation_id
    }

    pub fn sender(self) -> Recipient<EventStoreQueryResponse> {
        self.sender
    }

    pub fn with_options(mut self, limit: Option<u64>, filter: Option<EventStoreFilter>) -> Self {
        if let Some(l) = limit {
            self.limit = Some(l);
        }
        if let Some(f) = filter {
            self.filter = Some(f);
        }
        self
    }
}
