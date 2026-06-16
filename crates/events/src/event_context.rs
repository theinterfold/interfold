// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{fmt, ops::Deref};

use serde::{Deserialize, Serialize};

use crate::{
    E3id, EventContextAccessors, EventContextSeq, EventId, InterfoldEventData, SeqState, Sequenced,
    Unsequenced,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventSource {
    Local,
    Net,
    Evm,
}

#[derive(Clone, Copy, Debug, PartialEq, Ord, PartialOrd, Eq, Hash, Serialize, Deserialize)]
pub struct AggregateId(usize);

impl AggregateId {
    pub fn new(value: usize) -> Self {
        Self(value)
    }

    pub fn to_usize(&self) -> usize {
        self.0
    }

    /// Create AggregateId from Option<chain_id>
    /// None → AggregateId(0), Some(chain_id) → AggregateId(chain_id)
    pub fn from_chain_id(chain_id: Option<u64>) -> Self {
        match chain_id {
            None => Self::new(0),
            Some(id) => Self::new(id.try_into().unwrap_or(0)),
        }
    }

    /// Convert back to Option<chain_id>
    /// AggregateId(0) → None, otherwise → Some(chain_id)
    pub fn to_chain_id(&self) -> Option<u64> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0 as u64)
        }
    }
}

impl From<Option<E3id>> for AggregateId {
    fn from(value: Option<E3id>) -> Self {
        let chain_id = value.map(|e3_id| e3_id.chain_id());
        Self::from_chain_id(chain_id)
    }
}

impl Deref for AggregateId {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for AggregateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventContext<S: SeqState> {
    id: EventId,
    causation_id: EventId,
    origin_id: EventId,
    seq: S::Seq,
    ts: u128,
    aggregate_id: AggregateId,
    block: Option<u64>,
    source: EventSource,
}

impl EventContext<Unsequenced> {
    pub fn new(
        id: EventId,
        causation_id: EventId,
        origin_id: EventId,
        ts: u128,
        aggregate_id: AggregateId,
        block: Option<u64>,
        source: EventSource,
    ) -> Self {
        Self {
            id,
            causation_id,
            origin_id,
            seq: (),
            ts,
            aggregate_id,
            block,
            source,
        }
    }

    pub fn new_origin(
        id: EventId,
        ts: u128,
        aggregate_id: AggregateId,
        block: Option<u64>,
        source: EventSource,
    ) -> Self {
        Self::new(id, id, id, ts, aggregate_id, block, source)
    }

    pub fn from_cause(
        id: EventId,
        cause: EventContext<Sequenced>,
        ts: u128,
        aggregate_id: AggregateId,
        block: Option<u64>,
        source: EventSource,
    ) -> Self {
        EventContext::new(
            id,
            cause.id(),
            cause.origin_id(),
            ts,
            aggregate_id,
            cause.block.max(block), // block watermark
            source,
        )
    }

    pub fn with_ts(mut self, ts: u128) -> Self {
        self.ts = ts;
        self
    }

    pub fn with_aggregate(mut self, aggregate_id: AggregateId) -> Self {
        self.aggregate_id = aggregate_id;
        self
    }

    pub fn sequence(self, value: u64) -> EventContext<Sequenced> {
        EventContext::<Sequenced> {
            seq: value,
            id: self.id,
            causation_id: self.causation_id,
            origin_id: self.origin_id,
            ts: self.ts,
            aggregate_id: self.aggregate_id,
            block: self.block,
            source: self.source,
        }
    }
}

impl From<InterfoldEventData> for EventContext<Unsequenced> {
    fn from(value: InterfoldEventData) -> Self {
        let id = EventId::hash(value);
        EventContext::<Unsequenced>::new_origin(
            id,
            0,
            AggregateId::new(0),
            Some(0),
            EventSource::Local,
        )
    }
}

impl<S: SeqState> EventContextAccessors for EventContext<S> {
    fn id(&self) -> EventId {
        self.id
    }

    fn causation_id(&self) -> EventId {
        self.causation_id
    }

    fn origin_id(&self) -> EventId {
        self.origin_id
    }

    fn ts(&self) -> u128 {
        self.ts
    }

    fn aggregate_id(&self) -> AggregateId {
        self.aggregate_id
    }

    fn block(&self) -> Option<u64> {
        self.block
    }

    fn source(&self) -> EventSource {
        self.source
    }

    fn with_source(mut self, source: EventSource) -> Self {
        self.source = source;
        self
    }
}

impl EventContextSeq for EventContext<Sequenced> {
    fn seq(&self) -> u64 {
        self.seq
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        event_context::{AggregateId, EventContext},
        EventId, EventSource,
    };

    #[test]
    fn test_event_context_cycle() {
        let mut events = vec![];

        let one = EventContext::new(
            EventId::hash(1),
            EventId::hash(1),
            EventId::hash(1),
            1,
            AggregateId::new(1),
            None,
            EventSource::Local,
        )
        .sequence(1);
        events.push(one.clone());

        let two = EventContext::from_cause(
            EventId::hash(2),
            one,
            2,
            AggregateId::new(1),
            None,
            EventSource::Local,
        )
        .sequence(2);
        events.push(two.clone());

        let three = EventContext::from_cause(
            EventId::hash(3),
            two,
            3,
            AggregateId::new(1),
            None,
            EventSource::Local,
        )
        .sequence(3);
        events.push(three.clone());

        assert_eq!(
            events,
            vec![
                EventContext {
                    seq: 1,
                    id: EventId::hash(1),
                    origin_id: EventId::hash(1),
                    causation_id: EventId::hash(1),
                    ts: 1,
                    aggregate_id: AggregateId::new(1),
                    block: None,
                    source: EventSource::Local
                },
                EventContext {
                    seq: 2,
                    id: EventId::hash(2),
                    origin_id: EventId::hash(1),
                    causation_id: EventId::hash(1),
                    ts: 2,
                    aggregate_id: AggregateId::new(1),
                    block: None,
                    source: EventSource::Local
                },
                EventContext {
                    seq: 3,
                    id: EventId::hash(3),
                    origin_id: EventId::hash(1),
                    causation_id: EventId::hash(2),
                    ts: 3,
                    aggregate_id: AggregateId::new(1),
                    block: None,
                    source: EventSource::Local
                },
            ]
        )
    }
}
