// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::{InterfoldEvent, InterfoldEventData, SeqState, Sequenced, Unsequenced};
use crate::{traits::EventConstructorWithTimestamp, E3id, EventSource};
use actix::Message;
use serde::{Deserialize, Serialize};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct TestEvent {
    pub msg: String,
    pub entropy: u64,
    pub e3_id: Option<E3id>,
}

impl TestEvent {
    pub fn new(msg: &str, entropy: u64) -> Self {
        Self {
            msg: msg.to_owned(),
            entropy,
            e3_id: None,
        }
    }

    pub fn with_e3_id(self, id: E3id) -> Self {
        Self {
            msg: self.msg,
            entropy: self.entropy,
            e3_id: Some(id),
        }
    }
}

#[cfg(test)]
use std::fmt::{self, Display};

#[cfg(test)]
impl Display for TestEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TestEvent(msg: {})", self.msg)
    }
}

#[cfg(feature = "test-helpers")]
impl<S: SeqState> InterfoldEvent<S> {
    /// Create a test event using the TestEventBuilder struct
    pub fn test_event(label: &str) -> TestEventBuilder<Unsequenced> {
        TestEventBuilder::<Unsequenced>::new(label)
    }
}

/// Build out a test event
pub struct TestEventBuilder<S: SeqState> {
    label: String,
    seq: S::Seq,
    id: Option<u64>,
    data: Option<InterfoldEventData>,
    aggregate_id: Option<u64>,
    e3_id: Option<E3id>,
    ts: Option<u128>,
}

impl TestEventBuilder<Unsequenced> {
    /// Create a new test event
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_owned(),
            seq: (),
            id: None,
            aggregate_id: None,
            data: None,
            e3_id: None,
            ts: None,
        }
    }

    /// make it a sequenced event
    pub fn seq(self, seq: u64) -> TestEventBuilder<Sequenced> {
        TestEventBuilder::<Sequenced> {
            seq,
            label: self.label,
            id: self.id,
            data: self.data,
            aggregate_id: self.aggregate_id,
            e3_id: self.e3_id,
            ts: self.ts,
        }
    }
}

impl<S: SeqState> TestEventBuilder<S> {
    /// Add an e3_id based on a u64 this takes preference over e3_id()
    pub fn id(mut self, id: u64) -> Self {
        self.id = Some(id);
        self
    }

    /// Ensure the event holds the given aggregate_id this takes preference over e3_id()
    pub fn aggregate_id(mut self, id: u64) -> Self {
        self.aggregate_id = Some(id);
        self
    }

    /// Ensure the event holds the given e3_id.
    pub fn e3_id(mut self, e3_id: E3id) -> Self {
        self.e3_id = Some(e3_id);
        self
    }

    /// Ensure the event holds a ts
    pub fn ts(mut self, ts: u128) -> Self {
        self.ts = Some(ts);
        self
    }

    /// Ensure the event holds the given InterfoldEventData object. This overrides all other params
    /// aiside from seq(n)
    pub fn data(mut self, data: impl Into<InterfoldEventData>) -> Self {
        self.data = Some(data.into());
        self
    }

    fn get_built_event(self) -> InterfoldEvent<Unsequenced> {
        let event = self.data.unwrap_or(
            TestEvent {
                msg: self.label,
                entropy: self.id.unwrap_or(0),
                e3_id: resolve_e3_id(self.e3_id, self.id, self.aggregate_id),
            }
            .into(),
        );

        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            event,
            None,
            self.ts.unwrap_or(0),
            None,
            EventSource::Evm,
        )
    }
}

impl TestEventBuilder<Unsequenced> {
    /// Build the event
    pub fn build(self) -> InterfoldEvent<Unsequenced> {
        self.get_built_event()
    }
}

impl TestEventBuilder<Sequenced> {
    /// Build the event
    pub fn build(self) -> InterfoldEvent<Sequenced> {
        let seq = self.seq;
        let unseq = self.get_built_event();
        unseq.into_sequenced(seq)
    }
}

fn resolve_e3_id(e3_id: Option<E3id>, id: Option<u64>, aggregate_id: Option<u64>) -> Option<E3id> {
    match (e3_id, id, aggregate_id) {
        (Some(_), Some(id), Some(agg)) if agg != 0 => Some(E3id::new(id.to_string(), agg)),
        (Some(e3), Some(id), _) => Some(E3id::new(id.to_string(), e3.chain_id())),
        (Some(e3), _, Some(agg)) if agg != 0 => Some(E3id::new(e3.e3_id(), agg)),
        (None, Some(id), Some(agg)) if agg != 0 => Some(E3id::new(id.to_string(), agg)),
        (e3, _, _) => e3,
    }
}
