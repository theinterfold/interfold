// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::ops::Deref;

use actix::Message;
use serde::{Deserialize, Serialize};

use crate::{
    event_context::{AggregateId, EventContext},
    EventContextAccessors, EventContextSeq, EventId, EventSource,
};

use super::Sequenced;

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct TypedEvent<T> {
    inner: T,
    ctx: EventContext<Sequenced>,
}

impl<T> TypedEvent<T> {
    pub fn new(inner: T, ctx: impl Into<EventContext<Sequenced>>) -> Self {
        Self {
            inner,
            ctx: ctx.into(),
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn get_ctx(&self) -> &EventContext<Sequenced> {
        &self.ctx
    }

    pub fn into_components(self) -> (T, EventContext<Sequenced>) {
        (self.inner, self.ctx)
    }
}

impl<T> Deref for TypedEvent<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> EventContextAccessors for TypedEvent<T> {
    fn id(&self) -> EventId {
        self.ctx.id()
    }

    fn ts(&self) -> u128 {
        self.ctx.ts()
    }

    fn origin_id(&self) -> EventId {
        self.ctx.origin_id()
    }

    fn causation_id(&self) -> EventId {
        self.ctx.causation_id()
    }

    fn aggregate_id(&self) -> AggregateId {
        self.ctx.aggregate_id()
    }

    fn block(&self) -> Option<u64> {
        self.ctx.block()
    }

    fn source(&self) -> EventSource {
        self.ctx.source()
    }
    fn with_source(mut self, source: EventSource) -> Self {
        self.ctx = self.ctx.with_source(source);
        self
    }
}

impl<T> EventContextSeq for TypedEvent<T> {
    fn seq(&self) -> u64 {
        self.ctx.seq()
    }
}

impl<T> From<(T, &EventContext<Sequenced>)> for TypedEvent<T> {
    fn from(value: (T, &EventContext<Sequenced>)) -> Self {
        Self {
            inner: value.0,
            ctx: value.1.clone(),
        }
    }
}
