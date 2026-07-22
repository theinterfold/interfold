// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{EventContext, IntoKey, Sequenced};
use actix::Message;
use anyhow::Result;

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash)]
#[rtype(result = "()")]
pub struct Insert {
    key: Vec<u8>,
    value: Vec<u8>,
    ctx: Option<EventContext<Sequenced>>,
}

impl Insert {
    pub fn new<K: IntoKey>(key: K, value: Vec<u8>) -> Self {
        Self {
            key: key.into_key(),
            value,
            ctx: None,
        }
    }

    pub fn new_with_context<K: IntoKey>(
        key: K,
        value: Vec<u8>,
        ctx: EventContext<Sequenced>,
    ) -> Self {
        Self {
            key: key.into_key(),
            value,
            ctx: Some(ctx),
        }
    }

    pub fn key(&self) -> &Vec<u8> {
        &self.key
    }

    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    pub fn ctx(&self) -> Option<&EventContext<Sequenced>> {
        self.ctx.as_ref()
    }
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash)]
#[rtype(result = "Result<()>")]
pub struct InsertBatch(pub Vec<Insert>);
impl InsertBatch {
    pub fn new(commands: Vec<Insert>) -> Self {
        Self(commands)
    }

    pub fn commands(&self) -> &Vec<Insert> {
        &self.0
    }
}

/// Atomically insert every command only when all target keys are absent.
///
/// Returns `true` when the batch was inserted and `false` when at least one key
/// already existed. Storage failures are returned to the caller.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash)]
#[rtype(result = "Result<bool>")]
pub struct InsertBatchIfAbsent(pub Vec<Insert>);

impl InsertBatchIfAbsent {
    pub fn new(commands: Vec<Insert>) -> Self {
        Self(commands)
    }

    pub fn commands(&self) -> &[Insert] {
        &self.0
    }
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash)]
#[rtype(result = "Result<()>")]
pub struct InsertSync(pub Vec<u8>, pub Vec<u8>);
impl InsertSync {
    pub fn new<K: IntoKey>(key: K, value: Vec<u8>) -> Self {
        Self(key.into_key(), value)
    }

    pub fn key(&self) -> &Vec<u8> {
        &self.0
    }

    pub fn value(&self) -> &Vec<u8> {
        &self.1
    }
}

impl From<InsertSync> for Insert {
    fn from(value: InsertSync) -> Self {
        Insert::new(value.key(), value.value().clone())
    }
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash)]
#[rtype(result = "Result<Option<Vec<u8>>>")]
pub struct Get(pub Vec<u8>);
impl Get {
    pub fn new<K: IntoKey>(key: K) -> Self {
        Self(key.into_key())
    }

    pub fn key(&self) -> &Vec<u8> {
        &self.0
    }
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash)]
#[rtype(result = "()")]
pub struct Remove(pub Vec<u8>);
impl Remove {
    pub fn new<K: IntoKey>(key: K) -> Self {
        Self(key.into_key())
    }

    pub fn key(&self) -> &Vec<u8> {
        &self.0
    }
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct Flush;
