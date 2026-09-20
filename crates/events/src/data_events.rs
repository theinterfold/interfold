// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    AggregateId, EventContext, EventContextAccessors, EventContextSeq, IntoKey, Sequenced,
};
use actix::Message;
use anyhow::{ensure, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotRevision {
    aggregate_id: AggregateId,
    seq: u64,
}

impl SnapshotRevision {
    pub fn aggregate_id(self) -> AggregateId {
        self.aggregate_id
    }

    pub fn seq(self) -> u64 {
        self.seq
    }
}

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

    /// Return the revision shared by every contextual write in this batch.
    ///
    /// Snapshot batches must never combine revisions or mix contextual and direct writes. Keeping
    /// this check at the storage boundary prevents an older actor snapshot from replacing state
    /// covered by a newer replay cursor.
    pub fn snapshot_revision(&self) -> Result<Option<SnapshotRevision>> {
        let mut revision = None;
        let mut saw_direct = false;

        for command in &self.0 {
            let Some(ctx) = command.ctx() else {
                saw_direct = true;
                continue;
            };
            let candidate = SnapshotRevision {
                aggregate_id: ctx.aggregate_id(),
                seq: ctx.seq(),
            };
            if let Some(current) = revision {
                ensure!(
                    current == candidate,
                    "snapshot batch combines aggregate/sequence revisions"
                );
            } else {
                revision = Some(candidate);
            }
        }

        ensure!(
            revision.is_none() || !saw_direct,
            "snapshot batch mixes contextual and direct writes"
        );
        Ok(revision)
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
#[rtype(result = "Option<Vec<u8>>")]
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
