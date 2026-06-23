// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::sync::OnceLock;

use actix::Recipient;
use e3_events::{EventStoreQueryBy, SeqAgg, TsAgg};

#[derive(Clone, Debug)]
pub struct EventStoreReader {
    query_by_seq: Recipient<EventStoreQueryBy<SeqAgg>>,
    query_by_ts: Recipient<EventStoreQueryBy<TsAgg>>,
}

impl EventStoreReader {
    pub fn new(
        ts: Recipient<EventStoreQueryBy<TsAgg>>,
        seq: Recipient<EventStoreQueryBy<SeqAgg>>,
    ) -> Self {
        Self {
            query_by_ts: ts,
            query_by_seq: seq,
        }
    }

    pub fn seq(&self) -> Recipient<EventStoreQueryBy<SeqAgg>> {
        self.query_by_seq.clone()
    }

    pub fn ts(&self) -> Recipient<EventStoreQueryBy<TsAgg>> {
        self.query_by_ts.clone()
    }
}

// Hold shared eventstore seq - this is a singleton for production only
static CACHED_EVENTSTORE_READER: OnceLock<EventStoreReader> = OnceLock::new();

/// Save the eventstore to a cache for use by socket commands. This solves the problem of reusing a
/// commitlog connection while the node is running in start mode. We can use this during node start.
/// Only the first call to this is shared.
pub fn share_eventstore_reader(store: &EventStoreReader) {
    CACHED_EVENTSTORE_READER.get_or_init(|| store.clone());
}

pub fn get_shared_eventstore() -> Option<EventStoreReader> {
    CACHED_EVENTSTORE_READER.get().cloned()
}
