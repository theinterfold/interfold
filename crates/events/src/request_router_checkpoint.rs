// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{AggregateId, E3id};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Self-consistent request-router recovery state and its covered event-log cursors.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RequestRouterCheckpoint {
    pub contexts: Vec<E3id>,
    pub completed: HashSet<E3id>,
    pub replay_cursors: HashMap<AggregateId, u64>,
    /// E3s that failed with a slashable reason, keyed to the unix second after which the
    /// accusation/slashing lifecycle can no longer act and the context may be torn down.
    ///
    /// `serde(default)` covers a value built in memory, NOT an old on-disk record: bincode
    /// encodes this struct as a fixed sequence, so decoding a version-2 checkpoint that
    /// predates this field fails with "unexpected end of file" rather than defaulting.
    /// `SCHEMA_VERSION` was bumped to 3 so such a store halts with a migration message
    /// instead of an opaque decode error.
    #[serde(default)]
    pub teardown_deadlines: HashMap<E3id, u64>,
}
